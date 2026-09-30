import { DatabaseSync } from 'node:sqlite';
import { chmodSync, existsSync, lstatSync, openSync, closeSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { dailyRequestLimit, SafeError, selectionMode } from './hardened-policy.mjs';
import { processIdentity, processState } from './process-identity.mjs';
import { archiveRetrieval } from './retrieval-archive.mjs';

// Reserve the documented maximum Jev input per call, not a character estimate.
export const RESERVATION_MICRO_USD = Math.ceil(65536 * 0.042);
const LEASE_MS = 60000;
const cap = value => Math.floor(value * 1_000_000);

export class Store {
  constructor(home) {
    this.home = home;
    const path = join(home, 'state.sqlite3');
    if (existsSync(path) && (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink())) throw new SafeError('unsafe_state', 'Invalid private ledger');
    closeSync(openSync(path, 'a', 0o600));
    chmodSync(path, 0o600);
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=DELETE;
      CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, at INTEGER NOT NULL, month TEXT NOT NULL, day TEXT NOT NULL,
        purpose TEXT NOT NULL, cost INTEGER NOT NULL, status TEXT NOT NULL, lease_until INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY, expires INTEGER NOT NULL, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS discovery_metadata(workspace TEXT PRIMARY KEY, identity TEXT NOT NULL, expires INTEGER NOT NULL, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS accounting_archive(purpose TEXT PRIMARY KEY, cost INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS request_reconciliations(request_id TEXT PRIMARY KEY, at INTEGER NOT NULL,
        reason TEXT NOT NULL, cost_retained INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS request_processes(request_id TEXT PRIMARY KEY, process_identity TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS retrieval_archive(revision TEXT NOT NULL, origin TEXT NOT NULL, mode TEXT NOT NULL,
        samples INTEGER NOT NULL, at INTEGER NOT NULL, value TEXT NOT NULL, PRIMARY KEY(revision,origin,mode));
      CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, owner TEXT NOT NULL, root TEXT NOT NULL, expires INTEGER NOT NULL, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS retrieval_metrics(id INTEGER PRIMARY KEY, at INTEGER NOT NULL, trial_id TEXT NOT NULL,
        workspace_hash TEXT NOT NULL, session_id TEXT NOT NULL, mode TEXT NOT NULL, value TEXT NOT NULL);`);
    this.db.prepare('DELETE FROM cache WHERE expires < ?').run(Date.now());
    this.db.prepare('DELETE FROM sessions WHERE expires < ?').run(Date.now());
    // Keep the current and preceding year of request accounting, no payload data.
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const cutoff = Date.now() - 366 * 86400000;
      const columns = new Set(this.db.prepare('PRAGMA table_info(retrieval_metrics)').all().map(row => row.name));
      if (!columns.has('revision')) this.db.exec("ALTER TABLE retrieval_metrics ADD COLUMN revision TEXT NOT NULL DEFAULT 'legacy'");
      if (!columns.has('origin')) this.db.exec("ALTER TABLE retrieval_metrics ADD COLUMN origin TEXT NOT NULL DEFAULT 'unattributed'");
      const old = this.db.prepare("SELECT purpose,SUM(cost) total FROM requests WHERE at < ? AND status != 'reserved' GROUP BY purpose").all(cutoff);
      for (const row of old) this.db.prepare('INSERT INTO accounting_archive VALUES(?,?) ON CONFLICT(purpose) DO UPDATE SET cost=cost+excluded.cost').run(row.purpose, row.total);
      this.db.prepare("DELETE FROM requests WHERE at < ? AND status != 'reserved'").run(cutoff);
      this.db.prepare('DELETE FROM request_reconciliations WHERE at < ?').run(cutoff);
      this.db.exec('DELETE FROM request_processes WHERE request_id NOT IN (SELECT id FROM requests)');
      archiveRetrieval(this.db);
      this.db.exec('COMMIT');
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  close() { this.db.close(); }
  reserve(config, purpose = 'monthly', root) {
    if (existsSync(join(this.home, 'halt.json'))) throw new SafeError('halted', 'Quota halt is active; owner-authorized resume required');
    if (!config.enabled || (purpose !== 'validation' && selectionMode(config, root) === 'local_only')) throw new SafeError('disabled', 'Live Jev is not activated; local evidence only');
    const now = Date.now(), month = new Date(now).toISOString().slice(0, 7), day = new Date(now).toISOString().slice(0, 10);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      // A wall-clock lease expiring does not prove that a request has stopped.
      // Crashed reservations require reconciliation; their cost stays reserved.
      if (this.db.prepare('SELECT 1 FROM requests WHERE status = ?').get('reserved')) throw new SafeError('busy', 'A Jev request is in flight or unreconciled; no duplicate request was sent');
      const monthly = this.db.prepare('SELECT COALESCE(SUM(cost),0) total FROM requests WHERE month=?').get(month).total;
      const archived = this.db.prepare('SELECT COALESCE(SUM(cost),0) total FROM accounting_archive').get().total;
      const total = this.db.prepare('SELECT COALESCE(SUM(cost),0) total FROM requests').get().total + archived;
      const validation = this.db.prepare("SELECT COALESCE(SUM(cost),0) total FROM requests WHERE purpose='validation'").get().total +
        this.db.prepare("SELECT COALESCE(SUM(cost),0) total FROM accounting_archive WHERE purpose='validation'").get().total;
      const count = this.db.prepare('SELECT COUNT(*) count FROM requests WHERE day=?').get(day).count;
      if (total + RESERVATION_MICRO_USD > cap(config.total_budget_usd ?? 0) || monthly + RESERVATION_MICRO_USD > cap(config.monthly_budget_usd) ||
          (purpose === 'validation' && validation + RESERVATION_MICRO_USD > cap(config.validation_budget_usd)) ||
          (dailyRequestLimit(config, root) !== null && count >= dailyRequestLimit(config, root))) {
        throw new SafeError('budget_blocked', 'Configured Jev budget or daily request limit reached');
      }
      const id = randomUUID();
      this.db.prepare('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)')
        .run(id, now, month, day, purpose, RESERVATION_MICRO_USD, 'reserved', now + LEASE_MS);
      this.db.prepare('INSERT INTO request_processes VALUES(?,?)').run(id, JSON.stringify(processIdentity));
      this.db.exec('COMMIT');
      return id;
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  settle(id, usage) {
    if (!Number.isSafeInteger(usage?.input_tokens) || usage.input_tokens < 0 || usage.input_tokens > 65536) {
      this.uncertain(id);
      this.halt('usage_invalid');
      throw new SafeError('usage_invalid', 'Jev usage exceeded the verified billing contract; owner review required');
    }
    const changed = this.db.prepare("UPDATE requests SET cost=?,status='completed',lease_until=0 WHERE id=? AND status='reserved' AND id IN (SELECT request_id FROM request_processes WHERE process_identity=?)")
      .run(Math.ceil(usage.input_tokens * 0.042), id, JSON.stringify(processIdentity));
    if (changed.changes !== 1) throw new SafeError('reservation_conflict', 'Request is not reserved by this process; no charge was changed.');
  }
  uncertain(id) {
    this.db.prepare("UPDATE requests SET status='uncertain',lease_until=0 WHERE id=? AND status='reserved' AND id IN (SELECT request_id FROM request_processes WHERE process_identity=?)")
      .run(id, JSON.stringify(processIdentity));
  }
  reservations() {
    const rows = this.db.prepare("SELECT id,at,cost,status,process_identity FROM requests LEFT JOIN request_processes ON request_id=id WHERE status='reserved' ORDER BY at").all();
    return { blocked: rows.length > 0, pending: rows.map(row => {
      let owner; try { owner = JSON.parse(row.process_identity); } catch { /* Legacy/corrupt identity stays unknown. */ }
      return { id: row.id, at: row.at, reservedMicroUsd: row.cost, processState: processState(owner) };
    }), uncertain: this.db.prepare("SELECT COUNT(*) count,COALESCE(SUM(cost),0) reservedMicroUsd FROM requests WHERE status='uncertain'").get(),
    note: 'Age alone never releases a reservation. Reconciliation retains the full uncertain charge.' };
  }
  reconcileReservation(id, { acknowledge = false, confirmUnidentifiedStopped = false } = {}) {
    if (!acknowledge) throw new SafeError('acknowledgment_required', 'Explicit acknowledgment is required; charges remain reserved.');
    if (!/^[a-f0-9-]{36}$/.test(id ?? '')) throw new SafeError('invalid_input', 'A reservation identifier is required.');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.db.prepare('SELECT * FROM requests LEFT JOIN request_processes ON request_id=id WHERE id=?').get(id);
      if (!row || row.status !== 'reserved') throw new SafeError('reservation_conflict', 'Reservation is absent or already reconciled.');
      let owner; try { owner = JSON.parse(row.process_identity); } catch { /* Fail closed unless explicitly reconciled by owner. */ }
      const state = processState(owner);
      if (state === 'alive' || (state === 'unknown' && !confirmUnidentifiedStopped))
        throw new SafeError('process_unresolved', 'The request process is alive or cannot be verified stopped.');
      this.db.prepare("UPDATE requests SET status='uncertain',lease_until=0 WHERE id=? AND status='reserved'").run(id);
      this.db.prepare('INSERT INTO request_reconciliations VALUES(?,?,?,?)')
        .run(id, Date.now(), state === 'stopped' ? 'verified_process_exit' : 'owner_confirmed_process_exit', row.cost);
      this.db.exec('COMMIT');
      return { id, status: 'uncertain', reservedMicroUsd: row.cost, chargeReleased: false, haltCleared: false };
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  halt(reason) {
    const path = join(this.home, 'halt.json'), temp = join(this.home, `.halt-${randomUUID()}`);
    if (existsSync(path) && lstatSync(path).isSymbolicLink()) throw new SafeError('unsafe_state', 'Invalid halt marker');
    writeFileSync(temp, JSON.stringify({ provider: 'typesafe', reason, at: new Date().toISOString() }) + '\n', { mode: 0o600, flag: 'wx' });
    renameSync(temp, path);
  }
  cached(key) { const row = this.db.prepare('SELECT value FROM cache WHERE key=? AND expires>?').get(key, Date.now()); return row ? JSON.parse(row.value) : null; }
  discoveryIndex(workspace, identity) {
    const row = this.db.prepare('SELECT value FROM discovery_metadata WHERE workspace=? AND identity=? AND expires>?').get(workspace, identity, Date.now());
    return row ? JSON.parse(row.value) : null;
  }
  saveDiscoveryIndex(workspace, identity, files) {
    const value = JSON.stringify({ files: files.slice(0, 5000).map(({ path, signature, score }) => ({ path, signature, score })) });
    if (Buffer.byteLength(value) > 1024 * 1024) return false;
    this.db.prepare('INSERT OR REPLACE INTO discovery_metadata VALUES(?,?,?,?)').run(workspace, identity, Date.now() + 1800000, value);
    this.db.exec('DELETE FROM discovery_metadata WHERE rowid NOT IN (SELECT rowid FROM discovery_metadata ORDER BY expires DESC LIMIT 16)');
    return true;
  }
  cache(key, value) {
    this.db.prepare('INSERT OR REPLACE INTO cache VALUES(?,?,?)').run(key, Date.now() + 86400000, JSON.stringify(value));
    this.db.exec('DELETE FROM cache WHERE rowid NOT IN (SELECT rowid FROM cache ORDER BY expires DESC LIMIT 512)');
  }
  session(owner, root, value) {
    const id = randomUUID();
    this.db.prepare('INSERT INTO sessions VALUES(?,?,?,?,?)').run(id, owner, root, Date.now() + 1800000, JSON.stringify(value));
    this.db.exec('DELETE FROM sessions WHERE rowid NOT IN (SELECT rowid FROM sessions ORDER BY expires DESC LIMIT 128)');
    return id;
  }
  getSession(id, owner) {
    const row = this.db.prepare('SELECT root,value FROM sessions WHERE id=? AND owner=? AND expires>?').get(id, owner, Date.now());
    if (!row) throw new SafeError('session_expired', 'Evidence session expired or belongs to another MCP connection; search again');
    return { root: row.root, ...JSON.parse(row.value) };
  }
  useRecovery(id, owner) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const value = this.getSession(id, owner);
      if (value.recoveryUsed || value.isRecovery || value.jevFailed) throw new SafeError('recovery_exhausted', 'This investigation cannot make another Jev selection');
      this.db.prepare('UPDATE sessions SET value=? WHERE id=?').run(JSON.stringify({ ...value, recoveryUsed: true }), id);
      this.db.exec('COMMIT'); return value;
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  status() {
    return this.db.prepare('SELECT month,COUNT(*) requests,SUM(cost) reserved_or_spent_micro_usd FROM requests GROUP BY month ORDER BY month DESC LIMIT 12').all();
  }
  measure({ trialId, workspaceHash, sessionId, mode, metrics, revision = 'legacy', origin = 'unattributed' }) {
    if (!/^[a-f0-9]{64}$/.test(workspaceHash) || !/^[a-f0-9-]{36}$/.test(sessionId) ||
        !['jev', 'cache', 'bypass', 'local-fallback', 'exact-read'].includes(mode) ||
        !(trialId === 'qualified' || /^[a-f0-9-]{36}$/.test(trialId)) ||
        !(revision === 'legacy' || /^[a-f0-9]{64}$/.test(revision)) ||
        !['ordinary', 'synthetic', 'comparison', 'unattributed'].includes(origin)) throw new SafeError('invalid_metrics', 'Invalid measurement identity');
    const names = ['candidateEvidenceBytes', 'localPageEvidenceBytes', 'selectedEvidenceBytes', 'retrievalMs', 'selectionMs',
      'followupReadBytes', 'followupReads', 'jevRequests', 'jevInputTokens', 'jevOutputTokens'];
    const value = Object.fromEntries(names.filter(key => Number.isFinite(metrics[key]) && metrics[key] >= 0).map(key => [key, metrics[key]]));
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare('INSERT INTO retrieval_metrics(at,trial_id,workspace_hash,session_id,mode,value,revision,origin) VALUES(?,?,?,?,?,?,?,?)')
        .run(Date.now(), trialId, workspaceHash, sessionId, mode, JSON.stringify(value), revision, origin);
      archiveRetrieval(this.db);
      this.db.exec('COMMIT');
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  measurements(trialId = null) {
    const rows = trialId ? this.db.prepare('SELECT mode,value,revision,origin FROM retrieval_metrics WHERE trial_id=?').all(trialId)
      : this.db.prepare('SELECT mode,value,revision,origin FROM retrieval_metrics').all();
    const modes = {}, groups = new Map();
    for (const row of rows) {
      const group = modes[row.mode] ??= { samples: 0 };
      group.samples++;
      for (const [key, value] of Object.entries(JSON.parse(row.value))) group[key] = (group[key] ?? 0) + value;
      const key = `${row.revision}:${row.origin}:${row.mode}`;
      const cohort = groups.get(key) ?? { revision: row.revision, origin: row.origin, mode: row.mode, samples: 0, metrics: {} };
      cohort.samples++;
      for (const [name, value] of Object.entries(JSON.parse(row.value))) cohort.metrics[name] = (cohort.metrics[name] ?? 0) + value;
      groups.set(key, cohort);
    }
    const archived = this.db.prepare('SELECT revision,origin,mode,samples,value FROM retrieval_archive ORDER BY at DESC').all()
      .map(({ value, ...row }) => ({ ...row, metrics: JSON.parse(value) }));
    return { modes, cohorts: [...groups.values()], archived: { scope: 'all_trials_expired_detail', cohorts: archived,
      maxCohorts: 148, revisionNote: 'Oldest cohorts may have revision=archived; not attributable to the current build.' },
    retentionDays: 30, maxRecords: 10000, nativeTokensMeasured: false, accountSavingsMeasured: false };
  }
  runtimeMeasurements() {
    const path = join(this.home, 'measurements.sqlite3');
    if (!existsSync(path)) return { state: 'no_observations', nativeTokensMeasured: false };
    const info = lstatSync(path);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) throw new SafeError('unsafe_state', 'Invalid numeric telemetry ledger');
    const db = new DatabaseSync(path, { readOnly: true });
    try {
      db.exec('PRAGMA busy_timeout=1000');
      const native = db.prepare("SELECT COUNT(*) count FROM totals WHERE kind='native_usage' AND metric='input_tokens'").get().count;
      const coverage = db.prepare("SELECT COUNT(*) samples,COUNT(session_hash) withSession,COUNT(turn_hash) withTurn FROM events WHERE kind='native_usage'").get();
      return { state: native ? 'native_usage_observed' : 'native_usage_not_observed', nativeTokensMeasured: native > 0,
        accountSavingsMeasured: false, coverage,
        note: 'Metadata-only local telemetry; hook observations alone do not prove native token capture.' };
    } finally { db.close(); }
  }
}

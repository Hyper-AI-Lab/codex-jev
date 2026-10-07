import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { dirname, resolve } from 'node:path';

const OPERATIONS = new Set([
  'search_workspace_evidence', 'read_large_text_evidence', 'read_selected_evidence', 'list_evidence', 'evidence_status', 'judge_evidence',
]);
const ORIGINS = new Set(['ordinary', 'synthetic', 'comparison', 'unattributed']);
const METRICS = new Set([
  'responseBytes', 'durationMs', 'jevRequests', 'jevInputTokens', 'jevOutputTokens', 'retrievalMs', 'selectionMs',
  'evidenceBytes', 'followupBytes', 'followupReads', 'cacheHits', 'localBypasses', 'localFallbacks',
]);
const MAX_ROWS = 10000;
const RETENTION_MS = 30 * 86400000;
const DIGEST = /^[a-f0-9]{64}$/;
const sha256 = value => createHash('sha256').update(value, 'utf8').digest('hex');

function validUnicode(value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

function canonicalValue(value, depth, seen) {
  if (depth > 16) throw new TypeError('Canonical input exceeds maximum depth');
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    if (!validUnicode(value) || Buffer.byteLength(value, 'utf8') > 65536)
      throw new TypeError('Canonical input contains invalid or oversized Unicode');
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new TypeError('Canonical input numbers must be safe integers');
    return value;
  }
  if (typeof value !== 'object') throw new TypeError('Canonical input must contain only JSON values');
  if (seen.has(value)) throw new TypeError('Canonical input cannot contain cycles');
  seen.add(value);
  let result;
  if (Array.isArray(value)) {
    if (value.length > 4096) throw new TypeError('Canonical array exceeds entry limit');
    const keys = Reflect.ownKeys(value);
    if (keys.some(key => typeof key !== 'string' || (key !== 'length' && !/^(0|[1-9][0-9]*)$/.test(key))) ||
        Object.keys(value).length !== value.length) throw new TypeError('Canonical arrays must be dense JSON arrays');
    result = [];
    for (let i = 0; i < value.length; i++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value'))
        throw new TypeError('Canonical arrays must contain data values');
      result.push(canonicalValue(descriptor.value, depth + 1, seen));
    }
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Canonical input objects must be plain');
    if (Object.keys(value).length > 4096) throw new TypeError('Canonical object exceeds entry limit');
    result = Object.create(null);
    const keys = Reflect.ownKeys(value);
    if (keys.some(key => typeof key !== 'string')) throw new TypeError('Canonical objects cannot have symbol keys');
    for (const key of keys.sort()) {
      if (!/^[\x20-\x7e]{1,200}$/.test(key)) throw new TypeError('Canonical object keys must be printable ASCII');
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value'))
        throw new TypeError('Canonical objects must contain enumerable data values');
      result[key] = canonicalValue(descriptor.value, depth + 1, seen);
    }
  }
  seen.delete(value);
  return result;
}

export function canonicalDigest(input) {
  const normalized = canonicalValue(input, 0, new Set());
  const stringify = value => {
    if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
    if (typeof value === 'number') return BigInt(value).toString();
    if (Array.isArray(value)) return `[${value.map(stringify).join(',')}]`;
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stringify(value[key])}`).join(',')}}`;
  };
  const canonical = stringify(normalized);
  if (Buffer.byteLength(canonical, 'utf8') > 65536) throw new TypeError('Canonical input exceeds 64 KiB');
  return sha256(canonical);
}

function assertPrivatePath(home, path) {
  const absoluteHome = resolve(home);
  for (let current = absoluteHome; ; current = dirname(current)) {
    const info = lstatSync(current);
    if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('Unsafe private ledger ancestor');
    if (current === dirname(current)) break;
  }
  const homeInfo = lstatSync(absoluteHome);
  if (homeInfo.mode & 0o077) throw new Error('Private ledger directory permissions are too broad');
  if (existsSync(path)) {
    const info = lstatSync(path);
    if (info.isSymbolicLink() || !info.isFile() || info.nlink !== 1) throw new Error('Unsafe private ledger file');
  }
}

function normalizedMetrics(metrics) {
  if (!metrics || typeof metrics !== 'object' || Array.isArray(metrics) ||
      (Object.getPrototypeOf(metrics) !== Object.prototype && Object.getPrototypeOf(metrics) !== null)) {
    throw new TypeError('Metrics must be a plain object');
  }
  const result = {};
  for (const key of Object.keys(metrics).sort()) {
    const value = metrics[key];
    if (!METRICS.has(key) || typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1e15) {
      throw new TypeError('Invalid numeric invocation metric');
    }
    result[key] = value;
  }
  return result;
}

export class InvocationLedger {
  constructor(home) {
    this.home = resolve(home);
    this.path = resolve(this.home, 'invocations.sqlite3');
    assertPrivatePath(this.home, this.path);
    const flags = constants.O_RDWR | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0);
    const fd = openSync(this.path, flags, 0o600);
    try {
      const info = fstatSync(fd);
      if (!info.isFile() || info.nlink !== 1 || (typeof process.geteuid === 'function' && info.uid !== process.geteuid()))
        throw new Error('Unsafe private ledger file');
      chmodSync(this.path, 0o600);
    } finally { closeSync(fd); }
    this.db = new DatabaseSync(this.path);
    this.closed = false;
    try {
      this.db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=DELETE;');
      this.db.exec(readFileSync(new URL('../runtime/invocations.sql', import.meta.url), 'utf8'));
      const versions = this.db.prepare('SELECT version FROM invocation_schema').all().map(row => row.version);
      if (versions.length !== 1 || versions[0] !== 1) throw new Error('Unknown invocation schema');
      this.db.exec('BEGIN IMMEDIATE');
      try {
        this.#prune(Date.now());
        this.db.exec('COMMIT');
      } catch (error) {
        this.db.exec('ROLLBACK');
        throw error;
      }
    } catch (error) {
      this.db.close();
      this.closed = true;
      throw error;
    }
  }

  #prune(now) {
    const cutoff = now - RETENTION_MS;
    this.db.prepare("DELETE FROM invocations WHERE started_at < ? AND result_status IN ('success','error')").run(cutoff);
  }

  #transaction(action) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = action();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  begin({ workspace, operation, input, revision, origin = 'ordinary' } = {}) {
    if (typeof workspace !== 'string' || !workspace || !validUnicode(workspace) ||
        !OPERATIONS.has(operation) || typeof revision !== 'string' || !DIGEST.test(revision) || !ORIGINS.has(origin)) {
      throw new TypeError('Invalid invocation identity');
    }
    const argumentsHash = canonicalDigest(input);
    return this.#transaction(() => {
      const now = Date.now();
      this.#prune(now);
      if (this.db.prepare('SELECT COUNT(*) AS count FROM invocations').get().count >= MAX_ROWS)
        throw new Error('Invocation ledger capacity reached');
      const id = randomUUID();
      this.db.prepare(`INSERT INTO invocations
        (id,workspace_hash,operation,arguments_hash,revision,origin,started_at,completed_at,result_status,metrics)
        VALUES(?,?,?,?,?,?,?,NULL,'started','{}')`)
        .run(id, sha256(workspace), operation, argumentsHash, revision, origin, now);
      return id;
    });
  }

  finish(id, { status, metrics } = {}) {
    if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id) ||
        !['success', 'error'].includes(status)) throw new TypeError('Invalid invocation completion');
    const metricValue = normalizedMetrics(metrics);
    const serialized = JSON.stringify(metricValue);
    return this.#transaction(() => {
      const row = this.db.prepare('SELECT result_status,started_at,completed_at,metrics FROM invocations WHERE id=?').get(id);
      if (!row) throw new Error('Invocation not found');
      if (row.result_status !== 'started') {
        if (row.result_status === status && row.metrics === serialized) return false;
        throw new Error('Invocation completion conflicts with immutable result');
      }
      const now = Date.now();
      if (now < row.started_at) throw new Error('Invocation completion timestamp precedes start');
      const changed = this.db.prepare("UPDATE invocations SET completed_at=?,result_status=?,metrics=? WHERE id=? AND result_status='started'")
        .run(now, status, serialized, id);
      if (changed.changes !== 1) throw new Error('Invocation completion conflict');
      return true;
    });
  }

  summary() {
    const counts = this.db.prepare(`SELECT
      (SELECT COUNT(*) FROM invocations) AS total,
      (SELECT COUNT(*) FROM invocations WHERE session_hash IS NOT NULL AND turn_hash IS NOT NULL AND call_hash IS NOT NULL) AS verified,
      (SELECT COUNT(*) FROM invocation_receipts WHERE invocation_id IS NULL) AS pending,
      (SELECT COUNT(*) FROM invocations WHERE result_status='started') AS unfinished`).get();
    const capabilities = this.db.prepare('SELECT operation, COUNT(*) AS count FROM invocations GROUP BY operation').all()
      .filter(row => OPERATIONS.has(row.operation));
    return { ...counts, byOperation: Object.fromEntries(capabilities.map(row => [row.operation, row.count])), accountSavingsMeasured: false };
  }

  close() {
    if (!this.closed) {
      this.db.close();
      this.closed = true;
    }
  }
}

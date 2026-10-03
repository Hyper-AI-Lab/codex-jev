import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { Store, RESERVATION_MICRO_USD } from '../src/hardened-store.mjs';
import { EvidenceService } from '../src/hardened-service.mjs';
import { defaults, hash, MODEL } from '../src/hardened-policy.mjs';

async function fixture(t) {
  const base = await mkdtemp(join(tmpdir(), 'jev-storage-')), home = join(base, 'private'), root = join(base, 'project');
  await mkdir(home, { mode: 0o700 }); await mkdir(root);
  t.after(() => rm(base, { recursive: true, force: true }));
  const config = { ...defaults, allowed_roots: [root], enabled: true, live_validated: true,
    monthly_budget_usd: 1, validation_budget_usd: 1, total_budget_usd: 1 };
  await writeFile(join(home, 'config.json'), JSON.stringify(config), { mode: 0o600 });
  await mkdir(join(home, 'secrets'), { mode: 0o700 });
  await writeFile(join(home, 'secrets/typesafe_api_key'), 'synthetic-key-only', { mode: 0o600 });
  return { home, root, config };
}

test('additive ledger schema preserves legacy inserts, pending reservations and cumulative costs', async t => {
  const f = await fixture(t), path = join(f.home, 'state.sqlite3'), prior = new DatabaseSync(path);
  prior.exec('CREATE TABLE requests(id TEXT PRIMARY KEY,at INTEGER,month TEXT,day TEXT,purpose TEXT,cost INTEGER,status TEXT,lease_until INTEGER)');
  const id = randomUUID(), at = Date.now(), date = new Date(at).toISOString();
  prior.prepare('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)').run(id, at, date.slice(0, 7), date.slice(0, 10), 'validation', RESERVATION_MICRO_USD, 'reserved', 0);
  const store = new Store(f.home);
  t.after(() => { prior.close(); store.close(); });
  assert.equal(store.reservations().pending[0].processState, 'unknown');
  assert.throws(() => store.reserve(f.config), { code: 'busy' });
  prior.prepare("UPDATE requests SET status='uncertain' WHERE id=?").run(id);
  const second = randomUUID();
  prior.prepare('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)').run(second, at, date.slice(0, 7), date.slice(0, 10), 'monthly', 5, 'completed', 0);
  assert.equal(store.status()[0].reserved_or_spent_micro_usd, RESERVATION_MICRO_USD + 5);
});

test('SQLite full during admission makes no provider call and leaves no phantom reservation', async t => {
  const f = await fixture(t); let calls = 0;
  const service = await new EvidenceService({ ...f, boundRoot: f.root, fetcher: async () => { calls++; throw new Error('must not send'); } }).init();
  t.after(() => service.close());
  const db = service.store.db;
  db.exec('PRAGMA max_page_count=32; CREATE TABLE fill(payload BLOB)');
  assert.throws(() => { for (let i = 0; i < 100; i++) db.exec('INSERT INTO fill VALUES(zeroblob(4096))'); });
  // The extra row forces the request transaction to allocate another page.
  db.exec("CREATE TRIGGER full_admission AFTER INSERT ON requests BEGIN INSERT INTO fill VALUES(zeroblob(65536)); END");
  const candidates = Array.from({ length: 6 }, (_, i) => ({ path: `${i}.js`, hash: hash(`${i}`), lines: { start: 1, end: 12 }, excerpt: 'checkout '.repeat(200) }));
  const result = await service.select(f.root, 'checkout', [], candidates);
  assert.equal(calls, 0); assert.equal(result.mode, 'local-fallback');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM requests').get().n, 0);
});

test('settlement failure after send leaves a charge barrier rather than allowing unaccounted retries', async t => {
  const f = await fixture(t); let calls = 0;
  const service = await new EvidenceService({ ...f, boundRoot: f.root, fetcher: async (_url, input) => {
    calls++;
    service.store.db.exec("CREATE TRIGGER fail_settle BEFORE UPDATE ON requests BEGIN SELECT RAISE(ABORT,'synthetic disk full'); END");
    const request = JSON.parse(input.body);
    return new Response(JSON.stringify({ model: MODEL,
      answers: Object.fromEntries(Object.keys(request.questions).map(key => [key, { type: 'noul', noul: 0.8 }])),
      usage: { input_tokens: 100, output_tokens: 10 } }));
  } }).init();
  t.after(() => service.close());
  const candidates = Array.from({ length: 6 }, (_, i) => ({ path: `${i}.js`, hash: hash(`${i}`), lines: { start: 1, end: 12 }, excerpt: 'checkout '.repeat(200) }));
  await assert.rejects(service.select(f.root, 'checkout', [], candidates));
  assert.equal(calls, 1); assert.equal(service.store.reservations().blocked, true);
  assert.equal(service.store.status()[0].reserved_or_spent_micro_usd, RESERVATION_MICRO_USD);
  assert.throws(() => service.store.reserve(f.config), { code: 'busy' });
});

test('corrupt database is not reset or silently replaced', async t => {
  const f = await fixture(t), path = join(f.home, 'state.sqlite3');
  await writeFile(path, 'synthetic-corrupt-database', { mode: 0o600 });
  assert.throws(() => new Store(f.home));
  const { readFile } = await import('node:fs/promises');
  assert.equal(await readFile(path, 'utf8'), 'synthetic-corrupt-database');
});

test('expired numeric detail retains compact totals without duplicate migration or unbounded cohort growth', async t => {
  const f = await fixture(t); let store = new Store(f.home);
  t.after(() => store.close());
  const row = { trialId: 'qualified', workspaceHash: hash(f.root), sessionId: randomUUID(), mode: 'jev', metrics: { jevRequests: 1, jevInputTokens: 10 }, origin: 'ordinary' };
  for (let i = 0; i < 150; i++) store.measure({ ...row, revision: hash(`${i}`) });
  store.db.prepare('UPDATE retrieval_metrics SET at=?').run(Date.now() - 31 * 86400000);
  store.close(); store = new Store(f.home);
  const archived = store.measurements().archived;
  assert.equal(store.db.prepare('SELECT COUNT(*) n FROM retrieval_metrics').get().n, 0);
  assert.ok(archived.cohorts.length <= archived.maxCohorts);
  assert.equal(archived.cohorts.reduce((sum, item) => sum + item.samples, 0), 150);
  assert.equal(archived.cohorts.reduce((sum, item) => sum + item.metrics.jevInputTokens, 0), 1500);
  store.close(); store = new Store(f.home);
  assert.deepEqual(store.measurements().archived, archived);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, symlink, link, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { canonicalDigest, InvocationLedger } from '../src/invocation-ledger.mjs';

const REVISION = 'a'.repeat(64);
const INPUT = { z: 2, a: ['safe', true, null] };
const OP = 'search_workspace_evidence';

async function fixture(t) {
  const base = await mkdtemp(join(tmpdir(), 'jev-invocation-'));
  const home = join(base, 'private');
  await mkdir(home, { mode: 0o700 });
  t.after(() => rm(base, { recursive: true, force: true }));
  const ledger = new InvocationLedger(home);
  t.after(() => ledger.close());
  return { base, home, ledger };
}

test('canonical digest sorts keys and accepts bounded JSON values', () => {
  assert.equal(canonicalDigest({ b: 2, a: 1 }), canonicalDigest({ a: 1, b: 2 }));
  assert.match(canonicalDigest(INPUT), /^[a-f0-9]{64}$/);
  assert.throws(() => canonicalDigest({ x: 1.5 }));
  assert.throws(() => canonicalDigest({ x: Number.MAX_SAFE_INTEGER + 1 }));
  assert.throws(() => canonicalDigest({ ['é']: 1 }));
  assert.throws(() => canonicalDigest({ '': 1 }));
  assert.throws(() => canonicalDigest({ ['k'.repeat(201)]: 1 }));
  assert.throws(() => canonicalDigest(Object.fromEntries(Array.from({ length: 4097 }, (_, i) => [`k${i}`, i]))));
  assert.throws(() => canonicalDigest(Array(4097).fill(0)));
  assert.throws(() => canonicalDigest({ x: '\ud800' }));
  assert.throws(() => canonicalDigest(Object.defineProperty({}, 'x', { enumerable: true, get() { throw new Error('not JSON'); } })));
  assert.throws(() => canonicalDigest(Array(1)));
  let deep = 0;
  for (let i = 0; i < 18; i++) deep = [deep];
  assert.throws(() => canonicalDigest(deep));
  assert.throws(() => canonicalDigest('x'.repeat(65536)));
});

test('records only identity hashes and allowlisted metrics; summary makes no savings claim', async t => {
  const { home, ledger } = await fixture(t);
  const id = ledger.begin({ workspace: '/synthetic/private/project', operation: OP, input: INPUT, revision: REVISION });
  assert.match(id, /^[0-9a-f-]{36}$/);
  const metrics = { responseBytes: 10, jevRequests: 1, cacheHits: 0 };
  ledger.finish(id, { status: 'success', metrics });
  const row = ledger.db.prepare('SELECT * FROM invocations WHERE id=?').get(id);
  assert.equal(row.result_status, 'success');
  assert.match(row.workspace_hash, /^[a-f0-9]{64}$/);
  assert.equal(row.arguments_hash, canonicalDigest(INPUT));
  const serialized = JSON.stringify(row);
  assert.equal(serialized.includes('/synthetic/private/project'), false);
  assert.equal(serialized.includes('safe'), false);
  assert.equal(row.metrics, '{"cacheHits":0,"jevRequests":1,"responseBytes":10}');
  assert.deepEqual(ledger.summary(), { total: 1, verified: 0, pending: 0, unfinished: 0, accountSavingsMeasured: false });
  const info = await stat(join(home, 'invocations.sqlite3'));
  assert.equal(info.mode & 0o777, 0o600);
});

test('validates operation, revision, origin, input and metrics', async t => {
  const { ledger } = await fixture(t);
  for (const values of [
    { workspace: '/tmp/w', operation: 'unknown', input: INPUT, revision: REVISION },
    { workspace: '/tmp/w', operation: OP, input: INPUT, revision: 'bad' },
    { workspace: '/tmp/w', operation: OP, input: INPUT, revision: REVISION, origin: 'other' },
    { workspace: '/tmp/w', operation: OP, input: { x: NaN }, revision: REVISION },
  ]) assert.throws(() => ledger.begin(values));
  const id = ledger.begin({ workspace: '/tmp/w', operation: OP, input: INPUT, revision: REVISION });
  const startedAt = ledger.db.prepare('SELECT started_at FROM invocations WHERE id=?').get(id).started_at;
  ledger.db.prepare('UPDATE invocations SET started_at=? WHERE id=?').run(Date.now() + 10000, id);
  assert.throws(() => ledger.finish(id, { status: 'success', metrics: {} }), /precedes start/);
  ledger.db.prepare('UPDATE invocations SET started_at=? WHERE id=?').run(startedAt, id);
  for (const metrics of [{ mystery: 1 }, { responseBytes: -1 }, { responseBytes: Infinity }, { durationMs: '3' }])
    assert.throws(() => ledger.finish(id, { status: 'success', metrics }));
  assert.throws(() => ledger.finish(id, { status: 'success', metrics: { responseBytes: 1e15 + 1 } }));
  assert.throws(() => ledger.finish(id, { status: 'started', metrics: {} }));
});

test('completion replay is identical-only and unfinished rows remain started', async t => {
  const { ledger } = await fixture(t);
  const id = ledger.begin({ workspace: '/tmp/w', operation: OP, input: INPUT, revision: REVISION });
  const outcome = { status: 'error', metrics: { durationMs: 5 } };
  ledger.finish(id, outcome);
  ledger.finish(id, outcome);
  assert.throws(() => ledger.finish(id, { status: 'success', metrics: { durationMs: 5 } }));
  assert.throws(() => ledger.finish('00000000-0000-4000-8000-000000000000', outcome));
  ledger.begin({ workspace: '/tmp/w', operation: OP, input: INPUT, revision: REVISION });
  assert.deepEqual(ledger.summary(), { total: 2, verified: 0, pending: 0, unfinished: 1, accountSavingsMeasured: false });
});

test('prunes expired completed details but preserves unfinished operations and unexpired receipts', async t => {
  const { ledger } = await fixture(t);
  const old = Date.now() - 31 * 86400000;
  ledger.db.prepare('INSERT INTO invocations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').run(
    'old-done', 'b'.repeat(64), OP, 'c'.repeat(64), REVISION, 'ordinary', old, old, 'success', '{}', null, null, null);
  ledger.db.prepare('INSERT INTO invocations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').run(
    'old-started', 'b'.repeat(64), OP, 'c'.repeat(64), REVISION, 'ordinary', old, null, 'started', '{}', null, null, null);
  ledger.db.prepare('INSERT INTO invocation_receipts VALUES(?,?,?,?,?,?,?,?,?)').run(
    'd'.repeat(64), 'e'.repeat(64), 'f'.repeat(64), 'b'.repeat(64), OP, 'c'.repeat(64), Date.now(), Date.now() + 600000, null);
  ledger.close();
  const reopened = new InvocationLedger(ledger.home);
  try {
    assert.equal(reopened.db.prepare('SELECT COUNT(*) n FROM invocations WHERE id=?').get('old-done').n, 0);
    assert.equal(reopened.db.prepare('SELECT COUNT(*) n FROM invocations WHERE id=?').get('old-started').n, 1);
    assert.equal(reopened.db.prepare('SELECT COUNT(*) n FROM invocation_receipts WHERE call_hash=?').get('d'.repeat(64)).n, 1);
  } finally { reopened.close(); }
});

test('uses shared SQL schema and rejects linked database and symlink ancestors', async t => {
  const { base, home, ledger } = await fixture(t);
  const columns = ledger.db.prepare('PRAGMA table_info(invocations)').all().map(row => row.name);
  assert.deepEqual(columns, ['id', 'workspace_hash', 'operation', 'arguments_hash', 'revision', 'origin', 'started_at', 'completed_at', 'result_status', 'metrics', 'session_hash', 'turn_hash', 'call_hash']);
  ledger.close();
  await link(join(home, 'invocations.sqlite3'), join(base, 'linked.sqlite3'));
  assert.throws(() => new InvocationLedger(home));
  const target = join(base, 'target');
  await mkdir(target, { mode: 0o700 });
  const linkedHome = join(base, 'redirect');
  await symlink(target, linkedHome);
  assert.throws(() => new InvocationLedger(linkedHome));
  assert.equal((await readFile(join(home, 'invocations.sqlite3'))).length > 0, true);
});

test('rejects an unsupported schema version and closes the database after initialization failure', async t => {
  const base = await mkdtemp(join(tmpdir(), 'jev-invocation-schema-'));
  const home = join(base, 'private');
  await mkdir(home, { mode: 0o700 });
  t.after(() => rm(base, { recursive: true, force: true }));
  const path = join(home, 'invocations.sqlite3');
  const db = new DatabaseSync(path);
  db.exec('CREATE TABLE invocation_schema(version INTEGER PRIMARY KEY); INSERT INTO invocation_schema VALUES(2)');
  db.close();
  assert.throws(() => new InvocationLedger(home), /schema/i);
  const reopened = new DatabaseSync(path);
  assert.deepEqual(reopened.prepare('SELECT version FROM invocation_schema ORDER BY version').all().map(row => row.version), [1, 2]);
  reopened.close();
});

test('enforces the 10,000-operation cap without evicting live or recent rows', async t => {
  const { ledger } = await fixture(t);
  const insert = ledger.db.prepare('INSERT INTO invocations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)');
  ledger.db.exec('BEGIN IMMEDIATE');
  try {
    for (let i = 0; i < 10000; i++) insert.run(`row-${i}`, 'b'.repeat(64), OP, 'c'.repeat(64), REVISION,
      'ordinary', Date.now(), null, 'started', '{}', null, null, null);
    ledger.db.exec('COMMIT');
  } catch (error) { ledger.db.exec('ROLLBACK'); throw error; }
  assert.throws(() => ledger.begin({ workspace: '/tmp/w', operation: OP, input: INPUT, revision: REVISION }), /capacity/i);
  assert.equal(ledger.db.prepare('SELECT COUNT(*) n FROM invocations').get().n, 10000);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, symlink, link, rename } from 'node:fs/promises';
import promises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { RESERVATION_MICRO_USD } from '../src/hardened-store.mjs';
import { processIdentity, processState } from '../src/process-identity.mjs';
import { defaults, exec, hash, MODEL, readPrivateJson } from '../src/hardened-policy.mjs';
import { privateRead } from '../src/private-read.mjs';
import { EvidenceService } from '../src/hardened-service.mjs';
import { reservationsCommand } from '../scripts/reservations.mjs';

async function fixture(t) {
  const base = await mkdtemp(join(tmpdir(), 'jev-privacy-')), home = join(base, 'private'), root = join(base, 'project');
  await mkdir(home, { mode: 0o700 }); await mkdir(root); await exec('git', ['init', '-q', root]);
  const config = { ...defaults, allowed_roots: [root], enabled: true, live_validated: true,
    validation_budget_usd: 1, monthly_budget_usd: 1, total_budget_usd: 1 };
  const save = () => writeFile(join(home, 'config.json'), JSON.stringify(config), { mode: 0o600 });
  await save(); await mkdir(join(home, 'secrets'), { mode: 0o700 });
  await writeFile(join(home, 'secrets/typesafe_api_key'), 'synthetic-only-key', { mode: 0o600 });
  const service = await new EvidenceService({ home, boundRoot: root, fetcher: async () => { throw new Error('offline'); } }).init();
  t.after(async () => { service.close(); await rm(base, { recursive: true, force: true }); });
  return { base, home, root, config, save, service, store: service.store };
}

test('live process cannot be reconciled, even with acknowledgment or expired lease', async t => {
  const f = await fixture(t), id = f.store.reserve(f.config);
  f.store.db.exec('UPDATE requests SET lease_until=0');
  assert.equal(f.store.reservations().pending[0].processState, 'alive');
  assert.throws(() => f.store.reconcileReservation(id), { code: 'acknowledgment_required' });
  assert.throws(() => f.store.reconcileReservation(id, { acknowledge: true, confirmUnidentifiedStopped: true }), { code: 'process_unresolved' });
  assert.equal(f.store.status()[0].reserved_or_spent_micro_usd, RESERVATION_MICRO_USD);
});

test('exited request process is explicitly reconciled without dropping charges, replaying or clearing halt', async t => {
  const f = await fixture(t), module = new URL('../src/hardened-store.mjs', import.meta.url).href;
  const code = `import {Store} from ${JSON.stringify(module)}; const s = new Store(process.argv[1]);
    console.log(s.reserve(JSON.parse(process.argv[2]))); s.close();`;
  const id = (await exec(process.execPath, ['--input-type=module', '-e', code, f.home, JSON.stringify(f.config)])).stdout.trim();
  assert.equal(f.store.reservations().pending[0].processState, 'stopped');
  f.store.halt('synthetic_quota');
  const result = await reservationsCommand(['reconcile', id, '--acknowledge-uncertain-charge'], f.home);
  assert.equal(result.chargeReleased, false); assert.equal(result.haltCleared, false);
  assert.equal(result.reservedMicroUsd, RESERVATION_MICRO_USD);
  assert.equal(f.store.reservations().uncertain.count, 1);
  assert.equal(f.store.db.prepare('SELECT COUNT(*) n FROM request_reconciliations').get().n, 1);
  assert.throws(() => f.store.reserve(f.config), { code: 'halted' });
  await assert.rejects(reservationsCommand(['reconcile', id, '--acknowledge-uncertain-charge'], f.home), { code: 'reservation_conflict' });
});

test('legacy unknown identity requires separate owner confirmation; reused PID is not treated as original process', async t => {
  const f = await fixture(t), id = f.store.reserve(f.config);
  f.store.db.prepare('DELETE FROM request_processes WHERE request_id=?').run(id);
  assert.equal(f.store.reservations().pending[0].processState, 'unknown');
  assert.throws(() => f.store.reconcileReservation(id, { acknowledge: true }), { code: 'process_unresolved' });
  f.store.reconcileReservation(id, { acknowledge: true, confirmUnidentifiedStopped: true });
  assert.equal(f.store.status()[0].reserved_or_spent_micro_usd, RESERVATION_MICRO_USD);
  assert.throws(() => f.store.reserve({ ...f.config, total_budget_usd: RESERVATION_MICRO_USD / 1e6 }), { code: 'budget_blocked' });
  assert.equal(processState({ ...processIdentity, host: 'unknown' }), 'unknown');
  if (process.platform === 'linux') assert.equal(processState({ ...processIdentity, start: '0' }), 'stopped');
});

test('settlement requires original process and late error cannot downgrade a completed charge', async t => {
  const f = await fixture(t), id = f.store.reserve(f.config);
  f.store.db.prepare('DELETE FROM request_processes WHERE request_id=?').run(id);
  assert.throws(() => f.store.settle(id, { input_tokens: 1 }), { code: 'reservation_conflict' });
  f.store.db.prepare('INSERT INTO request_processes VALUES(?,?)').run(id, JSON.stringify(processIdentity));
  f.store.settle(id, { input_tokens: 100 }); f.store.uncertain(id);
  assert.equal(f.store.db.prepare('SELECT status FROM requests WHERE id=?').get(id).status, 'completed');
  assert.equal(f.store.status()[0].reserved_or_spent_micro_usd, 5);
});

test('private readers reject linked, public, oversized and malformed files without content-bearing errors', async t => {
  const f = await fixture(t), path = join(f.home, 'test.json'), marker = 'SECRET_MARKER_NEVER_IN_ERROR';
  await writeFile(path, marker, { mode: 0o600 });
  await assert.rejects(readPrivateJson(path), { code: 'invalid_config' });
  await assert.rejects(privateRead(path, { maxBytes: 4 }));
  await link(path, join(f.home, 'hard.json'));
  await assert.rejects(readPrivateJson(path), error => error.code === 'unsafe_state' && !error.message.includes(marker));
  await symlink(path, join(f.home, 'sym.json'));
  await assert.rejects(readPrivateJson(join(f.home, 'sym.json')), { code: 'unsafe_state' });
  await writeFile(join(f.home, 'public.json'), '{}', { mode: 0o644 });
  await assert.rejects(readPrivateJson(join(f.home, 'public.json')), { code: 'unsafe_state' });
  assert.equal(await privateRead(join(f.home, 'absent')), null);
});

test('key parent swap during pinned open cannot return outside key material', async t => {
  const f = await fixture(t), outside = join(f.base, 'outside');
  await mkdir(outside); await writeFile(join(outside, 'typesafe_api_key'), 'OUTSIDE_MARKER', { mode: 0o600 });
  const original = promises.open; let swapped = false;
  promises.open = async (path, ...args) => {
    if (String(path).endsWith('/typesafe_api_key') && !swapped) {
      swapped = true; await rename(join(f.home, 'secrets'), join(f.home, 'original'));
      await symlink(outside, join(f.home, 'secrets'));
    }
    return original(path, ...args);
  };
  syncBuiltinESMExports();
  try { await assert.rejects(privateRead(join(f.home, 'secrets/typesafe_api_key'))); assert.equal(swapped, true); }
  finally { promises.open = original; syncBuiltinESMExports(); }
});

test('saved references reject newly ignored sources and changed hashes', async t => {
  const f = await fixture(t);
  await writeFile(join(f.root, 'source.txt'), 'checkout source');
  const selected = await f.service.search({ workspaceRoot: f.root, query: 'checkout' });
  await writeFile(join(f.root, '.gitignore'), 'source.txt\n');
  await assert.rejects(f.service.list({ sessionId: selected.sessionId }), { code: 'path_denied' });
  await writeFile(join(f.root, '.gitignore'), '');
  await writeFile(join(f.root, 'source.txt'), 'changed');
  await assert.rejects(f.service.list({ sessionId: selected.sessionId }), { code: 'source_changed' });
});

test('cache identity includes privacy configuration even when excerpts are unchanged', async t => {
  const f = await fixture(t); let calls = 0;
  f.service.fetcher = async (_url, request) => {
    calls++; const body = JSON.parse(request.body);
    return new Response(JSON.stringify({ model: MODEL,
      answers: Object.fromEntries(Object.keys(body.questions).map(key => [key, { type: 'noul', noul: 0.8 }])),
      usage: { input_tokens: 100, output_tokens: 10 } }));
  };
  const candidates = Array.from({ length: 6 }, (_, i) => ({ path: `${i}.js`, lines: { start: 1, end: 12 }, hash: hash(`${i}`), excerpt: 'checkout '.repeat(200) }));
  assert.equal((await f.service.select(f.root, 'checkout', [], candidates)).mode, 'jev');
  assert.equal((await f.service.select(f.root, 'checkout', [], candidates)).mode, 'cache');
  f.config.additional_exclusions.push('private'); await f.save();
  assert.equal((await f.service.select(f.root, 'checkout', [], candidates)).mode, 'jev');
  assert.equal(calls, 2);
});

test('privacy changes during selection reject returned evidence but preserve known billed usage', async t => {
  const f = await fixture(t);
  await writeFile(join(f.root, 'sample.txt'), Array.from({ length: 90 }, (_, i) => `checkout context ${i} ${'information '.repeat(20)}`).join('\n'));
  f.service.fetcher = async (_url, request) => {
    const body = JSON.parse(request.body);
    f.config.additional_exclusions = ['sample.txt']; await f.save();
    return new Response(JSON.stringify({ model: MODEL,
      answers: Object.fromEntries(Object.keys(body.questions).map(key => [key, { type: 'noul', noul: 0.8 }])),
      usage: { input_tokens: 100, output_tokens: 10 } }));
  };
  await assert.rejects(f.service.search({ workspaceRoot: f.root, query: 'checkout' }), { code: 'privacy_changed' });
  assert.equal(f.store.status()[0].requests, 1);
  assert.equal(f.store.status()[0].reserved_or_spent_micro_usd, 5);
});

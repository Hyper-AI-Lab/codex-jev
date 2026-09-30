import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { defaults, POLICY, MODEL, hash, configuration, selectionMode, exec } from '../src/hardened-policy.mjs';
import { EvidenceService } from '../src/hardened-service.mjs';
import { Store } from '../src/hardened-store.mjs';
import { enableDefault, startTrial, stopTrial, trialReport, withEvaluationLock } from '../scripts/retrieval-trial.mjs';

async function fixture(t) {
  const base = await mkdtemp(join(tmpdir(), 'jev-trial-')), home = join(base, 'private'), root = join(base, 'workspace');
  await mkdir(home, { mode: 0o700 }); await mkdir(root); await exec('git', ['init', '-q', root]);
  const save = (name, value) => writeFile(join(home, name), JSON.stringify(value), { mode: 0o600 });
  await save('config.json', { ...defaults, allowed_roots: [root], validation_budget_usd: 1, monthly_budget_usd: 1, total_budget_usd: 1 });
  await save('evaluation-latest.json', { reportPath: join(home, 'retention.json') });
  await save('retention.json', { status: 'retention_passed', sourcePolicy: POLICY, live: true,
    arms: Array.from({ length: 8 }, () => ({ grade: { passed: true }, unchanged: true })) });
  await mkdir(join(home, 'secrets'), { mode: 0o700 });
  await writeFile(join(home, 'secrets/typesafe_api_key'), 'offline-test-token', { mode: 0o600 });
  t.after(() => rm(base, { recursive: true, force: true }));
  return { home, root, save };
}

test('measurement cohorts keep legacy, ordinary and comparison usage separate', async t => {
  const f = await fixture(t), store = new Store(f.home);
  t.after(() => store.close());
  const row = { trialId: 'qualified', workspaceHash: hash(f.root), sessionId: randomUUID(), mode: 'jev', metrics: { jevInputTokens: 10 } };
  store.measure(row);
  store.measure({ ...row, revision: hash('new-build'), origin: 'ordinary' });
  store.measure({ ...row, revision: hash('new-build'), origin: 'comparison' });
  const result = store.measurements();
  assert.equal(result.cohorts.length, 3);
  assert.equal(result.modes.jev.jevInputTokens, 30);
  assert.deepEqual(new Set(result.cohorts.map(r => r.origin)), new Set(['unattributed', 'ordinary', 'comparison']));
  assert.throws(() => store.measure({ ...row, origin: 'raw-prompt' }), { code: 'invalid_metrics' });
});

test('trial needs authorization and retention proof; activation is expiring, root-bound and not qualified', async t => {
  const f = await fixture(t);
  await assert.rejects(startTrial(f.home), { code: 'acknowledgement_required' });
  await assert.rejects(startTrial(f.home, { acknowledgeCost: true, days: 8 }), { code: 'invalid_trial' });
  const report = await startTrial(f.home, { acknowledgeCost: true });
  assert.equal(report.selectionMode, 'jev_trial'); assert.equal(report.liveValidated, false);
  assert.equal(report.totalCapUsd, 1); assert.equal(report.maxRequestsPerDay, 20);
  const config = await configuration(f.home);
  assert.equal(selectionMode(config, f.root), 'jev_trial');
  assert.equal(selectionMode(config, '/unapproved/project'), 'local_only');
  assert.equal(selectionMode(config, f.root, Date.parse(config.trial.expires_at)), 'local_only');
  assert.equal(selectionMode(config, f.root, Date.parse(config.trial.starts_at) - 1), 'local_only');
  assert.equal(selectionMode({ ...config, trial: { ...config.trial, policy: 'old' } }, f.root), 'local_only');
  await assert.rejects(startTrial(f.home, { acknowledgeCost: true }), { code: 'trial_conflict' });
  assert.equal((await stopTrial(f.home)).selectionMode, 'local_only');
  assert.equal((await configuration(f.home)).total_budget_usd, 1);
});

test('trial refuses missing/stale validation, halt and oversize duration', async t => {
  const f = await fixture(t);
  await f.save('retention.json', { status: 'retention_passed', sourcePolicy: 'old', live: true });
  await assert.rejects(startTrial(f.home, { acknowledgeCost: true }), { code: 'preflight_required' });
  await f.save('halt.json', {});
  await assert.rejects(startTrial(f.home, { acknowledgeCost: true }), { code: 'halted' });
  const config = await configuration(f.home);
  await f.save('config.json', { ...config, trial: { id: randomUUID(), policy: POLICY, roots: [f.root],
    starts_at: new Date().toISOString(), expires_at: new Date(Date.now() + 8 * 86400000).toISOString() } });
  await assert.rejects(configuration(f.home), { code: 'invalid_config' });
});

test('trial makes one live request, cache reuse is free, forced local never sends, and expired admission fails closed', async t => {
  const f = await fixture(t); await startTrial(f.home, { acknowledgeCost: true });
  let calls = 0;
  const service = await new EvidenceService({ home: f.home, boundRoot: f.root, fetcher: async (_url, options) => {
    calls++; const body = JSON.parse(options.body);
    return new Response(JSON.stringify({ model: MODEL, answers: Object.fromEntries(Object.keys(body.questions).map(key => [key, { type: 'noul', noul: 0.9 }])),
      usage: { input_tokens: 100, output_tokens: 10 } }));
  } }).init();
  t.after(() => service.close());
  for (let i = 0; i < 6; i++) await writeFile(join(f.root, `source-${i}.txt`), `search evidence ${'background '.repeat(280)}`);
  const input = { workspaceRoot: f.root, query: 'search evidence' };
  const first = await service.search(input), cached = await service.search(input);
  assert.equal(first.mode, 'jev'); assert.equal(cached.mode, 'cache'); assert.equal(calls, 1);
  assert.equal(cached.metrics.jevUsage, undefined); assert.equal(cached.metrics.nativeTokensMeasured, false);
  assert.ok(first.metrics.candidateEvidenceBytes >= first.metrics.selectedEvidenceBytes);
  await service.read({ sessionId: first.sessionId, evidenceId: first.evidence[0].evidenceId });
  const report = await trialReport(f.home);
  assert.equal(report.measurements.modes.jev.jevRequests, 1);
  assert.equal(report.measurements.modes.cache.jevRequests, 0);
  assert.equal(report.measurements.modes['exact-read'].followupReads, 1);
  assert.doesNotMatch(JSON.stringify(report.measurements), /background|source-0|search evidence|offline-test-token/);
  service.forceLocal = true;
  assert.equal((await service.search(input)).selectionReason, 'comparison_local'); assert.equal(calls, 1);
  service.forceLocal = false;
  const config = await configuration(f.home);
  config.trial.starts_at = new Date(Date.now() - 2 * 86400000).toISOString();
  config.trial.expires_at = new Date(Date.now() - 86400000).toISOString();
  await f.save('config.json', config);
  assert.equal((await service.search(input)).mode, 'local-fallback'); assert.equal(calls, 1);
  assert.throws(() => service.store.reserve(config, 'monthly', f.root), { code: 'disabled' });
  const trialId = config.trial.id;
  await stopTrial(f.home);
  await service.read({ sessionId: first.sessionId, evidenceId: first.evidence[0].evidenceId });
  assert.equal(service.store.measurements(trialId).modes['exact-read'].followupReads, 2);
});

test('measurement storage rejects unknown payload fields and prunes old metrics without altering billing', async t => {
  const f = await fixture(t), store = new Store(f.home); t.after(() => store.close());
  store.measure({ trialId: randomUUID(), workspaceHash: hash(f.root), sessionId: randomUUID(), mode: 'jev',
    metrics: { jevRequests: 1, selectedEvidenceBytes: 300, privateText: 'never persist this', query: 'private question', retrievalMs: NaN } });
  const value = store.db.prepare('SELECT value FROM retrieval_metrics').get().value;
  assert.deepEqual(JSON.parse(value), { selectedEvidenceBytes: 300, jevRequests: 1 });
  store.db.exec('UPDATE retrieval_metrics SET at=0');
  store.measure({ trialId: randomUUID(), workspaceHash: hash(f.root), sessionId: randomUUID(), mode: 'cache', metrics: {} });
  assert.equal(store.db.prepare('SELECT COUNT(*) count FROM retrieval_metrics').get().count, 1);
  assert.deepEqual(store.status(), []);
  assert.ok((await readFile(join(f.home, 'config.json'), 'utf8')).includes('false'));
});

test('trial configuration cannot change during another evaluation', async t => {
  const f = await fixture(t);
  await withEvaluationLock(f.home, async () => {
    await assert.rejects(startTrial(f.home, { acknowledgeCost: true }), { code: 'evaluation_busy' });
    await assert.rejects(stopTrial(f.home), { code: 'evaluation_busy' });
  });
  assert.equal((await configuration(f.home)).enabled, false);
});

test('persistent owner authorization preserves count, spending and retention gates', async t => {
  const f = await fixture(t);
  await assert.rejects(enableDefault(f.home), { code: 'acknowledgement_required' });
  const report = await enableDefault(f.home, { acknowledgeCost: true });
  assert.equal(report.selectionMode, 'jev_default');
  assert.equal(report.maxRequestsPerDay, 100); assert.equal(report.totalCapUsd, 1);
  assert.equal(report.liveValidated, false); assert.equal(report.trial, null);
  const config = await configuration(f.home);
  assert.equal(selectionMode(config, f.root, Date.now() + 365 * 86400000), 'jev_default');
  const store = new Store(f.home);
  try {
    const tinyLegacyCap = { ...config, max_requests_per_day: 1 };
    const first = store.reserve(tinyLegacyCap, 'monthly', f.root); store.settle(first, { input_tokens: 100 });
    assert.throws(() => store.reserve(tinyLegacyCap, 'monthly', f.root), { code: 'budget_blocked' });
    const second = store.reserve({ ...config, max_requests_per_day: null }, 'monthly', f.root);
    store.settle(second, { input_tokens: 100 });
    assert.throws(() => store.reserve({ ...tinyLegacyCap, total_budget_usd: 0 }, 'monthly', f.root), { code: 'budget_blocked' });
  } finally { store.close(); }
  assert.equal(selectionMode({ ...config, default_authorization: { ...config.default_authorization, policy: 'old' } }), 'local_only');
  assert.deepEqual((await enableDefault(f.home, { acknowledgeCost: true })).defaultAuthorization, report.defaultAuthorization);
  await f.save('retention.json', { status: 'retention_passed', sourcePolicy: 'old', live: true });
  await assert.rejects(enableDefault(f.home, { acknowledgeCost: true }), { code: 'preflight_required' });
  assert.equal((await stopTrial(f.home)).selectionMode, 'local_only');
  assert.equal((await configuration(f.home)).total_budget_usd, 1);
});

import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { defaults, POLICY } from '../src/hardened-policy.mjs';
import { Store } from '../src/hardened-store.mjs';
import { gradeSelection, runPreflight, validLiveSelection } from '../scripts/evaluation-preflight.mjs';

test('only a known no-request size or small-packet fallback passes the live safety gate', () => {
  assert.equal(validLiveSelection({ mode: 'local-fallback', selectionReason: 'request_limit', metrics: { jevRequests: 0 } }), true);
  assert.equal(validLiveSelection({ mode: 'bypass', metrics: { jevRequests: 0 } }), true);
  for (const selectionReason of ['disabled', 'key_missing', 'provider_error', 'selection_failed']) {
    assert.equal(validLiveSelection({ mode: 'local-fallback', selectionReason, metrics: { jevRequests: 0 } }), false);
  }
  assert.equal(validLiveSelection({ mode: 'local-fallback', selectionReason: 'request_limit', metrics: { jevRequests: 1 } }), false);
});

test('retention rubric rejects an omitted source and missing exception frames', () => {
  const task = { files: { 'a.mjs': 'source', 'b.md': 'constraint' } };
  const result = { evidence: [{ path: 'a.mjs', excerpt: 'source' }] };
  assert.equal(gradeSelection(task, result, [{ path: 'a.mjs', disposition: 'retained' },
    { path: 'b.md', disposition: 'omitted' }]).passed, false);
  const log = { path: 'trace.log', log: { exception: 'TypeError', key: 'POOL_SIZE', firstFrame: ['load', 'a:2'], secondFrame: ['start', 'b:4'] } };
  const partial = gradeSelection(log, { evidence: [{ path: log.path, excerpt: 'TypeError POOL_SIZE load a:2' }] },
    [{ path: log.path, disposition: 'retained' }]);
  assert.deepEqual(partial.missingDiagnostics, ['start', 'b:4']);
  assert.equal(partial.passed, false);
});

async function setup(t) {
  const home = await mkdtemp(join(tmpdir(), 'jev-preflight-'));
  await writeFile(join(home, 'config.json'), JSON.stringify({ ...defaults, enabled: true, monthly_budget_usd: 1,
    validation_budget_usd: 1, total_budget_usd: 1, allowed_roots: ['/owner/original'] }), { mode: 0o600 });
  await mkdir(join(home, 'secrets'), { mode: 0o700 });
  await writeFile(join(home, 'secrets', 'typesafe_api_key'), 'test-token-not-a-credential', { mode: 0o600 });
  t.after(() => rm(home, { force: true, recursive: true }));
  return home;
}

test('mocked live preflight uses shared ledger, preserves owner config and verifies exact reads', async t => {
  const home = await setup(t); let calls = 0;
  const originalConfig = await readFile(join(home, 'config.json'), 'utf8');
  const report = await runPreflight({ home, live: true, taskIds: ['environment-precedence-contract'], fetcher: async (url, request) => {
    calls++; assert.equal(url, 'https://api.typesafe.ai/v1/systemone');
    const body = JSON.parse(request.body);
    assert.doesNotMatch(request.body, /owner\/original|test-token-not/);
    return new Response(JSON.stringify({ model: body.model,
      answers: Object.fromEntries(Object.keys(body.questions).map(key => [key, { type: 'noul', noul: 0.9 }])),
      usage: { input_tokens: 200, output_tokens: 10 } }));
  } });
  assert.equal(report.status, 'retention_passed');
  assert.equal(report.sourcePolicy, POLICY);
  const manifest = JSON.parse(await readFile(join(report.reportPath, '..', 'manifest.json')));
  assert.equal(manifest.sourcePolicy, POLICY);
  assert.ok(report.arms.every(row => row.sourcePolicy === POLICY));
  assert.equal(calls, 1); assert.equal(report.nativeTokens, null);
  assert.ok(report.arms.every(row => row.unchanged && row.exactReads > 0));
  const config = JSON.parse(await readFile(join(home, 'config.json')));
  assert.equal(await readFile(join(home, 'config.json'), 'utf8'), originalConfig);
  assert.equal(config.enabled, true); assert.equal(config.live_validated, false);
  assert.deepEqual(config.allowed_roots, ['/owner/original']);
  const store = new Store(home); try { assert.equal(store.status()[0].requests, 1); } finally { store.close(); }
});

test('provider failure stops without retry and never rewrites live settings', async t => {
  const home = await setup(t); let calls = 0;
  const report = await runPreflight({ home, live: true, taskIds: ['environment-precedence-contract'],
    fetcher: async () => { calls++; return new Response('private body never persisted', { status: 503 }); } });
  assert.equal(report.status, 'blocked'); assert.equal(report.error, 'live_selection_failed'); assert.equal(calls, 1);
  assert.doesNotMatch(await readFile(report.reportPath, 'utf8'), /private body never/);
  const config = JSON.parse(await readFile(join(home, 'config.json')));
  assert.equal(config.enabled, true); assert.deepEqual(config.allowed_roots, ['/owner/original']);
});

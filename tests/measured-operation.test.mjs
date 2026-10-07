import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { defaults, exec, SafeError } from '../src/hardened-policy.mjs';
import { measuredOperation, operationMetrics } from '../src/measured-operation.mjs';

const runtimePath = join(dirname(fileURLToPath(import.meta.url)), '..', 'runtime');

async function fixture(t, enabled = true) {
  const home = await mkdtemp(join(tmpdir(), 'jev-measured-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  await mkdir(home, { recursive: true, mode: 0o700 });
  await writeFile(join(home, 'config.json'), JSON.stringify({ ...defaults, measurement_enabled: enabled }), { mode: 0o600 });
  return { home, boundRoot: home, buildHash: 'a'.repeat(64), measurementOrigin: 'synthetic' };
}

test('cache hits never claim repeated provider token usage', () => {
  const value = { mode: 'cache', metrics: { jevRequests: 0, jevUsage: { input_tokens: 100, output_tokens: 10 } } };
  const result = operationMetrics('search_workspace_evidence', value, {}, 3);
  assert.equal(result.cacheHits, 1);
  assert.equal(result.jevInputTokens, undefined);
  assert.equal(result.jevOutputTokens, undefined);
});

test('local fallbacks are counted separately from free small-result bypasses', () => {
  const fallback = operationMetrics('search_workspace_evidence', { mode: 'local-fallback', metrics: { jevRequests: 0 } }, {}, 2);
  assert.equal(fallback.localFallbacks, 1);
  assert.equal(fallback.localBypasses, undefined);
  assert.equal(operationMetrics('search_workspace_evidence', { mode: 'bypass' }, {}, 2).localBypasses, 1);
});

test('full envelopes and exact follow-up bytes are measured without content storage', async t => {
  const service = await fixture(t);
  const response = await measuredOperation(service, 'read_selected_evidence', { evidenceId: 'NEVER-STORE-INPUT' },
    async () => ({ content: 'NEVER-STORE-SOURCE' }));
  assert.ok(response.structuredContent.measurementId);
  const db = new DatabaseSync(join(service.home, 'invocations.sqlite3'), { readOnly: true });
  try {
    const row = db.prepare('SELECT * FROM invocations').get();
    const metrics = JSON.parse(row.metrics);
    assert.equal(row.result_status, 'success'); assert.equal(row.session_hash, null);
    assert.equal(metrics.followupReads, 1); assert.equal(metrics.followupBytes, 18);
    assert.equal(metrics.responseBytes, Buffer.byteLength(JSON.stringify(response)));
  } finally { db.close(); }
  const raw = await readFile(join(service.home, 'invocations.sqlite3'));
  assert.equal(raw.includes(Buffer.from('NEVER-STORE-INPUT')), false);
  assert.equal(raw.includes(Buffer.from('NEVER-STORE-SOURCE')), false);
});

test('native receipts verify list, exact-read and synthetic cache-hit envelopes; unknown tool aliases stay unattributed', async t => {
  const service = await fixture(t);
  const codexHome = service.home;
  service.home = join(codexHome, 'jev-context');
  await mkdir(service.home, { mode: 0o700 });
  await writeFile(join(service.home, 'config.json'), JSON.stringify({ ...defaults, measurement_enabled: true }), { mode: 0o600 });
  service.boundRoot = join(codexHome, 'workspace');
  await mkdir(service.boundRoot);
  await exec('git', ['init', '-q', service.boundRoot]);
  const runHook = (hook, payload) => exec(process.env.JEV_TEST_PYTHON || 'python3', ['-c', `
import json, sys
from common import Home
from invocations import ${hook}
h = Home(sys.argv[1])
p = json.loads(sys.argv[3])
h.register(sys.argv[2], p['session_id'])
print(json.dumps(${hook}(h, p, sys.argv[2])))
`, codexHome, service.boundRoot, JSON.stringify(payload)], {
    env: { ...process.env, PYTHONPATH: runtimePath }, timeout: 20000,
  });
  const cases = [
    { name: 'list_evidence', input: { sessionId: 'synthetic-session' }, run: async () => ({ total: 2 }) },
    { name: 'read_selected_evidence', input: { evidenceId: 'synthetic-evidence' }, run: async () => ({ content: 'synthetic exact read' }) },
    { name: 'search_workspace_evidence', input: { query: 'synthetic cache' }, run: async () => ({
      mode: 'cache', metrics: { jevRequests: 0, jevUsage: { input_tokens: 12, output_tokens: 3 } },
    }) },
    { name: 'judge_evidence', input: { question: 'synthetic claim' }, run: async () => ({
      mode: 'jev', advisory: true, metrics: { jevRequests: 1, jevUsage: { input_tokens: 20, output_tokens: 3 } },
    }) },
  ];
  const envelopes = [];

  for (const [index, item] of cases.entries()) {
    const payload = {
      session_id: 'synthetic-native-task', turn_id: 'synthetic-native-turn',
      tool_use_id: `synthetic-native-call-${index}`,
      tool_name: `mcp__jev_context__${item.name}`, tool_input: item.input,
    };
    const pre = await runHook('pre_tool', payload);
    assert.equal(JSON.parse(pre.stdout).state, 'receipt_created', item.name);
    const result = await measuredOperation(service, item.name, item.input, item.run);
    envelopes.push(result);
    const post = await runHook('post_tool', { ...payload, tool_response: result });
    assert.equal(JSON.parse(post.stdout).state, 'verified', item.name);
    assert.ok(result.structuredContent.measurementId, item.name);
    if (item.name === 'search_workspace_evidence') {
      const metrics = operationMetrics(item.name, result.structuredContent, result, 1);
      assert.equal(metrics.cacheHits, 1);
      assert.equal(metrics.jevInputTokens, undefined);
    }
  }

  const db = new DatabaseSync(join(service.home, 'invocations.sqlite3'), { readOnly: true });
  try {
    const rows = db.prepare('SELECT operation, session_hash, turn_hash, call_hash, metrics FROM invocations ORDER BY operation').all();
    assert.equal(rows.length, 4);
    assert.deepEqual(rows.map(row => row.operation), ['judge_evidence', 'list_evidence', 'read_selected_evidence', 'search_workspace_evidence']);
    assert.ok(rows.every(row => row.session_hash && row.turn_hash && row.call_hash));
    assert.equal(new Set(rows.map(row => row.call_hash)).size, 4);
    assert.equal(JSON.parse(rows.find(row => row.operation === 'search_workspace_evidence').metrics).cacheHits, 1);
    const readMetrics = JSON.parse(rows.find(row => row.operation === 'read_selected_evidence').metrics);
    assert.equal(readMetrics.followupReads, 1);
    assert.equal(readMetrics.followupBytes, Buffer.byteLength('synthetic exact read'));
  } finally { db.close(); }

  const unknown = {
    session_id: 'synthetic-native-task', turn_id: 'synthetic-native-turn',
    tool_use_id: 'synthetic-unknown-call',
    tool_name: 'mcp__jev_context__search_workspace_evidence_alias',
    tool_input: { query: 'synthetic cache' },
  };
  const ignored = await runHook('pre_tool', unknown);
  assert.equal(JSON.parse(ignored.stdout).state, 'not_covered');
  const ignoredPost = await runHook('post_tool', { ...unknown, tool_response: envelopes[0] });
  assert.equal(JSON.parse(ignoredPost.stdout).state, 'not_covered');
  const finalDb = new DatabaseSync(join(service.home, 'invocations.sqlite3'), { readOnly: true });
  try {
    assert.equal(finalDb.prepare('SELECT COUNT(*) AS count FROM invocation_receipts').get().count, 4);
    assert.equal(finalDb.prepare('SELECT COUNT(*) AS count FROM invocations WHERE call_hash IS NOT NULL').get().count, 4);
  } finally { finalDb.close(); }
});

test('safe errors remain errors; private exception payloads are not returned or persisted', async t => {
  const service = await fixture(t);
  const response = await measuredOperation(service, 'search_workspace_evidence', {}, async () => {
    throw new Error('PRIVATE-ERROR-CANARY');
  });
  assert.equal(response.isError, true);
  assert.equal(response.structuredContent.code, 'evidence_failed');
  assert.doesNotMatch(JSON.stringify(response), /PRIVATE-ERROR/);
  assert.ok(response.structuredContent.measurementId);
  assert.equal((await readFile(join(service.home, 'invocations.sqlite3'))).includes(Buffer.from('PRIVATE-ERROR')), false);
});

test('disabled measurement creates no invocation ledger and does not alter operation behavior', async t => {
  const service = await fixture(t, false);
  const response = await measuredOperation(service, 'list_evidence', {}, async () => ({ total: 2 }));
  assert.deepEqual(response.structuredContent, { total: 2 });
  await assert.rejects(readFile(join(service.home, 'invocations.sqlite3')), { code: 'ENOENT' });
});

test('measurement corruption cannot convert a denied operation into success', async t => {
  const service = await fixture(t);
  await writeFile(join(service.home, 'invocations.sqlite3'), 'corrupt', { mode: 0o600 });
  const response = await measuredOperation(service, 'search_workspace_evidence', {}, async () => {
    throw new SafeError('workspace_denied', 'Workspace denied');
  });
  assert.equal(response.isError, true);
  assert.equal(response.structuredContent.code, 'workspace_denied');
  assert.match(response.structuredContent.measurementWarning, /unavailable/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { defaults, SafeError } from '../src/hardened-policy.mjs';
import { measuredOperation, operationMetrics } from '../src/measured-operation.mjs';

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

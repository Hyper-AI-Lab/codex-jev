import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { COMPARISON_PLAN, nextAllowed, comparisonPrompt, runComparison } from '../scripts/hardening-comparison.mjs';
import { TASKS } from '../benchmarks/confirmation-v4-tasks.mjs';
import { evaluationLaunch } from '../src/evaluation-launch.mjs';
import { EvidenceService } from '../src/hardened-service.mjs';
import { defaults, hash, readPrivateJson } from '../src/hardened-policy.mjs';
import { mcpArguments } from '../scripts/native-packet-pilot.mjs';

test('comparison has exactly two counterbalanced pairs and stops on unknown usage, failure or input boundary', () => {
  assert.deepEqual(COMPARISON_PLAN.map(row => row.arm), ['native', 'jev', 'jev', 'native']);
  assert.equal(new Set(COMPARISON_PLAN.map(row => row.taskId)).size, 2);
  assert.equal(nextAllowed([]), COMPARISON_PLAN[0]);
  const success = { status: 'completed', usage: { input_tokens: 100 } };
  assert.equal(nextAllowed([success]), COMPARISON_PLAN[1]);
  for (const row of [{ status: 'started', usage: null }, { ...success, error: 'native_quota' }, { ...success, usage: null }])
    assert.throws(() => nextAllowed([row]), { code: 'prior_run_unresolved' });
  assert.throws(() => nextAllowed([{ ...success, usage: { input_tokens: 100000 } }]), { code: 'input_boundary' });
  assert.throws(() => nextAllowed(Array(4).fill(success)), { code: 'comparison_complete' });
});

test('log and workspace prompts use their correct actual MCP tool and preserve task/rubric', () => {
  for (const task of TASKS.filter(task => COMPARISON_PLAN.some(row => row.taskId === task.id))) {
    const native = comparisonPrompt(task, '/fixture', 'native'), jev = comparisonPrompt(task, '/fixture', 'jev');
    assert.ok(native.includes(task.query) && jev.includes(task.query));
    assert.ok(jev.includes(task.path ? 'read_large_text_evidence' : 'search_workspace_evidence'));
    assert.ok(native.includes('At most 12 tool calls') && jev.includes('At most 12 tool calls'));
    for (const requirement of task.requirements) assert.ok(native.includes(requirement) && jev.includes(requirement));
  }
  assert.throws(() => mcpArguments({ command: '/node', server: '/server', home: '/home', forceLocal: false,
    manifestPath: '/manifest', manifestHash: 'invalid' }), { code: 'invalid_mcp_launch' });
});

test('comparison manifest authority is hash-bound, time-limited and cannot authorize other workspaces or changed files', async t => {
  const base = await mkdtemp(join(tmpdir(), 'jev-comparison-')), home = join(base, 'private');
  const run = join(home, 'evaluations', 'fixed'), root = join(run, 'fixtures', 'environment-precedence-contract');
  await mkdir(root, { recursive: true, mode: 0o700 });
  t.after(() => rm(base, { recursive: true, force: true }));
  await writeFile(join(home, 'config.json'), JSON.stringify(defaults), { mode: 0o600 });
  const source = 'checkout evidence'; await writeFile(join(root, 'source.txt'), source);
  const manifest = { kind: 'capped-hardening-comparison-v1', maxNativeRuns: 4, inputBoundary: 100000,
    expires: new Date(Date.now() + 3600000).toISOString(), baseline: { 'environment-precedence-contract': { 'source.txt': hash(source) } } };
  const path = join(run, 'comparison-manifest.json');
  await writeFile(path, JSON.stringify(manifest), { mode: 0o600 });
  const digest = hash(JSON.stringify(manifest)), options = await evaluationLaunch(home, root, path, digest);
  const service = await new EvidenceService({ home, boundRoot: root, forceLocal: true, ...options }).init();
  t.after(() => service.close());
  const result = await service.search({ workspaceRoot: root, query: 'checkout' });
  assert.equal(result.evidence[0].path, 'source.txt');
  await assert.rejects(evaluationLaunch(home, root, path, hash('different')), { code: 'fixture_denied' });
  await assert.rejects(evaluationLaunch(home, base, path, digest), { code: 'fixture_denied' });
  await writeFile(join(root, 'source.txt'), 'changed');
  await assert.rejects(service.read({ sessionId: result.sessionId, evidenceId: result.evidence[0].evidenceId }), { code: 'fixture_changed' });
  manifest.expires = new Date(0).toISOString(); await writeFile(path, JSON.stringify(manifest), { mode: 0o600 });
  await assert.rejects(evaluationLaunch(home, root, path, hash(JSON.stringify(manifest))), { code: 'fixture_denied' });
});

test('comparison refuses acknowledgment-free execution before any native or Jev operation', async () => {
  await assert.rejects(runComparison(), { code: 'acknowledgment_required' });
});

test('persisted comparison stops after missing usage and refuses rerun without altering owner settings', { timeout: 90000 }, async t => {
  const home = await mkdtemp(join(tmpdir(), 'jev-capped-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  const config = { ...defaults, enabled: true };
  await writeFile(join(home, 'config.json'), JSON.stringify(config), { mode: 0o600 });
  let calls = 0;
  const options = { home, acknowledge: true, selectedSettings: async () => ({ model: 'mock', model_reasoning_effort: 'low' }),
    runNative: async () => { calls++; return { status: 'blocked', error: 'native_usage_unavailable', usage: null, answer: null }; } };
  const result = await runComparison(options);
  assert.equal(calls, 1); assert.equal(result.runs.length, 1); assert.equal(result.unknownUsageRuns, 1);
  assert.equal(result.status, 'blocked'); assert.equal(result.error, 'native_usage_unavailable');
  assert.deepEqual(await readPrivateJson(join(home, 'config.json')), config);
  await assert.rejects(runComparison(options), { code: 'already_attempted' });
  assert.equal(calls, 1);
});

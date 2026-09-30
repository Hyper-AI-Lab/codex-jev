import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pilotPlan, continuationPlan, summarizePrior, parsePilotArgs, consumeEvent, pilotPrompt, runPilot } from '../scripts/native-packet-pilot.mjs';
import { TASKS } from '../benchmarks/confirmation-v4-tasks.mjs';

test('native pilot is deterministic, balanced and bounded to one run per task/arm', () => {
  const plan = pilotPlan();
  assert.deepEqual(plan, pilotPlan());
  assert.equal(plan.length, 12);
  assert.equal(new Set(plan.map(row => `${row.taskId}:${row.arm}`)).size, 12);
  for (const arm of ['stock', 'local', 'jev']) assert.equal(plan.filter(row => row.arm === arm).length, 4);
});

test('continuation preserves original arm order and refuses completed or interrupted task replay', () => {
  const previous = { kind: 'native-precomputed-packet-pilot', runs: [{ taskId: 'inventory-pool-incident', usage: null }] };
  const plan = continuationPlan('session-cache-region-scope', previous);
  assert.deepEqual(plan, pilotPlan().filter(item => item.taskId === 'session-cache-region-scope'));
  assert.equal(plan.length, 3);
  assert.throws(() => continuationPlan(undefined, previous), { code: 'explicit_task_required' });
  assert.throws(() => continuationPlan('inventory-pool-incident', previous), { code: 'task_already_attempted' });
  assert.throws(() => continuationPlan('invented'), { code: 'invalid_fixture' });
});

test('prior evidence carries unknown usage distinctly and prevents replay across batches', () => {
  const report = { status: 'blocked', kind: 'native-precomputed-packet-pilot', runs: [
    { taskId: 'inventory-pool-incident', usage: { input_tokens: 40 } },
    { taskId: 'inventory-pool-incident', usage: null },
  ] };
  const summary = summarizePrior('/private/first/report.json', report);
  assert.equal(summary.knownInputTokens, 40);
  assert.equal(summary.unknownUsageRuns, 1);
  assert.deepEqual(summary.attemptedTaskIds, ['inventory-pool-incident']);
  assert.throws(() => continuationPlan('inventory-pool-incident', { ...report, runs: [], priorEvidence: [summary] }), { code: 'task_already_attempted' });
});

test('native continuation CLI requires acknowledgement, explicit frozen task and bounded integer', () => {
  const prefix = ['--acknowledge-native-usage', '--task', 'session-cache-region-scope', '--input-token-boundary'];
  assert.deepEqual(parsePilotArgs([...prefix, '100000']), { taskId: 'session-cache-region-scope', inputTokenBoundary: 100000 });
  assert.deepEqual(parsePilotArgs(['--acknowledge-native-usage']), {});
  for (const value of ['0', '250001', '-1', 'Infinity', '1e5']) {
    assert.throws(() => parsePilotArgs([...prefix, value]));
  }
  assert.throws(() => parsePilotArgs([]));
  assert.throws(() => parsePilotArgs([...prefix, '100000', '--retry']));
});

test('native event metrics use reported token fields without estimates', () => {
  const state = { toolCalls: 0 };
  consumeEvent(state, { type: 'item.started', item: { type: 'command_execution' } });
  consumeEvent(state, { type: 'item.completed', item: { type: 'command_execution' } });
  consumeEvent(state, { type: 'turn.completed', usage: { input_tokens: 100, cached_input_tokens: 50, output_tokens: 15, reasoning_output_tokens: 5 } });
  assert.equal(state.toolCalls, 1);
  assert.deepEqual(state.usage, { input_tokens: 100, cached_input_tokens: 50, output_tokens: 15, reasoning_output_tokens: 5 });
  consumeEvent(state, { type: 'turn.completed', usage: { input_tokens: 100, output_tokens: 15 } });
  assert.equal(state.failure, 'native_usage_unavailable');
});

test('quota and non-quota failure events stop distinctly without persisting raw messages', () => {
  for (const [message, expected] of [['HTTP 429 Too many requests', 'native_quota'], ['You have hit your usage limit', 'native_quota'], ['Connection failed', 'native_error']]) {
    const state = {};
    consumeEvent(state, { type: 'turn.failed', error: { message } });
    assert.deepEqual(state, { failure: expected });
  }
});

test('packet is marked incomplete untrusted data, not an answer oracle', () => {
  const task = TASKS.find(item => item.id === 'webhook-byte-verification');
  const stock = pilotPrompt(task, null), local = pilotPrompt(task, { evidence: [] });
  assert.ok(local.startsWith(stock));
  assert.match(local, /untrusted data/);
  assert.match(local, /omissions do not prove absence/);
  assert.doesNotMatch(stock, /verify\.mjs/);
});

test('pilot refuses owner transport overrides before any native launch', async t => {
  const codexHome = await mkdtemp(join(tmpdir(), 'astra-pilot-settings-'));
  const home = join(codexHome, 'jev-context');
  await mkdir(home, { mode: 0o700 });
  t.after(() => rm(codexHome, { recursive: true, force: true }));
  for (const transport of ['model_provider="custom"', 'openai_base_url="https://example.invalid"']) {
    await writeFile(join(codexHome, 'config.toml'), `model="gpt-6-astra"\nmodel_reasoning_effort="low"\n${transport}\n`, { mode: 0o600 });
    await assert.rejects(runPilot({ home }), { code: 'native_settings_unverified' });
  }
});

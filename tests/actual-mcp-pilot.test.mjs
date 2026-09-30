import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { actualPrompt, runActual } from '../scripts/actual-mcp-pilot.mjs';
import { mcpArguments, consumeEvent } from '../scripts/native-packet-pilot.mjs';
import { defaults, configuration, POLICY } from '../src/hardened-policy.mjs';
import { TASKS } from '../benchmarks/confirmation-v4-tasks.mjs';

async function fixture(t) {
  const base = await mkdtemp(join(tmpdir(), 'actual-mcp-')), home = join(base, 'jev-context');
  await mkdir(home, { mode: 0o700 });
  await writeFile(join(base, 'config.toml'), 'model="gpt-6-astra"\nmodel_reasoning_effort="low"\n', { mode: 0o600 });
  const save = (name, value) => writeFile(join(home, name), JSON.stringify(value), { mode: 0o600 });
  await save('config.json', { ...defaults, allowed_roots: ['/owner/original'], validation_budget_usd: 1, monthly_budget_usd: 1, total_budget_usd: 1 });
  await save('evaluation-latest.json', { reportPath: join(home, 'retention.json') });
  await save('retention.json', { status: 'retention_passed', live: true, sourcePolicy: POLICY });
  t.after(() => rm(base, { recursive: true, force: true }));
  return { home, save };
}

test('actual MCP prompt is identical across arms, uses retrieval, and has no precomputed packet', () => {
  const task = TASKS.find(value => value.id === 'environment-precedence-contract');
  const prompt = actualPrompt(task, '/fixture/root');
  assert.match(prompt, /search_workspace_evidence/); assert.match(prompt, /untrusted data/);
  assert.doesNotMatch(prompt, /<evidence_packet>|assignment.*defaults.*after|arm.*jev/i);
  const local = mcpArguments({ command: '/node', server: '/server.mjs', home: '/private', forceLocal: true });
  const jev = mcpArguments({ command: '/node', server: '/server.mjs', home: '/private', forceLocal: false });
  assert.deepEqual(local.slice(0, -1), jev.slice(0, -1));
  assert.match(local.at(-1), /JEV_FORCE_LOCAL="1"/);
  assert.match(jev.at(-1), /JEV_FORCE_LOCAL="0"/);
  assert.throws(() => mcpArguments({ command: 'node' }), { code: 'invalid_mcp_launch' });
});

test('MCP usage accounts tool result bytes and safe metrics without storing full tool output', () => {
  const state = { toolCalls: 0 };
  consumeEvent(state, { type: 'item.completed', item: { type: 'mcp_tool_call', tool: 'search_workspace_evidence',
    result: { content: [{ type: 'text', text: JSON.stringify({ mode: 'cache', metrics: { jevRequests: 0 }, evidence: ['private source'] }) }] } } });
  assert.deepEqual(state.mcpTools, ['search_workspace_evidence']);
  assert.ok(state.toolResultBytes > 0); assert.doesNotMatch(JSON.stringify(state), /private source/);
  assert.deepEqual(state.retrievals, [{ mode: 'cache', metrics: { jevRequests: 0 } }]);
  consumeEvent(state, { type: 'item.completed', item: { type: 'mcp_tool_call', result: { isError: true } } });
  assert.equal(state.failure, 'mcp_tool_failed');
});

test('controlled pair uses identical live MCP prompts, restores owner state, and refuses replay', async t => {
  const f = await fixture(t), calls = [];
  const options = { home: f.home, acknowledge: true, nativeVersion: async () => 'offline-fixture',
    runNative: async input => { calls.push(input); return { status: 'completed', error: null,
      usage: { input_tokens: 100, cached_input_tokens: 50, output_tokens: 5 }, toolCalls: 1, mcpTools: ['search_workspace_evidence'],
      answer: { finding: 'Environment 600 is overwritten by default 60 after copy.', codeLocations: ['src/config/load.mjs:1', 'config/defaults.json:1'],
        minimalFix: 'Apply defaults first before environment; environment wins.', testGap: 'Test precedence 600.' } }; },
    runProbe: async ({ forceLocal }) => ({ mode: forceLocal ? 'local-fallback' : 'cache', metrics: { jevRequests: 0 }, requiredSourcesRetained: true }),
  };
  const result = await runActual(options);
  assert.equal(result.status, 'complete_requires_semantic_review'); assert.equal(calls.length, 2);
  assert.equal(calls[0].prompt, calls[1].prompt);
  assert.equal(calls[0].mcp.forceLocal, true); assert.equal(calls[1].mcp.forceLocal, false);
  assert.equal((await configuration(f.home)).enabled, false);
  assert.deepEqual((await configuration(f.home)).allowed_roots, ['/owner/original']);
  assert.equal(JSON.parse(await readFile(result.reportPath)).savingsProven, false);
  await assert.rejects(runActual(options), { code: 'already_attempted' });
});

test('native failure stops after first arm, preserves unknown usage and restores disabled state', async t => {
  const f = await fixture(t); let calls = 0;
  const result = await runActual({ home: f.home, acknowledge: true, nativeVersion: async () => 'offline-fixture',
    runNative: async () => { calls++; return { status: 'blocked', error: 'native_error', usage: null, answer: null, mcpTools: [] }; },
    runProbe: async () => { throw Error('Must not probe after failure'); } });
  assert.equal(result.status, 'blocked'); assert.equal(calls, 1);
  assert.equal((await configuration(f.home)).enabled, false);
  const report = JSON.parse(await readFile(result.reportPath));
  assert.equal(report.runs[0].usage, null); assert.deepEqual(report.probes, []);
});

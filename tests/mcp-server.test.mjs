import assert from 'node:assert/strict';
import { mkdtemp, readFile, mkdir, writeFile, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { defaults, exec } from '../src/hardened-policy.mjs';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
test('legacy plugin no longer inherits keys or auto-approves tools', async () => {
  const config = JSON.parse(await readFile(join(repoRoot, '.mcp.json'), 'utf8'));
  assert.equal(config.mcpServers.jev_token_saver.env_vars, undefined);
  assert.equal(config.mcpServers.jev_token_saver.default_tools_approval_mode, undefined);
});

test('built stdio server works in two isolated workspaces with private shared configuration', async () => {
  const temp = await realpath(await mkdtemp(join(tmpdir(), 'astra-mcp-')));
  const home = join(temp, 'codex', 'jev-context'), roots = [join(temp, 'one'), join(temp, 'two')];
  const clients = [];
  try {
    await mkdir(home, { recursive: true, mode: 0o700 });
    await writeFile(join(home, 'config.json'), JSON.stringify({ ...defaults, allowed_roots: roots }), { mode: 0o600 });
    let firstSession;
    for (const root of roots) {
      await mkdir(root); await exec('git', ['init', '-q', root]);
      await writeFile(join(root, 'source.js'), 'const evidence = 42;\n// must not lose errors\n');
      const transport = new StdioClientTransport({ command: process.execPath, args: [join(repoRoot, 'dist/server.mjs')], cwd: root,
        env: { PATH: process.env.PATH, JEV_CONTEXT_HOME: home }, stderr: 'pipe' });
      const client = new Client({ name: 'astra-offline-test', version: '1.0.0' });
      clients.push(client); await client.connect(transport);
      assert.match(client.getInstructions(), /at most one targeted recovery selection/);
      const listed = await client.listTools();
      assert.deepEqual(listed.tools.map(t => t.name).sort(), ['evidence_status', 'judge_evidence', 'list_evidence', 'read_large_text_evidence', 'read_selected_evidence', 'search_workspace_evidence']);
      const judgment = await client.callTool({ name: 'judge_evidence', arguments: { workspaceRoot: root, preset: 'completion_claim',
        question: 'This source declares evidence as 42', items: [{ path: 'source.js', startLine: 1, endLine: 1 }] } });
      assert.equal(judgment.isError, undefined);
      assert.equal(judgment.structuredContent.mode, 'unavailable');
      assert.equal(judgment.structuredContent.reason, 'disabled');
      assert.deepEqual(judgment.structuredContent.results, []);
      const result = await client.callTool({ name: 'search_workspace_evidence', arguments: { workspaceRoot: root, query: 'evidence' } });
      assert.equal(result.isError, undefined);
      assert.equal(result.structuredContent.mode, 'bypass');
      assert.equal(result.structuredContent.evidence[0].path, 'source.js');
      const sessionId = result.structuredContent.sessionId;
      const read = await client.callTool({ name: 'read_selected_evidence', arguments: { sessionId, path: 'source.js', startLine: 1, endLine: 1 } });
      assert.equal(read.isError, undefined); assert.equal(read.structuredContent.content, '1: const evidence = 42;');
      if (firstSession) {
        const denied = await client.callTool({ name: 'list_evidence', arguments: { sessionId: firstSession } });
        assert.equal(denied.isError, true); assert.match(denied.content[0].text, /session_expired/);
      }
      firstSession = sessionId;
      const denied = await client.callTool({ name: 'search_workspace_evidence', arguments: { workspaceRoot: roots.find(r => r !== root), query: 'evidence' } });
      assert.equal(denied.isError, true);
      const status = await client.callTool({ name: 'evidence_status', arguments: {} });
      assert.equal(status.structuredContent.enabled, false);
      assert.equal(status.structuredContent.judgments.advisoryOnly, true);
      assert.equal(status.structuredContent.selectionMode, 'local_only');
      assert.deepEqual(status.structuredContent.liveSelectionBlockers, ['selection_disabled', 'qualification_or_owner_authorization_required']);
      assert.equal(status.structuredContent.hookTrust, 'not_inspected_by_mcp');
      for (const [enabled, live_validated] of [[true, false], [false, true], [true, true]]) {
        await writeFile(join(home, 'config.json'), JSON.stringify({ ...defaults, allowed_roots: roots, enabled, live_validated }), { mode: 0o600 });
        const current = (await client.callTool({ name: 'evidence_status', arguments: {} })).structuredContent;
        assert.equal(current.selectionMode, enabled && live_validated ? 'jev_eligible' : 'local_only');
        assert.deepEqual(current.liveSelectionBlockers, [...(!enabled ? ['selection_disabled'] : []), ...(!live_validated ? ['qualification_or_owner_authorization_required'] : [])]);
        assert.equal(current.hookTrust, 'not_inspected_by_mcp');
        assert.deepEqual(current.accounting, []);
        assert.match(current.eligibilityNote, /per-request.*budget/);
      }
      await writeFile(join(home, 'config.json'), JSON.stringify({ ...defaults, allowed_roots: roots }), { mode: 0o600 });
    }
  } finally {
    for (const client of clients) await client.close();
    await rm(temp, { recursive: true, force: true });
  }
});

test('native pre/post hook receipts verify real stdio results across Python and Node', async () => {
  const temp = await realpath(await mkdtemp(join(tmpdir(), 'jev-attribution-')));
  const codexHome = join(temp, 'codex'), home = join(codexHome, 'jev-context'), root = join(temp, 'workspace');
  const client = new Client({ name: 'receipt-offline-test', version: '1.0.0' });
  const native = { session_id: 'synthetic-native-task', turn_id: 'synthetic-native-turn', tool_use_id: 'synthetic-native-call' };
  const runPython = (code, data) => exec(process.env.JEV_TEST_PYTHON || 'python3', ['-c', code, codexHome, root, JSON.stringify(data)], {
    env: { ...process.env, PYTHONPATH: join(repoRoot, 'runtime') }, timeout: 20000,
  });
  try {
    await mkdir(home, { recursive: true, mode: 0o700 });
    await mkdir(root); await exec('git', ['init', '-q', root]);
    await writeFile(join(root, 'evidence.txt'), 'call-specific diagnostic evidence\n');
    await writeFile(join(home, 'config.json'), JSON.stringify({ ...defaults, measurement_enabled: true, allowed_roots: [root] }), { mode: 0o600 });
    const input = { workspaceRoot: root, query: 'diagnostic', requirements: ['keep Unicode \u00e9 evidence'], resultLimit: 4 };
    const payload = { ...native, tool_name: 'mcp__jev_context__search_workspace_evidence', tool_input: input };
    const pre = await runPython('import sys,json;from common import Home;from invocations import pre_tool;h=Home(sys.argv[1]);p=json.loads(sys.argv[3]);h.register(sys.argv[2],p["session_id"]);print(json.dumps(pre_tool(h,p,sys.argv[2])))', payload);
    assert.equal(JSON.parse(pre.stdout).state, 'receipt_created');
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [join(repoRoot, 'dist/server.mjs')], cwd: root,
      env: { PATH: process.env.PATH, JEV_CONTEXT_HOME: home }, stderr: 'pipe' }));
    const result = await client.callTool({ name: 'search_workspace_evidence', arguments: input });
    assert.equal(result.isError, undefined);
    assert.ok(result.structuredContent.measurementId);
    const post = await runPython('import sys,json;from common import Home;from invocations import post_tool,usage_report;h=Home(sys.argv[1]);p=json.loads(sys.argv[3]);print(json.dumps({"link":post_tool(h,p,sys.argv[2]),"report":usage_report(h,p["session_id"])}))', { ...payload, tool_response: result });
    const observed = JSON.parse(post.stdout);
    assert.equal(observed.link.state, 'verified');
    assert.equal(observed.report.verifiedOperations, 1);
    assert.equal(observed.report.metrics.localBypasses, 1);
    assert.equal(observed.report.accountSavingsMeasured, false);
    const status = (await client.callTool({ name: 'evidence_status', arguments: {} })).structuredContent;
    assert.equal(status.invocationCoverage.verified, 1);
  } finally { await client.close(); await rm(temp, { recursive: true, force: true }); }
});

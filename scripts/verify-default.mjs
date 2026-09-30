#!/usr/bin/env node
// One installed-protocol selection and one fresh-process cache check. No native
// coding-model benchmark or automatic replay; only numerical evidence is saved.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { exec, defaultHome, hash, POLICY, SafeError } from '../src/hardened-policy.mjs';
import { savePrivate } from './retrieval-trial.mjs';

export async function verifyDefault({ root, path, query }) {
  const { stdout } = await exec('codex', ['mcp', 'get', 'jev_context', '--json'], { timeout: 10000, maxBuffer: 65536 });
  const installed = JSON.parse(stdout), transport = installed.transport;
  if (!installed.enabled || transport?.type !== 'stdio') throw new SafeError('installation_required', 'Installed stdio integration is required');
  const report = { at: new Date().toISOString(), policy: POLICY, workspaceHash: hash(root), passes: [],
    nativeTokensMeasured: false, desktopReloadVerified: false };
  for (const pass of ['selection', 'fresh_process_cache']) {
    const client = new Client({ name: 'astra-default-verification', version: '1' });
    try {
      await client.connect(new StdioClientTransport({ command: transport.command, args: transport.args, cwd: root,
        env: { PATH: process.env.PATH, HOME: process.env.HOME, ...transport.env }, stderr: 'pipe' }));
      const call = async (name, args = {}) => {
        const reply = await client.callTool({ name, arguments: args });
        if (reply.isError) {
          const code = JSON.parse(reply.content[0].text).code;
          throw new SafeError(code, 'Installed tool verification failed; inspect local status, do not retry');
        }
        return reply.structuredContent;
      };
      const status = await call('evidence_status');
      if (status.sourcePolicy !== POLICY || status.selectionMode !== 'jev_default') throw new SafeError('reload_required', 'Installed process did not load the authorized default');
      const result = await call(path ? 'read_large_text_evidence' : 'search_workspace_evidence', {
        workspaceRoot: root, ...(path ? { path } : {}), query, resultLimit: 4,
      });
      if (!(pass === 'selection' ? ['jev', 'cache'].includes(result.mode) : result.mode === 'cache') || !result.evidence.length)
        throw new SafeError('selection_unverified', 'Real selection/cache behavior was not verified; no retry');
      let exactReads = 0;
      for (const item of result.evidence) {
        const read = await call('read_selected_evidence', { sessionId: result.sessionId, evidenceId: item.evidenceId,
          startLine: item.lines.start, endLine: item.lines.end });
        if (read.hash !== item.hash || read.content !== item.excerpt) throw new SafeError('evidence_mismatch', 'Hash or exact source range differs');
        exactReads++;
      }
      report.passes.push({ pass, mode: result.mode, metrics: result.metrics, exactReads, omissionCount: result.omittedCount,
        unscoredCount: result.unscoredCount, warnings: result.warnings });
    } finally { await client.close(); }
  }
  report.passed = true;
  const evidencePath = join(defaultHome(), `default-proof-${hash(root).slice(0, 16)}.json`);
  await savePrivate(evidencePath, report);
  return { ...report, evidencePath };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.umask(0o077);
  const args = process.argv.slice(2);
  try {
    if (args.length !== 4 || args[0] !== '--acknowledge-cost') throw new SafeError('invalid_arguments', 'Use --acknowledge-cost ABSOLUTE_WORKSPACE RELATIVE_PATH QUERY');
    console.log(JSON.stringify(await verifyDefault({ root: args[1], path: args[2], query: args[3] })));
  } catch (error) {
    console.error(JSON.stringify({ error: error instanceof SafeError ? error.code : 'verification_failed',
      instruction: 'Inspect status; no automatic retry, provider switch or cap reset.' }));
    process.exitCode = 1;
  }
}

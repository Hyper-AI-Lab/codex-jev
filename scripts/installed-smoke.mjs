#!/usr/bin/env node
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { exec } from '../src/hardened-policy.mjs';

const root = process.cwd();
const { stdout } = await exec('codex', ['mcp', 'get', 'jev_context', '--json'], { timeout: 10000, maxBuffer: 65536 });
const config = JSON.parse(stdout), transport = config.transport;
if (!config.enabled || transport?.type !== 'stdio') throw new Error('Installed stdio entry is not enabled');
const client = new Client({ name: 'astra-installed-offline-smoke', version: '1' });
try {
  await client.connect(new StdioClientTransport({ command: transport.command, args: transport.args, cwd: root,
    env: { PATH: process.env.PATH, HOME: process.env.HOME, ...transport.env }, stderr: 'pipe' }));
  const status = await client.callTool({ name: 'evidence_status', arguments: {} });
  if (status.isError || status.structuredContent.enabled) throw new Error('Smoke requires paid selection disabled');
  const listed = await client.listTools();
  const selected = await client.callTool({ name: 'read_large_text_evidence', arguments: {
    workspaceRoot: root, path: 'README.md', query: 'architecture deployment installation project evidence', resultLimit: 1,
  } });
  if (selected.isError || !selected.structuredContent.evidence.length) throw new Error('Installed selection failed');
  const data = selected.structuredContent;
  const read = await client.callTool({ name: 'read_selected_evidence', arguments: {
    sessionId: data.sessionId, evidenceId: data.evidence[0].evidenceId, startLine: 1, endLine: 5,
  } });
  if (read.isError || data.metrics.jevRequests !== 0) throw new Error('Installed read/local-only invariant failed');
  console.log(JSON.stringify({ root, passed: true, toolCount: listed.tools.length, mode: data.mode,
    jevRequests: 0, selectedCount: data.evidence.length, exactReadVerified: true, nativeDesktopReloadVerified: false }));
} finally { await client.close(); }

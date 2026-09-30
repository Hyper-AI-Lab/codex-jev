import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { SafeError } from '../src/hardened-policy.mjs';
import { gradeSelection } from './evaluation-preflight.mjs';

export async function comparisonProbe({ home, root, server, manifestPath, manifestHash, revision, task }) {
  const client = new Client({ name: 'hardening-cache-proof', version: '1' });
  const call = async (name, args) => {
    const result = await client.callTool({ name, arguments: args });
    if (result.isError) {
      let code;
      try { code = JSON.parse(result.content?.[0]?.text).code; } catch { /* Do not echo provider-controlled bodies. */ }
      throw new SafeError(['halted', 'usage_invalid'].includes(code) ? code : 'probe_failed', 'Protocol probe failed.');
    }
    if (!result.structuredContent) throw new SafeError('probe_failed', 'Protocol response lacks structured evidence.');
    return result.structuredContent;
  };
  try {
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [server], cwd: root,
      env: { PATH: process.env.PATH, HOME: process.env.HOME, JEV_CONTEXT_HOME: home,
        JEV_EVALUATION_MANIFEST: manifestPath, JEV_EVALUATION_DIGEST: manifestHash }, stderr: 'pipe' }));
    const status = await call('evidence_status', {});
    if (status.loadedBuild !== revision || status.measurementOrigin !== 'comparison') throw new SafeError('probe_failed', 'Loaded comparison build is not verified.');
    const result = await call(task.path ? 'read_large_text_evidence' : 'search_workspace_evidence', {
      workspaceRoot: root, query: task.query, requirements: task.requirements, candidateLimit: 20, resultLimit: 8,
      ...(task.path ? { path: task.path } : {}) });
    const records = []; let offset = 0;
    do {
      const page = await call('list_evidence', { sessionId: result.sessionId, offset });
      records.push(...page.evidence);
      if (page.nextOffset !== null && page.nextOffset <= offset) throw new SafeError('probe_failed', 'Reference pagination did not advance.');
      offset = page.nextOffset;
    } while (offset !== null);
    let exactReads = 0;
    for (const item of result.evidence) {
      const read = await call('read_selected_evidence', { sessionId: result.sessionId, evidenceId: item.evidenceId, startLine: item.lines.start, endLine: item.lines.end });
      if (read.hash !== item.hash || read.content !== item.excerpt) throw new SafeError('probe_failed', 'Exact range/hash mismatch.');
      exactReads++;
    }
    return { mode: result.mode, metrics: result.metrics, exactReads, grade: gradeSelection(task, result, records) };
  } finally { await client.close(); }
}

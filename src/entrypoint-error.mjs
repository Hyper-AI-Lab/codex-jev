import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { exec, SafeError } from './hardened-policy.mjs';

export async function entrypointError(error, home) {
  let checkpoint = '';
  if (['halted', 'usage_invalid'].includes(error.code)) {
    const manager = resolve(dirname(fileURLToPath(import.meta.url)), '../runtime/manage.py');
    try {
      await exec(process.env.JEV_PYTHON || 'python3', [manager, 'halt', '--provider', 'typesafe', '--codex-home', dirname(home)],
        { timeout: 30000, maxBuffer: 65536 });
      checkpoint = ' Recovery checkpoint requested.';
    } catch { checkpoint = ' Automatic checkpoint failed; halt remains set. Inspect local recovery status.'; }
  }
  return { code: error instanceof SafeError ? error.code : 'evidence_failed',
    ...(Number.isInteger(error.jevRequests) && error.jevRequests >= 0 && error.jevRequests <= 1 ? { metrics: { jevRequests: error.jevRequests } } : {}),
    message: (error instanceof SafeError ? error.message : 'Evidence operation failed; no unsafe source or error payload returned.') + checkpoint };
}

import { join } from 'node:path';
import { authorizedRoot, configuration, hash, readPrivateJson, SafeError } from './hardened-policy.mjs';

const validTask = task => typeof task === 'string' && task.length > 0 && task.length <= 200 && !/[\x00-\x1f\x7f]/.test(task);

export async function cliTask(home, root, boundRoot, task, nativeTask) {
  if (!validTask(task) || (nativeTask !== undefined && nativeTask !== task))
    throw new SafeError('task_denied', 'CLI task must match the current registered native task.');
  const canonicalRoot = await authorizedRoot(root, home, boundRoot);
  const registry = await readPrivateJson(join(home, 'authorized-workspaces.json'), {});
  const entry = registry.version === 1 && registry.sessions?.[task];
  const updated = Date.parse(entry?.updated_at);
  if (!entry || !Number.isFinite(updated) || updated > Date.now() + 300000 || updated < Date.now() - 30 * 86400000)
    throw new SafeError('task_denied', 'Register this task through a trusted workspace hook before CLI follow-up reads.');
  const config = await configuration(home);
  if (entry.root !== canonicalRoot && !config.allowed_roots.includes(canonicalRoot))
    throw new SafeError('workspace_denied', 'Secondary checkout needs explicit owner workspace authorization.');
  // Stable local scope, not an authentication credential or native receipt.
  const owner = hash(JSON.stringify(['cli-task-v1', canonicalRoot, task]));
  return { owner, root: canonicalRoot, taskScope: owner, taskAttribution: 'cli_declared_not_native_verified' };
}

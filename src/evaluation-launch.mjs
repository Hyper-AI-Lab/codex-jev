import { basename, dirname, join, resolve } from 'node:path';
import { fixtureScope } from './evaluation-scope.mjs';
import { hash, readPrivateJson, SafeError } from './hardened-policy.mjs';

export async function evaluationLaunch(home, root, manifestPath, digest) {
  if (!manifestPath && !digest) return {};
  const run = dirname(resolve(manifestPath ?? '.'));
  if (!/^[a-f0-9]{64}$/.test(digest ?? '') || dirname(run) !== join(resolve(home), 'evaluations') ||
      resolve(manifestPath) !== join(run, 'comparison-manifest.json') ||
      dirname(resolve(root)) !== join(run, 'fixtures'))
    throw new SafeError('fixture_denied', 'Invalid comparison manifest location.');
  const manifest = await readPrivateJson(manifestPath);
  if (!manifest || hash(JSON.stringify(manifest)) !== digest || manifest.kind !== 'capped-hardening-comparison-v1' ||
      manifest.maxNativeRuns !== 4 || manifest.inputBoundary !== 100000 ||
      !Number.isFinite(Date.parse(manifest.expires)) || Date.parse(manifest.expires) <= Date.now() ||
      Date.parse(manifest.expires) > Date.now() + 2 * 3600000 ||
      !['environment-precedence-contract', 'inventory-pool-incident'].includes(basename(root)))
    throw new SafeError('fixture_denied', 'Comparison authority is expired, changed or invalid.');
  return { evaluationScope: await fixtureScope(home, root, manifest.baseline?.[basename(root)]),
    purpose: 'validation', measurementOrigin: 'comparison' };
}

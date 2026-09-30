import { realpath } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { SafeError, sensitivePath } from './hardened-policy.mjs';

// Process-local capabilities issued only by the frozen-fixture runner. No MCP or
// CLI input can grant a scope or authorize an arbitrary external workspace.
const scopes = new WeakMap();
export async function fixtureScope(home, root, files) {
  const base = await realpath(join(home, 'evaluations'));
  const canonical = await realpath(root);
  const parts = relative(base, canonical).split(sep);
  if (canonical !== resolve(root) || parts.length !== 3 || parts[0] === '..' || parts[1] !== 'fixtures' ||
      !files || !Object.keys(files).length || Object.keys(files).length > 5000 ||
      Object.entries(files).some(([path, digest]) => isAbsolute(path) || path.split(/[\\/]/).includes('..') || sensitivePath(path) || !/^[a-f0-9]{64}$/.test(digest))) {
    throw new SafeError('fixture_denied', 'Evaluation scope must contain frozen, eligible synthetic fixtures.');
  }
  const capability = Object.freeze({});
  scopes.set(capability, { home: resolve(home), root: canonical, files: Object.freeze({ ...files }), expires: Date.now() + 2 * 3600000 });
  return capability;
}

export async function authorizeFixture(scope, input, home, boundRoot) {
  const value = scopes.get(scope);
  if (!value || value.expires <= Date.now() || value.home !== resolve(home) ||
      await realpath(input) !== value.root || await realpath(boundRoot) !== value.root) {
    throw new SafeError('fixture_denied', 'Evaluation scope is invalid, expired or belongs to another workspace.');
  }
  return value.root;
}

export function verifyFixtureSource(scope, source) {
  const value = scopes.get(scope);
  if (!value || value.expires <= Date.now() || !Object.hasOwn(value.files, source.path) || value.files[source.path] !== source.hash) {
    throw new SafeError('fixture_changed', 'Source is not part of the immutable evaluation fixture.');
  }
}

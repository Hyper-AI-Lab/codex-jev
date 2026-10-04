import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { releaseInfo } from '../src/release-info.mjs';

const hash = data => createHash('sha256').update(data).digest('hex');
async function fixture(t) {
  const base = await mkdtemp(join(tmpdir(), 'jev-release-'));
  t.after(() => rm(base, { recursive: true, force: true }));
  const names = ['dist/server.mjs', 'runtime/manage.py', 'runtime/invocations.sql', 'src/hardened-policy.mjs', 'dist/dependency-lock.json'];
  const data = 'offline fixture', files = Object.fromEntries(names.map(name => [name, { sha256: hash(data), bytes: data.length }]));
  const raw = JSON.stringify({ schema: 1, version: 'test', files }), id = hash(raw), root = join(base, id);
  for (const name of names) { await mkdir(join(root, name, '..'), { recursive: true }); await writeFile(join(root, name), data, { mode: 0o400 }); }
  await writeFile(join(root, 'release-manifest.json'), raw, { mode: 0o400 });
  return { root, id, url: pathToFileURL(join(root, 'dist/server.mjs')) };
}

test('release status verifies pinned component hashes and rejects a different release', async t => {
  const f = await fixture(t);
  const result = await releaseInfo(f.url, f.id);
  assert.equal(result.verified, true);
  assert.equal(result.id, f.id);
  assert.equal(result.components.bundle, hash('offline fixture'));
  await assert.rejects(releaseInfo(f.url, hash('wrong')), /release_manifest_mismatch/);
});

test('tampered and writable installed components fail startup validation', async t => {
  const f = await fixture(t), path = join(f.root, 'runtime/manage.py');
  await chmod(path, 0o600);
  await assert.rejects(releaseInfo(f.url, f.id), /unsafe_release_component/);
  await writeFile(path, 'changed fixture'); await chmod(path, 0o400);
  await assert.rejects(releaseInfo(f.url, f.id), /release_hash_mismatch/);
});

test('development checkout is explicitly unsealed, not falsely deployment verified', async () => {
  assert.deepEqual(await releaseInfo(import.meta.url, undefined), { state: 'unsealed_checkout', verified: false });
});

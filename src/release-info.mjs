import { lstat, readFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const hash = data => createHash('sha256').update(data).digest('hex');
const hex = /^[a-f0-9]{64}$/;
const eligible = name => /^(?:package\.json|LICENSE|NOTICE\.md|THIRD_PARTY_NOTICES\.txt|runtime\/(?!test_)[A-Za-z0-9_-]+\.(?:py|sql)|(?:src|scripts)\/[A-Za-z0-9_-]+\.mjs|dist\/[A-Za-z0-9_.-]+\.(?:mjs|LEGAL\.txt)|dist\/dependency-lock\.json|skills\/codex-jev\/(?:SKILL\.md|references\/(?:typed-judgments\.md|typesafe-guidance\.md|LICENSES\.txt)))$/.test(name);

export async function releaseInfo(url, expected = process.env.JEV_RELEASE_ID) {
  const root = dirname(dirname(fileURLToPath(url)));
  if (!expected && !hex.test(basename(root))) return { state: 'unsealed_checkout', verified: false };
  if (expected && !hex.test(expected)) throw new Error('invalid_release_identity');
  for (let path = root; ; path = dirname(path)) {
    const info = await lstat(path);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('unsafe_release_path');
    if (path === dirname(path)) break;
  }
  const read = async (name, maxBytes) => {
    const path = join(root, name), parent = await lstat(dirname(path)), info = await lstat(path);
    for (let ancestor = dirname(path); ancestor !== root; ancestor = dirname(ancestor)) {
      const folder = await lstat(ancestor);
      if (!folder.isDirectory() || folder.isSymbolicLink()) throw new Error('unsafe_release_path');
    }
    if (!parent.isDirectory() || parent.isSymbolicLink() || !info.isFile() || info.isSymbolicLink() || info.nlink !== 1 ||
        info.size > maxBytes || (info.mode & 0o222)) throw new Error('unsafe_release_component');
    const bytes = await readFile(path), after = await lstat(path);
    if (info.ino !== after.ino || info.dev !== after.dev || info.ctimeMs !== after.ctimeMs || info.size !== bytes.length)
      throw new Error('release_changed_during_read');
    return bytes;
  };
  const raw = await read('release-manifest.json', 256 * 1024), id = hash(raw), manifest = JSON.parse(raw);
  if (id !== basename(root) || (expected && expected !== id) || manifest.schema !== 1 ||
      !manifest.files || typeof manifest.files !== 'object' || Array.isArray(manifest.files) ||
      Object.keys(manifest.files).length > 512) throw new Error('release_manifest_mismatch');
  for (const name of ['dist/server.mjs', 'runtime/manage.py', 'runtime/invocations.sql', 'src/hardened-policy.mjs', 'dist/dependency-lock.json'])
    if (!manifest.files[name]) throw new Error('release_component_missing');
  let total = 0;
  for (const [name, record] of Object.entries(manifest.files)) {
    if (!eligible(name) || !record || !hex.test(record.sha256) || !Number.isSafeInteger(record.bytes) ||
        record.bytes < 0 || record.bytes > 8 * 1024 * 1024) throw new Error('invalid_release_component');
    total += record.bytes;
    if (total > 32 * 1024 * 1024) throw new Error('release_too_large');
    const data = await read(name, record.bytes);
    if (data.length !== record.bytes || hash(data) !== record.sha256) throw new Error('release_hash_mismatch');
  }
  return { state: 'immutable_release', verified: true, id, version: manifest.version,
    components: { bundle: manifest.files['dist/server.mjs'].sha256,
      python: manifest.files['runtime/manage.py'].sha256, policy: manifest.files['src/hardened-policy.mjs'].sha256,
      schema: manifest.files['runtime/invocations.sql'].sha256, dependencies: manifest.files['dist/dependency-lock.json'].sha256,
      ...(manifest.files['skills/codex-jev/SKILL.md'] ? { skill: manifest.files['skills/codex-jev/SKILL.md'].sha256 } : {}) } };
}

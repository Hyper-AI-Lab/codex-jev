import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { EvidenceService } from '../src/hardened-service.mjs';
import { defaults, exec, hash, ignoredMany, safeReadBatch } from '../src/hardened-policy.mjs';
import { pathFilters } from '../src/discovery.mjs';

async function fixture(t) {
  const base = await mkdtemp(join(tmpdir(), 'jev-discovery-')), root = join(base, 'root'), home = join(base, 'private');
  await mkdir(root); await mkdir(home, { mode: 0o700 });
  await exec('git', ['init', '-q', root]);
  const config = { ...defaults, allowed_roots: [root] };
  const save = () => writeFile(join(home, 'config.json'), JSON.stringify(config), { mode: 0o600 });
  await save();
  const service = await new EvidenceService({ home, boundRoot: root, fetcher: async () => { throw Error('offline'); } }).init();
  t.after(async () => { service.close(); await rm(base, { recursive: true, force: true }); });
  return { base, root, home, config, save, service };
}

test('query-specific paths precede alphabetical noise and scan limits remain explicit', async t => {
  const f = await fixture(t);
  await writeFile(join(f.root, 'a-noise.txt'), 'unrelated informational text');
  await writeFile(join(f.root, 'z-dispatch_handler.js'), 'const dispatch_handler = "target";');
  const result = await f.service.search({ workspaceRoot: f.root, query: 'dispatch_handler', maxFiles: 1 });
  assert.equal(result.evidence[0].path, 'z-dispatch_handler.js');
  assert.equal(result.metrics.filesVisited, 1); assert.equal(result.metrics.scanTruncated, true);
  assert.ok(result.warnings.some(value => /incomplete/.test(value)));
});

test('metadata index is bounded, invalidates changed files/exclusions, and never substitutes cached content', async t => {
  const f = await fixture(t);
  await writeFile(join(f.root, 'dispatch.txt'), 'dispatch first');
  const input = { workspaceRoot: f.root, query: 'dispatch' };
  const first = await f.service.search(input), warm = await f.service.search(input);
  assert.equal(first.metrics.metadataCacheHits, 0); assert.equal(warm.metrics.metadataCacheHits, 1);
  await writeFile(join(f.root, 'dispatch.txt'), 'dispatch changed and longer');
  const changed = await f.service.search(input);
  assert.equal(changed.metrics.metadataCacheHits, 0);
  assert.notEqual(changed.evidence[0].hash, warm.evidence[0].hash);
  await writeFile(join(f.root, '.gitignore'), 'dispatch.txt\n');
  const ignored = await f.service.search(input);
  assert.ok(!ignored.evidence.some(item => item.path === 'dispatch.txt'));
  await assert.rejects(f.service.read({ sessionId: changed.sessionId, evidenceId: changed.evidence[0].evidenceId }), { code: 'path_denied' });
  for (let i = 0; i < 25; i++) f.service.store.saveDiscoveryIndex(hash(String(i)), hash('policy'), []);
  assert.equal(f.service.store.db.prepare('SELECT COUNT(*) n FROM discovery_metadata').get().n, 16);
  assert.equal(f.service.store.saveDiscoveryIndex(hash('oversize'), hash('policy'), [{ path: 'x'.repeat(1024 * 1024), signature: 's', score: 1 }]), false);
});

test('path filters are additive, bound relative prefixes and retain exact-read authorization', async t => {
  const f = await fixture(t);
  await mkdir(join(f.root, 'src')); await mkdir(join(f.root, 'tests'));
  await writeFile(join(f.root, 'src/a.js'), 'dispatch implementation');
  await writeFile(join(f.root, 'tests/a.js'), 'dispatch test');
  const result = await f.service.search({ workspaceRoot: f.root, query: 'dispatch', pathFilters: ['tests'] });
  assert.deepEqual(result.evidence.map(item => item.path), ['tests/a.js']);
  for (const filter of ['../src', '/src', 'src/../tests', '.env', '*', 'src\0x']) assert.throws(() => pathFilters([filter]), { code: 'invalid_input' });
  f.config.additional_exclusions = ['tests']; await f.save();
  await assert.rejects(f.service.read({ sessionId: result.sessionId, evidenceId: result.evidence[0].evidenceId }), { code: 'path_denied' });
});

test('batched exclusions honor tracked ignores, nested rules, odd filenames and symlinks', async t => {
  const f = await fixture(t);
  await mkdir(join(f.root, 'nested'));
  await writeFile(join(f.root, 'tracked.txt'), 'private');
  await exec('git', ['-C', f.root, 'add', 'tracked.txt']);
  await writeFile(join(f.root, '.gitignore'), 'tracked.txt\n');
  await writeFile(join(f.root, 'nested/.gitignore'), '*.data\n');
  await writeFile(join(f.root, 'nested/hidden.data'), 'private');
  await writeFile(join(f.root, 'odd\nfile.txt'), 'eligible');
  await writeFile(join(f.base, 'outside.txt'), 'OUTSIDE');
  await symlink(join(f.base, 'outside.txt'), join(f.root, 'redirect.txt'));
  const paths = ['tracked.txt', 'nested/hidden.data', 'odd\nfile.txt', 'redirect.txt'];
  assert.deepEqual([...await ignoredMany(f.root, paths)].sort(), ['nested/hidden.data', 'tracked.txt']);
  const rows = await safeReadBatch(f.root, paths);
  assert.deepEqual(rows.filter(row => row.source).map(row => row.source.text), ['eligible']);
  assert.ok(!JSON.stringify(rows).includes('OUTSIDE'));
});

test('batch reads recheck exclusions after reading and never return a newly ignored source', async t => {
  const f = await fixture(t), bin = join(f.base, 'bin');
  await writeFile(join(f.root, 'source.txt'), 'PRIVATE_AFTER_RULE_CHANGE');
  await mkdir(bin);
  const realGit = (await exec('which', ['git'])).stdout.trim();
  const count = join(f.base, 'count');
  await writeFile(join(bin, 'git'), `#!/bin/sh\nif test -f '${count}'; then printf 'source.txt\\n' > '${f.root}/.gitignore'; else touch '${count}'; fi\nexec '${realGit}' "$@"\n`, { mode: 0o700 });
  const before = process.env.PATH;
  try {
    process.env.PATH = `${bin}:${before}`;
    const result = await safeReadBatch(f.root, ['source.txt']);
    assert.equal(result[0].error, 'path_denied'); assert.equal(result[0].source, undefined);
  } finally { process.env.PATH = before; }
});

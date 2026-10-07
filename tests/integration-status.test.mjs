import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { hash } from '../src/hardened-policy.mjs';
import { skillStatus, historyStatus } from '../src/integration-status.mjs';

test('skill metadata distinguishes installed and loaded without inferring client use', async t => {
  const base = await mkdtemp(join(tmpdir(), 'jev-skill-')), home = join(base, 'jev-context');
  await mkdir(home, { mode: 0o700 }); t.after(() => rm(base, { recursive: true, force: true }));
  assert.equal((await skillStatus(home, {})).state, 'not_installed');
  const skill = {};
  for (const name of ['SKILL.md', 'references/typed-judgments.md', 'references/typesafe-guidance.md', 'references/LICENSES.txt']) {
    const path = join(base, 'skills/codex-jev', name);
    await mkdir(join(path, '..'), { recursive: true, mode: 0o700 });
    await writeFile(path, name, { mode: 0o600 }); skill[name] = hash(name);
  }
  await writeFile(join(home, 'installation.json'), JSON.stringify({ skill, release_id: 'test-release' }), { mode: 0o600 });
  const release = { id: 'test-release', components: { skill: hash('SKILL.md') } };
  const ready = await skillStatus(home, release);
  assert.equal(ready.state, 'installed_verified'); assert.equal(ready.matchesLoadedRelease, true);
  assert.equal(ready.clientLoaded, 'not_observable_by_mcp');
  assert.equal((await skillStatus(home, { ...release, id: 'other' })).matchesLoadedRelease, false);
  await writeFile(join(base, 'skills/codex-jev/references/typed-judgments.md'), 'owner edit');
  assert.equal((await skillStatus(home, release)).state, 'mismatch');
});

test('history compatibility publishes allowlisted metadata only with explicit incomplete coverage', async t => {
  const home = await mkdtemp(join(tmpdir(), 'jev-history-status-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  await writeFile(join(home, 'usage-history-status.json'), JSON.stringify({ state: 'incomplete',
    skipped_records: 3, skipped_bytes: 8192, recorded: 0, discarding_oversized: false,
    at: '2026-10-05T00:00:00+00:00', raw: 'PRIVATE_MARKER', invalid_records: 'PRIVATE_MARKER' }), { mode: 0o600 });
  const status = await historyStatus(home);
  assert.equal(status.skipped_records, 3); assert.equal(status.wholeTaskCoverageVerified, false);
  assert.equal(status.checkedAt, '2026-10-05T00:00:00+00:00');
  assert.doesNotMatch(JSON.stringify(status), /PRIVATE_MARKER/);
  await writeFile(join(home, 'usage-history-status.json'), 'invalid');
  assert.equal((await historyStatus(home)).state, 'unavailable');
});

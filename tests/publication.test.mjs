import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { redact, exec } from '../src/hardened-policy.mjs';

test('generic opaque token assignments are redacted before selection', () => {
  for (const input of ['token = "synthetic-opaque-value"', 'token=synthetic-opaque-value',
    "'token': 'synthetic-opaque-value'", 'bearer_token = "synthetic-opaque-value"']) {
    assert.doesNotMatch(redact(input), /synthetic-opaque-value/);
    assert.match(redact(input), /REDACTED/);
  }
});

test('public tree scan excludes development caches but rejects private artifacts without printing values', async t => {
  const root = await mkdtemp(join(tmpdir(), 'jev-publication-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, '.ruff_cache'));
  await writeFile(join(root, '.ruff_cache/cache'), '/home/' + 'projects/synthetic/cache');
  const script = new URL('../scripts/check-publication.mjs', import.meta.url).pathname;
  const clean = await exec(process.execPath, [script], { cwd: root });
  assert.match(clean.stdout, /checks passed/);
  await writeFile(join(root, '.env'), 'SYNTHETIC_PRIVATE_VALUE');
  await assert.rejects(exec(process.execPath, [script], { cwd: root }), error => {
    assert.match(error.stderr, /private-artifact/);
    assert.doesNotMatch(error.stderr, /SYNTHETIC_PRIVATE_VALUE/);
    return true;
  });
});

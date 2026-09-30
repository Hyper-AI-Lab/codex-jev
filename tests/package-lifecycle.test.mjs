import test from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { exec } from '../src/hardened-policy.mjs';

test('offline package contains recovery runtime and survives isolated install, upgrade, rollback and uninstall', { timeout: 90000 }, async t => {
  const temp = await mkdtemp(join(tmpdir(), 'jev-package-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeFile(join(temp, 'user.npmrc'), '');
  await writeFile(join(temp, 'global.npmrc'), '');
  const env = { ...process.env, npm_config_userconfig: join(temp, 'user.npmrc'), npm_config_globalconfig: join(temp, 'global.npmrc'), npm_config_offline: 'true' };
  const { stdout } = await exec('npm', ['pack', '--ignore-scripts', '--offline', '--json', '--pack-destination', temp],
    { cwd: resolve('.'), env, timeout: 60000, maxBuffer: 8 * 1024 * 1024 });
  const info = JSON.parse(stdout)[0], names = new Set(info.files.map(item => item.path));
  for (const required of ['runtime/manage.py', 'runtime/common.py', 'runtime/installer.py', 'runtime/recovery.py',
    'runtime/measurements.py', 'runtime/telemetry.py', 'runtime/observer.py', 'dist/server.mjs', 'dist/live-smoke.mjs',
    'src/private-read.mjs', 'src/process-identity.mjs', 'src/retrieval-archive.mjs', 'scripts/reservations.mjs', 'eslint.config.mjs', 'LICENSE',
    'benchmarks/fixtures/tenant-cache/src/cache.mjs', 'benchmarks/evaluation-v2.manifest.json', 'NOTICE.md', 'THIRD_PARTY_NOTICES.txt']) assert.ok(names.has(required), required);
  assert.ok([...names].every(path => !path.includes('__pycache__') && !path.includes('.pyc') && !path.includes('.toolchain')));
  await exec('tar', ['-xzf', join(temp, info.filename), '-C', temp]);
  const previous = join(temp, 'package'), upgraded = join(temp, 'upgrade');
  await mkdir(upgraded);
  for (const path of ['runtime', 'dist', 'src', 'scripts', 'package.json']) await cp(join(previous, path), join(upgraded, path), { recursive: true });
  const root = join(temp, 'workspace'), codex = join(temp, 'codex');
  await mkdir(root); await mkdir(codex, { mode: 0o700 });
  await exec('git', ['init', '-q', root]);
  const original = 'model="owner-model"\nmodel_reasoning_effort="high"\n';
  await writeFile(join(codex, 'config.toml'), original, { mode: 0o600 });
  await writeFile(join(codex, 'auth.json'), '{"test_only":"DO_NOT_TOUCH"}', { mode: 0o600 });
  const run = async (checkout, action) => {
    const args = [join(checkout, 'runtime/manage.py'), action, '--codex-home', codex];
    if (action === 'install') args.push('--workspace', root, '--node', process.execPath, '--entrypoint', 'dist');
    return JSON.parse((await exec(process.env.JEV_PYTHON || 'python3', args, { env, timeout: 20000, maxBuffer: 65536 })).stdout);
  };
  assert.equal((await run(previous, 'install')).installed, true);
  const home = join(codex, 'jev-context');
  await writeFile(join(home, 'halt.json'), '{"reason":"fixture_halt"}', { mode: 0o600 });
  await writeFile(join(home, 'accounting-marker.json'), '{"spent":17}', { mode: 0o600 });
  assert.equal((await run(upgraded, 'install')).installed, true);
  assert.ok((await readFile(join(codex, 'config.toml'), 'utf8')).includes(upgraded));
  assert.equal((await run(previous, 'install')).installed, true);
  assert.ok((await readFile(join(codex, 'config.toml'), 'utf8')).includes(previous));
  assert.equal((await run(previous, 'uninstall')).uninstalled, true);
  assert.equal(await readFile(join(codex, 'config.toml'), 'utf8'), original);
  assert.equal(await readFile(join(codex, 'auth.json'), 'utf8'), '{"test_only":"DO_NOT_TOUCH"}');
  assert.equal(await readFile(join(home, 'halt.json'), 'utf8'), '{"reason":"fixture_halt"}');
  assert.equal(await readFile(join(home, 'accounting-marker.json'), 'utf8'), '{"spent":17}');
  const cli = await exec(process.execPath, [join(previous, 'scripts/investigate.mjs'), '--help'], { cwd: root });
  assert.match(cli.stdout, /same protected key/);
  await assert.rejects(exec(process.execPath, [join(previous, 'dist/live-smoke.mjs')], { cwd: root }), error => {
    assert.match(error.stderr, /invalid_arguments/); assert.doesNotMatch(error.stderr, /ERR_MODULE_NOT_FOUND/); return true;
  });
});

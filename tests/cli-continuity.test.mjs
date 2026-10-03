import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { runCli } from '../scripts/investigate.mjs';
import { defaults, exec } from '../src/hardened-policy.mjs';

async function fixture(t) {
  const base = await mkdtemp(join(tmpdir(), 'jev-cli-task-'));
  const home = join(base, 'private'), root = join(base, 'repo'), secondary = join(base, 'secondary');
  for (const p of [home, root, secondary]) await mkdir(p, { mode: 0o700 });
  for (const p of [root, secondary]) await exec('git', ['init', '-q', p]);
  const config = { ...defaults, allowed_roots: [root, secondary] };
  const registry = { version: 1, sessions: Object.fromEntries(['task-one', 'task-two'].map(id =>
    [id, { root, updated_at: new Date().toISOString() }])), roots: [root] };
  await writeFile(join(home, 'config.json'), JSON.stringify(config), { mode: 0o600 });
  await writeFile(join(home, 'authorized-workspaces.json'), JSON.stringify(registry), { mode: 0o600 });
  for (const p of [root, secondary]) await writeFile(join(p, 'source.txt'), 'dispatch context\n'.repeat(20));
  t.after(() => rm(base, { recursive: true, force: true }));
  const args = (operation, extra = [], task = 'task-one') => [operation, '--root', root, '--task', task, ...extra];
  const options = { home, boundRoot: root, nativeTask: 'task-one', fetcher: () => { throw Error('no network'); } };
  return { home, root, secondary, registry, config, args, options };
}

test('task-scoped CLI search list and exact read survive separate service instances', async t => {
  const f = await fixture(t);
  const result = await runCli(f.args('search', ['--query', 'dispatch', '--local']), f.options);
  const listed = await runCli(f.args('list', ['--session', result.sessionId]), f.options);
  const read = await runCli(f.args('read', ['--session', result.sessionId, '--evidence', listed.evidence[0].evidenceId,
    '--start-line', '1', '--end-line', '2']), f.options);
  assert.match(read.content, /1: dispatch context/);
  assert.equal(read.lines.end, 2);
  assert.equal(result.taskAttribution, 'cli_declared_not_native_verified');
  assert.equal(read.taskScope, result.taskScope);
});

test('cross-task, unregistered, foreign root, expired registration and missing task are refused', async t => {
  const f = await fixture(t);
  const result = await runCli(f.args('search', ['--query', 'dispatch', '--local']), f.options);
  const extra = ['--session', result.sessionId];
  await assert.rejects(runCli(f.args('list', extra, 'task-two'), f.options), { code: 'task_denied' });
  await assert.rejects(runCli(f.args('list', extra, 'task-two'), { ...f.options, nativeTask: 'task-two' }), { code: 'session_expired' });
  await assert.rejects(runCli(f.args('list', extra, 'unregistered'), { ...f.options, nativeTask: undefined }), { code: 'task_denied' });
  await assert.rejects(runCli(['list', '--root', f.root, ...extra], f.options), { code: 'invalid_arguments' });
  await assert.rejects(runCli(['search', '--root', f.secondary, '--task', 'task-one', '--query', 'dispatch'], f.options), { code: 'workspace_denied' });
  f.registry.sessions['task-one'].updated_at = '2000-01-01T00:00:00Z';
  await writeFile(join(f.home, 'authorized-workspaces.json'), JSON.stringify(f.registry), { mode: 0o600 });
  await assert.rejects(runCli(f.args('list', extra), f.options), { code: 'task_denied' });
});

test('secondary workspace requires explicit authorization and cannot reuse primary references', async t => {
  const f = await fixture(t);
  const primary = await runCli(f.args('search', ['--query', 'dispatch', '--local']), f.options);
  const args = op => [op, '--root', f.secondary, '--task', 'task-one'];
  const options = { ...f.options, boundRoot: f.secondary };
  const secondary = await runCli([...args('search'), '--query', 'dispatch', '--local'], options);
  assert.notEqual(primary.taskScope, secondary.taskScope);
  await assert.rejects(runCli([...args('list'), '--session', primary.sessionId], options), { code: 'session_expired' });
  f.config.allowed_roots = [f.root];
  await writeFile(join(f.home, 'config.json'), JSON.stringify(f.config), { mode: 0o600 });
  await assert.rejects(runCli([...args('list'), '--session', secondary.sessionId], options), { code: 'workspace_denied' });
});

test('follow-up commands recheck hashes ignores symlinks privacy and halt without network', async t => {
  const f = await fixture(t);
  const search = () => runCli(f.args('search', ['--query', 'dispatch', '--local']), f.options);
  const follow = result => runCli(f.args('read', ['--session', result.sessionId, '--evidence', result.evidence[0].evidenceId]), f.options);
  let result = await search();
  await writeFile(join(f.root, 'source.txt'), 'changed dispatch\n');
  await assert.rejects(follow(result), { code: 'source_changed' });
  result = await search();
  await writeFile(join(f.root, '.gitignore'), 'source.txt\n');
  await assert.rejects(follow(result), { code: 'path_denied' });
  await rm(join(f.root, '.gitignore'));
  await rm(join(f.root, 'source.txt'));
  await symlink(join(f.secondary, 'source.txt'), join(f.root, 'source.txt'));
  await assert.rejects(follow(result), { code: 'path_denied' });
  await writeFile(join(f.home, 'halt.json'), '{}', { mode: 0o600 });
  await assert.rejects(follow(result), { code: 'halted' });
});

test('two real CLI processes share only their registered task evidence references', async t => {
  const f = await fixture(t), entry = resolve('scripts/investigate.mjs');
  const invoke = async args => JSON.parse((await exec(process.execPath, [entry, ...args], {
    cwd: f.root, env: { ...process.env, CODEX_THREAD_ID: 'task-one', JEV_CONTEXT_HOME: f.home }, timeout: 15000 })).stdout);
  const result = await invoke(f.args('search', ['--query', 'dispatch', '--local']));
  const listed = await invoke(f.args('list', ['--session', result.sessionId]));
  assert.equal(listed.evidence[0].hash, result.evidence[0].hash);
  assert.deepEqual(JSON.parse(await readFile(join(f.home, 'config.json'), 'utf8')), f.config);
});

test('changed privacy and closed task revoke follow-up access without deleting history', async t => {
  const f = await fixture(t);
  const result = await runCli(f.args('search', ['--query', 'dispatch', '--local']), f.options);
  const args = f.args('list', ['--session', result.sessionId]);
  f.config.additional_exclusions = ['source.txt'];
  await writeFile(join(f.home, 'config.json'), JSON.stringify(f.config), { mode: 0o600 });
  await assert.rejects(runCli(args, f.options), { code: 'path_denied' });
  f.config.additional_exclusions = [];
  await writeFile(join(f.home, 'config.json'), JSON.stringify(f.config), { mode: 0o600 });
  delete f.registry.sessions['task-one'];
  await writeFile(join(f.home, 'authorized-workspaces.json'), JSON.stringify(f.registry), { mode: 0o600 });
  await assert.rejects(runCli(args, f.options), { code: 'task_denied' });
});

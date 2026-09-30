import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { runCli } from '../scripts/investigate.mjs';
import { defaults, exec, hash } from '../src/hardened-policy.mjs';
import { EvidenceService } from '../src/hardened-service.mjs';
import { fixtureScope } from '../src/evaluation-scope.mjs';
import { Store } from '../src/hardened-store.mjs';

async function fixture(t) {
  const base = await mkdtemp(join(tmpdir(), 'jev-entry-'));
  const home = join(base, 'private'), root = join(base, 'workspace');
  await mkdir(root); await mkdir(home, { mode: 0o700 });
  await exec('git', ['init', '-q', root]);
  const config = { ...defaults, enabled: true, live_validated: true, allowed_roots: [root],
    validation_budget_usd: 1, monthly_budget_usd: 1, total_budget_usd: 1 };
  await writeFile(join(home, 'config.json'), JSON.stringify(config), { mode: 0o600 });
  const text = Array.from({ length: 96 }, (_, i) => `line ${i} dispatch handler lifecycle verification ${'bounded context '.repeat(8)}`).join('\n');
  await writeFile(join(root, 'source.txt'), text);
  t.after(() => rm(base, { recursive: true, force: true }));
  return { base, home, root, config, text };
}

test('CLI uses shared authorization, redaction, ledger and cache without environment keys', async t => {
  const f = await fixture(t);
  let calls = 0;
  const fetcher = async (_url, options) => {
    calls++;
    assert.equal(options.headers.authorization, 'Bearer synthetic-protected-key');
    assert.doesNotMatch(options.body, /secret-CLI-query|synthetic-protected-key/);
    const body = JSON.parse(options.body);
    return new Response(JSON.stringify({ model: body.model,
      answers: Object.fromEntries(Object.keys(body.questions).map(key => [key, { type: 'noul', noul: .9 }])),
      usage: { input_tokens: 100, output_tokens: 1 } }));
  };
  const args = ['--root', f.root, '--query', 'dispatch handler API_KEY="secret-CLI-query"', '--jev', '--allow-network'];
  const noKey = await runCli(args, { home: f.home, boundRoot: f.root, fetcher });
  assert.equal(noKey.selectionReason, 'key_missing'); assert.equal(calls, 0);
  await mkdir(join(f.home, 'secrets'), { mode: 0o700, recursive: true });
  await writeFile(join(f.home, 'secrets/typesafe_api_key'), 'synthetic-protected-key', { mode: 0o600 });
  const first = await runCli(args, { home: f.home, boundRoot: f.root, fetcher });
  const second = await runCli(args, { home: f.home, boundRoot: f.root, fetcher });
  assert.equal(first.mode, 'jev'); assert.equal(second.mode, 'cache'); assert.equal(calls, 1);
  const store = new Store(f.home);
  try { assert.equal(store.status()[0].requests, 1); } finally { store.close(); }
});

test('CLI blocks foreign roots, unsafe flags and halts before network; errors never reflect arguments', async t => {
  const f = await fixture(t);
  const options = { home: f.home, boundRoot: f.root, fetcher: async () => { throw Error('NETWORK_FORBIDDEN'); } };
  for (const option of ['--model', '--diagnostics', '--unsafe-PRIVATE_MARKER']) {
    await assert.rejects(runCli([option, 'PRIVATE_MARKER'], options), error => error.code === 'invalid_arguments' && !error.message.includes('PRIVATE_MARKER'));
  }
  await assert.rejects(runCli(['--root', f.base, '--query', 'dispatch'], options), { code: 'workspace_denied' });
  await writeFile(join(f.home, 'halt.json'), '{}', { mode: 0o600 });
  await assert.rejects(runCli(['--root', f.root, '--query', 'dispatch', '--local'], options), { code: 'halted' });
});

test('isolated fixture authorization cannot grant ordinary or mutable-source access', async t => {
  const f = await fixture(t), root = join(f.home, 'evaluations/run/fixtures/task');
  await mkdir(root, { recursive: true });
  await writeFile(join(root, 'fixture.txt'), f.text);
  const before = await readFile(join(f.home, 'config.json'), 'utf8');
  const evaluationScope = await fixtureScope(f.home, root, { 'fixture.txt': hash(f.text) });
  assert.throws(() => new EvidenceService({ evaluationScope }), { code: 'fixture_denied' });
  const service = await new EvidenceService({ home: f.home, boundRoot: root, evaluationScope,
    purpose: 'validation', measurementOrigin: 'synthetic', forceLocal: true }).init();
  try {
    const result = await service.large({ workspaceRoot: root, path: 'fixture.txt', query: 'dispatch' });
    assert.ok(result.evidence.length);
    await writeFile(join(root, 'fixture.txt'), 'changed');
    await assert.rejects(service.read({ sessionId: result.sessionId, evidenceId: result.evidence[0].evidenceId }), { code: 'fixture_changed' });
    await assert.rejects(service.large({ workspaceRoot: root, path: 'fixture.txt', query: 'dispatch' }), { code: 'fixture_changed' });
    await assert.rejects(service.search({ workspaceRoot: f.root, query: 'dispatch' }), { code: 'fixture_denied' });
  } finally { service.close(); }
  await assert.rejects(fixtureScope(f.home, f.root, { 'source.txt': hash(f.text) }), { code: 'fixture_denied' });
  assert.equal(await readFile(join(f.home, 'config.json'), 'utf8'), before);
});

test('historical executable campaigns stop before reading credentials or launching inference', async () => {
  for (const path of ['benchmarks/paired-pilot.mjs', 'benchmarks/evaluation-v2.mjs', 'benchmarks/gateway-pilot.mjs',
    ...[1, 2, 3, 4].map(version => `benchmarks/confirmation-v${version}.mjs`),
    'benchmarks/controlled-workflow.mjs', 'benchmarks/installed-workflow-pilot.mjs',
    'scripts/native-packet-pilot.mjs', 'scripts/actual-mcp-pilot.mjs']) {
    await assert.rejects(exec(process.execPath, [resolve(path)], { timeout: 10000, env: { PATH: process.env.PATH } }), error => {
      assert.match(error.stderr, /[Hh]istorical.*disabled/); return error.code === 1;
    });
  }
});

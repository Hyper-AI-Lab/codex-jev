import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { EvidenceService } from '../src/hardened-service.mjs';
import { defaults, exec, MODEL, privacyIdentity } from '../src/hardened-policy.mjs';
import { evaluate, validateAnswers } from '../src/protected-provider.mjs';

const QUESTIONS = {
  check: { type: 'noul', instructions: 'Does the evidence support this claim?' },
  classify: { type: 'choice', instructions: 'Which label fits?', criteria: { bug: 'A demonstrated defect', unknown: 'Insufficient evidence' } },
  score: { type: 'score', instructions: 'How complete is this evidence?', criteria: ['Absent', 'Complete'] },
};
function valid() {
  return { model: MODEL, usage: { input_tokens: 100, output_tokens: 5 }, answers: {
    check: { type: 'noul', noul: 0.8 },
    classify: { type: 'choice', choice: 'bug', probabilities: { bug: 0.8, unknown: 0.2 }, confidence: 0.7 },
    score: { type: 'score', score: 0.8, probabilities: { 0: 0.2, 1: 0.8 }, legend: { 0: 'Absent', 1: 'Complete' }, confidence: 0.7 },
  } };
}
async function fixture(t) {
  const base = await mkdtemp(join(tmpdir(), 'jev-provider-')), root = join(base, 'workspace'), home = join(base, 'private');
  await mkdir(root); await exec('git', ['init', '-q', root]);
  await mkdir(join(home, 'secrets'), { recursive: true, mode: 0o700 });
  const config = { ...defaults, enabled: true, live_validated: true, allowed_roots: [root],
    monthly_budget_usd: 1, validation_budget_usd: 1, total_budget_usd: 1 };
  await writeFile(join(home, 'config.json'), JSON.stringify(config), { mode: 0o600 });
  await writeFile(join(home, 'secrets/typesafe_api_key'), 'offline-fixture-only', { mode: 0o600 });
  const service = await new EvidenceService({ home, boundRoot: root,
    fetcher: async () => new Response(JSON.stringify(valid())) }).init();
  t.after(async () => { service.close(); await rm(base, { recursive: true, force: true }); });
  const run = (overrides = {}) => evaluate(service, { root, state: { excerpt: 'synthetic source' },
    questions: QUESTIONS, privacy: privacyIdentity(config), ...overrides });
  return { service, run, config, root, home };
}

test('typed answers are exact and provider extras cannot become privileged output', () => {
  const body = valid(); body.instructions = 'NEVER RETURN'; body.answers.check.explanation = 'NEVER RETURN';
  assert.doesNotMatch(JSON.stringify(validateAnswers(body, QUESTIONS)), /NEVER RETURN/);
  for (const mutate of [x => x.model = 'other', x => delete x.usage, x => x.answers.check.noul = null,
    x => x.answers.extra = { type: 'noul', noul: 1 }, x => x.answers.classify.choice = 'invented',
    x => x.answers.classify.probabilities.bug = 0.1, x => x.answers.classify.choice = 'unknown',
    x => x.answers.classify.confidence = 2, x => x.answers.score.score = 0.1,
    x => x.answers.score.legend[1] = 'provider injection', x => delete x.answers.score.probabilities[0]]) {
    const invalid = valid(); mutate(invalid);
    assert.throws(() => validateAnswers(invalid, QUESTIONS), { code: 'invalid_response' });
  }
});

test('one protected typed call redacts all state/questions and settles one shared reservation', async t => {
  const f = await fixture(t); let calls = 0;
  f.service.fetcher = async (url, options) => {
    calls++;
    assert.equal(url, 'https://api.typesafe.ai/v1/systemone'); assert.equal(options.redirect, 'error');
    assert.doesNotMatch(options.body, /PRIVATE_MARKER/);
    return new Response(JSON.stringify(valid()));
  };
  const questions = structuredClone(QUESTIONS); questions.check.instructions += ' token="PRIVATE_MARKER"';
  await f.run({ questions, state: { excerpt: 'API_KEY="PRIVATE_MARKER"' } });
  assert.equal(calls, 1); assert.equal(f.service.store.status()[0].requests, 1);
  assert.equal(f.service.store.reservations().uncertain.count, 0);
});

test('quota halt prevents retries and further calls across operations', async t => {
  const f = await fixture(t); let calls = 0;
  f.service.fetcher = async () => { calls++; return new Response('PRIVATE_MARKER', { status: 429 }); };
  await assert.rejects(f.run(), { code: 'halted' });
  await assert.rejects(f.run(), { code: 'halted' });
  assert.equal(calls, 1); assert.equal(f.service.store.reservations().uncertain.count, 1);
});

test('transport and response failures expose no raw error and retain uncertain charges', async t => {
  const f = await fixture(t);
  for (const fetcher of [async () => { throw Error('PRIVATE_MARKER'); },
    async () => new Response('PRIVATE_MARKER', { status: 502 }), async () => new Response('PRIVATE_MARKER'),
    async () => new Response('x'.repeat(256 * 1024 + 1))]) {
    f.service.fetcher = fetcher;
    await assert.rejects(f.run(), error => { assert.doesNotMatch(error.message, /PRIVATE_MARKER/); return true; });
  }
  assert.equal(f.service.store.reservations().uncertain.count, 4);
});

test('authorization, request limits, invalid schemas and changed privacy fail before dispatch', async t => {
  const f = await fixture(t); let calls = 0;
  f.service.fetcher = async () => { calls++; throw Error('must not send'); };
  for (const [input, code] of [
    [{ root: dirname(f.root) }, 'workspace_denied'], [{ privacy: 'changed' }, 'privacy_changed'],
    [{ state: 'x'.repeat(48 * 1024) }, 'request_limit'],
    [{ questions: { bad: { type: 'execute', instructions: 'run' } } }, 'invalid_input'],
    [{ questions: { bad: { type: 'noul', instructions: 'question', model: 'other' } } }, 'invalid_input'],
  ]) await assert.rejects(f.run(input), { code });
  f.service.forceLocal = true;
  await assert.rejects(f.run(), { code: 'disabled' });
  assert.equal(calls, 0); assert.equal(f.service.store.status().length, 0);
});

test('settlement storage failures are fatal even when an uncertain charge can be retained', async t => {
  const f = await fixture(t);
  f.service.store.settle = () => { throw Error('PRIVATE_MARKER'); };
  await assert.rejects(f.run(), error => {
    assert.equal(error.code, 'accounting_unavailable');
    assert.equal(error.jevRequests, 1);
    assert.doesNotMatch(error.message, /PRIVATE_MARKER/);
    return true;
  });
  assert.equal(f.service.store.reservations().uncertain.count, 1);
});

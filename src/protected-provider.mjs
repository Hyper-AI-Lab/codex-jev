import { lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { privateRead } from './private-read.mjs';
import { MODEL, SafeError, configuration, privateDirectory, privacyIdentity, redact, selectionMode } from './hardened-policy.mjs';

export const REQUEST_BYTES = 48 * 1024;
const probability = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1;
const validId = value => /^[A-Za-z][A-Za-z0-9_]{0,79}$/.test(value);
const criterion = value => typeof value === 'string' && value.length > 0 && value.length <= 2000;
const object = value => value && Object.getPrototypeOf(value) === Object.prototype;

function validQuestions(questions) {
  if (!object(questions) || !Object.keys(questions).length || Object.keys(questions).length > 140) return false;
  return Object.entries(questions).every(([key, q]) => {
    if (!validId(key) || !object(q) || !criterion(q.instructions) ||
        Object.keys(q).some(k => !['type', 'instructions', 'criteria'].includes(k))) return false;
    if (q.type === 'noul') return q.criteria === undefined ||
      (sameKeys(q.criteria, ['true', 'false']) && Object.values(q.criteria).every(criterion));
    if (q.type === 'choice') return object(q.criteria) && Object.keys(q.criteria).length >= 2 &&
      Object.keys(q.criteria).length <= 20 && Object.keys(q.criteria).every(validId) && Object.values(q.criteria).every(criterion);
    return q.type === 'score' && Array.isArray(q.criteria) && q.criteria.length >= 2 &&
      q.criteria.length <= 10 && q.criteria.every(criterion);
  });
}

export async function protectedKey(home) {
  await privateDirectory(join(home, 'secrets'));
  let text;
  try { text = await privateRead(join(home, 'secrets', 'typesafe_api_key'), { maxBytes: 4096 }); }
  catch { throw new SafeError('unsafe_key', 'Jev key must be a stable owner-only regular file with one link.'); }
  const key = text?.trim();
  if (!key) return null;
  if (/\s|["']/.test(key) || /^(?:export\b|Bearer\b|[A-Z_]*API_KEY=)/i.test(key))
    throw new SafeError('invalid_key_format', 'Key file must contain only the token, without quotes, assignments or header prefixes');
  return key;
}

export function sanitizeRequest(value, config, root, depth = 0) {
  if (depth > 12) throw new SafeError('invalid_input', 'Request nesting exceeds the local bound.');
  if (typeof value === 'string') return config.redaction_literals.reduce((text, literal) => text.split(literal).join('[REDACTED]'), redact(value, root));
  if (value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return value;
  if (Array.isArray(value) && value.length <= 2000) return value.map(x => sanitizeRequest(x, config, root, depth + 1));
  if (value && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length <= 2000) {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => {
      if (sanitizeRequest(key, config, root, depth + 1) !== key)
        throw new SafeError('invalid_input', 'Sensitive identifiers must be replaced with opaque local IDs.');
      return [key, sanitizeRequest(item, config, root, depth + 1)];
    }));
  }
  throw new SafeError('invalid_input', 'Only bounded JSON request data is supported.');
}

function sameKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join('|') === [...keys].sort().join('|');
}

function distribution(value, keys) {
  return sameKeys(value, keys) && Object.values(value).every(probability) &&
    Math.abs(Object.values(value).reduce((a, b) => a + b, 0) - 1) <= 0.0001;
}

export function validateAnswers(body, questions) {
  const invalid = () => { throw new SafeError('invalid_response', 'Jev model, answers or usage did not match the validated contract'); };
  if (body?.model !== MODEL || !sameKeys(body.answers, Object.keys(questions)) ||
      !Number.isSafeInteger(body.usage?.input_tokens) || !Number.isSafeInteger(body.usage?.output_tokens) ||
      body.usage.output_tokens < 0 || body.usage.output_tokens > 65536) invalid();
  const answers = {};
  for (const [key, q] of Object.entries(questions)) {
    const a = body.answers[key];
    if (!a || a.type !== q.type) invalid();
    if (q.type === 'noul') {
      if (!probability(a.noul)) invalid();
      answers[key] = { type: 'noul', noul: a.noul };
    } else if (q.type === 'choice') {
      if (!distribution(a.probabilities, Object.keys(q.criteria)) || !probability(a.confidence) ||
          !Object.hasOwn(q.criteria, a.choice) || a.probabilities[a.choice] < Math.max(...Object.values(a.probabilities)) - 0.0001) invalid();
      answers[key] = { type: 'choice', choice: a.choice, probabilities: a.probabilities, confidence: a.confidence };
    } else {
      const keys = q.criteria.map((_, i) => String(i));
      if (!distribution(a.probabilities, keys) || !probability(a.confidence) ||
          !Number.isFinite(a.score) || a.score < 0 || a.score > keys.length - 1 ||
          !sameKeys(a.legend, keys) || keys.some(k => a.legend[k] !== q.criteria[Number(k)]) ||
          Math.abs(a.score - keys.reduce((sum, k) => sum + Number(k) * a.probabilities[k], 0)) > 0.001) invalid();
      answers[key] = { type: 'score', score: a.score, probabilities: a.probabilities, confidence: a.confidence,
        legend: Object.fromEntries(q.criteria.map((text, i) => [String(i), text])) };
    }
  }
  return { model: MODEL, answers, usage: { input_tokens: body.usage.input_tokens, output_tokens: body.usage.output_tokens } };
}

export async function evaluate(service, { root, state, questions, privacy, verifyEvidence }) {
  let reservation, sent = false, providerStatus;
  try {
    if (await lstat(join(service.home, 'halt.json')).catch(() => null)) throw new SafeError('halted', 'Quota halt active; owner-authorized resume required');
    await service.root({ workspaceRoot: root });
    const config = await configuration(service.home);
    if (service.forceLocal || !config.enabled || (service.purpose !== 'validation' && selectionMode(config, root) === 'local_only'))
      throw new SafeError('disabled', 'Live Jev is not activated for this operation.');
    if (privacy !== privacyIdentity(config)) throw new SafeError('privacy_changed', 'Privacy policy changed before dispatch; retrieve again.');
    const request = { model: MODEL, ...sanitizeRequest({ state, questions }, config, root) };
    if (!validQuestions(request.questions)) throw new SafeError('invalid_input', 'Invalid bounded typed questions.');
    const body = JSON.stringify(request);
    if (Buffer.byteLength(body) > REQUEST_BYTES) throw new SafeError('request_limit', 'Request exceeds 48 KiB; split it explicitly.');
    const key = await protectedKey(service.home);
    if (!key) throw new SafeError('key_missing', 'Jev key is not configured.');
    const current = await configuration(service.home);
    await service.root({ workspaceRoot: root });
    if (privacyIdentity(current) !== privacy) throw new SafeError('privacy_changed', 'Privacy policy changed before dispatch; retrieve again.');
    if (verifyEvidence) await verifyEvidence();
    reservation = service.store.reserve(current, service.purpose, root);
    sent = true;
    const response = await service.fetcher('https://api.typesafe.ai/v1/systemone', {
      method: 'POST', headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
      body, signal: AbortSignal.timeout(15000), redirect: 'error',
    });
    providerStatus = response.status;
    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      if (response.status === 429) { service.store.halt('http_429'); throw new SafeError('halted', 'Jev quota limit: execution halted without retry'); }
      throw new SafeError('provider_error', `Jev returned HTTP ${response.status}; no judgment was accepted`);
    }
    const reader = response.body?.getReader();
    if (!reader) throw new SafeError('invalid_response', 'Jev returned no response body');
    const chunks = []; let bytes = 0;
    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      bytes += value.length;
      if (bytes > 256 * 1024) { await reader.cancel(); throw new SafeError('invalid_response', 'Jev response exceeded limit'); }
      chunks.push(Buffer.from(value));
    }
    let parsed;
    try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch { throw new SafeError('invalid_response', 'Invalid Jev response'); }
    const result = validateAnswers(parsed, request.questions);
    try { service.store.settle(reservation, result.usage); }
    catch (error) {
      if (error instanceof SafeError) throw error;
      throw new SafeError('accounting_unavailable', 'Request accounting could not be committed; reconcile the preserved reservation before further paid use.');
    }
    return result;
  } catch (error) {
    if (reservation) {
      try { service.store.uncertain(reservation); }
      catch {
        const failure = new SafeError('accounting_unavailable', 'Request accounting is unavailable; the original reservation remains a charge barrier.');
        failure.jevRequests = Number(sent);
        throw failure;
      }
    }
    const safe = error instanceof SafeError ? error : new SafeError('provider_failure', 'Jev request failed; any uncertain charge remains reserved.');
    safe.jevRequests = Number(sent);
    if (Number.isInteger(providerStatus)) safe.providerStatus = providerStatus;
    throw safe;
  }
}

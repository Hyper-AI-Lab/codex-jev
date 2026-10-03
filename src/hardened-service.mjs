import { lstat, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { buildJevRankingRequest, rankWithJev } from './investigator.mjs';
import { Store } from './hardened-store.mjs';
import { authorizeFixture, verifyFixtureSource } from './evaluation-scope.mjs';
import { discover, excludedPath, pathFilters } from './discovery.mjs';
import { candidatesFrom, diverseShortlist, preview } from './evidence-ranges.mjs';
import { privateRead } from './private-read.mjs';
import { MODEL, POLICY, SafeError, authorizedRoot, configuration, defaultHome, hash,
  privateDirectory, privacyIdentity, redact, redactSource, safeRead, safeReadBatch, selectionMode } from './hardened-policy.mjs';

const LIMITS = Object.freeze({ candidates: 20, results: 8, fileBytes: 8 * 1024 * 1024,
  scanBytes: 64 * 1024 * 1024, files: 5000, responseBytes: 32000, requestBytes: 48 * 1024 });

function integer(value, fallback, min, max, name) {
  const number = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(number) || number < min || number > max) throw new SafeError('invalid_input', `${name} must be an integer from ${min} to ${max}`);
  return number;
}

function validate(input) {
  if (typeof input.query !== 'string' || !input.query.trim() || input.query.length > 2000) throw new SafeError('invalid_input', 'A bounded concrete query is required');
  if (!Array.isArray(input.requirements ?? []) || (input.requirements ?? []).length > 6 ||
      !(input.requirements ?? []).every(value => typeof value === 'string' && value.length > 0 && value.length <= 240)) throw new SafeError('invalid_input', 'At most six bounded requirements are allowed');
}

function packCandidates(query, requirements, sanitized) {
  const indices = [], items = [];
  for (const [index, candidate] of sanitized.entries()) {
    try {
      const request = buildJevRankingRequest(query, requirements, [...items, candidate], { preserveExcerpts: true });
      if (Buffer.byteLength(JSON.stringify({ model: MODEL, state: request.state, questions: request.questions })) > LIMITS.requestBytes) continue;
      indices.push(index); items.push(candidate);
    } catch (error) {
      if (error.code !== 'request_limit') throw error;
    }
  }
  return { indices, items };
}

function page(items, offset, limit) {
  const result = []; let bytes = 0;
  for (const item of items.slice(offset, offset + limit)) {
    const size = Buffer.byteLength(JSON.stringify(item));
    if (size > LIMITS.responseBytes && !result.length) {
      const { excerpt: _excerpt, ...reference } = item;
      if (Buffer.byteLength(JSON.stringify(reference)) > LIMITS.responseBytes) throw new SafeError('source_limit', 'Evidence metadata is oversized; narrow the search.');
      result.push({ ...reference, excerpt: '', detailLevel: 'reference', omittedText: true,
        readInstruction: 'Use exact line ranges, or columnOffset/maxCharacters for one oversized line. Columns refer to the redacted UTF-16 line, not raw bytes.' });
      break;
    }
    if (bytes + size > LIMITS.responseBytes) break;
    result.push(item); bytes += size;
  }
  return { items: result, next: offset + result.length < items.length ? offset + result.length : null };
}

async function protectedKey(home) {
  await privateDirectory(join(home, 'secrets'));
  const path = join(home, 'secrets', 'typesafe_api_key');
  let text;
  try { text = await privateRead(path, { maxBytes: 4096 }); }
  catch { throw new SafeError('unsafe_key', 'Jev key must be a stable owner-only regular file with one link.'); }
  const key = text?.trim();
  if (!key) return null;
  if (/\s|["']/.test(key) || /^(?:export\b|Bearer\b|[A-Z_]*API_KEY=)/i.test(key)) {
    throw new SafeError('invalid_key_format', 'Key file must contain only the token, without quotes, assignments or header prefixes');
  }
  return key;
}

export class EvidenceService {
  constructor({ home = defaultHome(), boundRoot = process.cwd(), fetcher = fetch, owner = randomUUID(), purpose = 'monthly', forceLocal = false, measurementOrigin = 'unattributed', evaluationScope } = {}) {
    if (!['ordinary', 'synthetic', 'comparison', 'unattributed'].includes(measurementOrigin)) throw new SafeError('invalid_metrics', 'Invalid measurement origin');
    this.measurementOrigin = measurementOrigin;
    if (evaluationScope && (purpose !== 'validation' || !['synthetic', 'comparison'].includes(measurementOrigin))) throw new SafeError('fixture_denied', 'Fixture scopes are limited to synthetic validation/comparison.');
    this.evaluationScope = evaluationScope;
    this.home = home; this.boundRoot = boundRoot; this.fetcher = fetcher; this.owner = owner; this.purpose = purpose; this.forceLocal = forceLocal;
  }
  async init() {
    this.buildHash = hash(await readFile(fileURLToPath(import.meta.url)));
    await privateDirectory(this.home); this.store = new Store(this.home); return this;
  }
  close() { this.store?.close(); }
  async root(input) {
    return this.evaluationScope ? authorizeFixture(this.evaluationScope, input.workspaceRoot, this.home, this.boundRoot) :
      authorizedRoot(input.workspaceRoot, this.home, this.boundRoot);
  }
  async source(root, path, maxBytes) {
    const source = await safeRead(root, path, maxBytes);
    if (this.evaluationScope) verifyFixtureSource(this.evaluationScope, source);
    return source;
  }

  async checkAccess() {
    if (await lstat(join(this.home, 'halt.json')).catch(() => null)) throw new SafeError('halted', 'Quota halt active; owner-authorized resume required');
    const key = await protectedKey(this.home);
    if (!key) return { passed: false, requests: 0, reason: 'key_missing' };
    try {
      // No source text or evaluation is sent. Discard all provider-controlled body data.
      const response = await this.fetcher('https://api.typesafe.ai/v1/models', {
        method: 'GET', headers: { authorization: `Bearer ${key}` },
        signal: AbortSignal.timeout(15000), redirect: 'error',
      });
      await response.body?.cancel().catch(() => {});
      if (response.status === 429) { this.store.halt('http_429'); throw new SafeError('halted', 'Jev quota limit: execution halted without retry'); }
      return { passed: response.ok, requests: 1, providerStatus: response.status };
    } catch (error) {
      if (error.code === 'halted') throw error;
      return { passed: false, requests: 1, reason: 'access_check_failed' };
    }
  }

  async select(root, query, requirements, candidates) {
    if (await lstat(join(this.home, 'halt.json')).catch(() => null)) throw new SafeError('halted', 'Quota halt active; owner-authorized resume required');
    await this.root({ workspaceRoot: root });
    const config = await configuration(this.home);
    const local = { mode: 'local-fallback', keep: candidates.map((_, index) => index), jevRequests: 0 };
    const clean = text => config.redaction_literals.reduce((value, literal) => value.split(literal).join('[REDACTED]'), redact(text, root));
    const sanitized = candidates.map((candidate, index) => ({ path: `candidate-${index + 1}`, excerpt: clean(candidate.excerpt),
      ...(candidate.kind ? { kind: candidate.kind } : {}) }));
    const cleanQuery = clean(query), cleanRequirements = requirements.map(clean);
    if (JSON.stringify(sanitized).length <= 8000 || candidates.length <= 2) return { ...local, mode: 'bypass' };
    if (this.forceLocal) return { ...local, reason: 'comparison_local' };
    if (!config.enabled || (this.purpose !== 'validation' && selectionMode(config, root) === 'local_only')) return { ...local, reason: 'disabled' };
    // Share selection metadata for identical authorized inputs, never connection-bound sessions.
    const cacheKey = hash(JSON.stringify({ root, policy: POLICY, privacy: privacyIdentity(config), scoring: 'atomic-evidence-v2', model: MODEL,
      query: cleanQuery, requirements: cleanRequirements,
      sources: candidates.map(({ path, lines, hash: digest, critical }) => ({ path, lines, digest, critical: Boolean(critical) })), sanitized }));
    const cached = config.cache_enabled ? this.store.cached(cacheKey) : null;
    if (cached) return { ...cached, mode: 'cache', jevRequests: 0 };
    // Score whole ranges that fit; keep every unscored range locally recoverable.
    // Packing includes criterion overhead, not just excerpt bytes.
    const packed = packCandidates(cleanQuery, cleanRequirements, sanitized);
    if (!packed.items.length) return { ...local, reason: 'request_limit', scoredIndices: [] };
    const key = await protectedKey(this.home);
    if (!key) return { ...local, reason: 'key_missing' };
    let reservation, providerStatus, sent = false;
    try {
      let responseBody;
      const ranked = await rankWithJev(cleanQuery, cleanRequirements, packed.items, {
        model: MODEL, preserveExcerpts: true, resultLimit: 8,
        ask: async (state, questions) => {
          const body = JSON.stringify({ model: MODEL, state, questions });
          if (Buffer.byteLength(body) > LIMITS.requestBytes) throw new SafeError('request_limit', 'Evidence packet exceeds the request limit; no partial scoring');
          const currentConfig = await configuration(this.home);
          await this.root({ workspaceRoot: root });
          if (privacyIdentity(currentConfig) !== privacyIdentity(config)) throw new SafeError('privacy_changed', 'Privacy policy changed before dispatch; search again.');
          reservation = this.store.reserve(currentConfig, this.purpose, root);
          sent = true;
          const response = await this.fetcher('https://api.typesafe.ai/v1/systemone', {
            method: 'POST', headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
            body, signal: AbortSignal.timeout(15000), redirect: 'error',
          });
          providerStatus = response.status;
          if (response.status === 429) { this.store.halt('http_429'); throw new SafeError('halted', 'Jev quota limit: execution halted without retry'); }
          if (!response.ok) {
            await response.body?.cancel().catch(() => {});
            throw new SafeError('provider_error', `Jev returned HTTP ${response.status}; local evidence retained`);
          }
          // Bound the response before parsing; never put response bodies in errors.
          const reader = response.body?.getReader();
          if (!reader) throw new SafeError('invalid_response', 'Jev returned no response body');
          const chunks = []; let bytes = 0;
          while (true) {
            const { value, done } = await reader.read(); if (done) break;
            bytes += value.length;
            if (bytes > 256 * 1024) { await reader.cancel(); throw new SafeError('invalid_response', 'Jev response exceeded limit'); }
            chunks.push(Buffer.from(value));
          }
          try { responseBody = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
          catch { throw new SafeError('invalid_response', 'Invalid Jev response'); }
          if (responseBody.model !== MODEL || !responseBody.answers || typeof responseBody.answers !== 'object' ||
              Object.keys(responseBody.answers).sort().join('|') !== Object.keys(questions).sort().join('|') ||
              !Object.values(responseBody.answers).every(answer => answer?.type === 'noul' && Number.isFinite(answer.noul) && answer.noul >= 0 && answer.noul <= 1) ||
              !Number.isSafeInteger(responseBody.usage?.input_tokens) || !Number.isSafeInteger(responseBody.usage?.output_tokens) || responseBody.usage.output_tokens < 0) {
            throw new SafeError('invalid_response', 'Jev model, answers or usage did not match the validated contract');
          }
          return responseBody;
        },
      });
      this.store.settle(reservation, responseBody.usage);
      for (const item of ranked.scored) item.index = packed.indices[item.index];
      // selected holds references to scored entries, so indices are already mapped.
      const unscored = candidates.map((_, index) => index).filter(index => !packed.indices.includes(index));
      // Uncertainty retains evidence. Removal requires a low keep probability for every criterion.
      const keep = [...unscored, ...ranked.scored.filter(item => candidates[item.index].critical || item.relevance > 0.1 || item.requirementSupport.some(score => score > 0.1)).map(item => item.index)];
      const retained = new Set(keep);
      const strength = item => Math.max(item.relevance, ...item.requirementSupport);
      const remaining = [...ranked.scored].sort((a, b) => strength(b) - strength(a) || a.index - b.index);
      const order = [...new Set([
        ...candidates.map((_, index) => index).filter(index => candidates[index].critical),
        ...ranked.selected.map(item => item.index),
        ...remaining.map(item => item.index),
        ...unscored,
      ])].filter(index => retained.has(index));
      const result = { mode: 'jev', keep, order, scoredIndices: packed.indices, requestLimited: unscored.length > 0,
        jevRequests: 1, usage: responseBody.usage, latencyMs: ranked.latencyMs };
      // A cache hit has no new provider usage or latency to bill/report.
      if (config.cache_enabled) this.store.cache(cacheKey, { keep, order, scoredIndices: packed.indices, requestLimited: unscored.length > 0 });
      return result;
    } catch (error) {
      if (reservation) this.store.uncertain(reservation);
      const cause = error.cause instanceof SafeError ? error.cause : error;
      if (cause.code === 'halted' || cause.code === 'usage_invalid') throw cause;
      return { ...local, jevRequests: Number(sent), reason: cause.code === 'request_limit' ? 'request_limit' : cause instanceof SafeError ? cause.code : 'selection_failed', jevFailed: sent,
        ...(Number.isInteger(providerStatus) ? { providerStatus } : {}) };
    }
  }

  async investigate(input, large = false) {
    const started = performance.now();
    validate(input);
    if (input.detailLevel !== undefined && !['full', 'preview'].includes(input.detailLevel)) throw new SafeError('invalid_input', 'detailLevel must be full or preview.');
    if (await lstat(join(this.home, 'halt.json')).catch(() => null)) throw new SafeError('halted', 'Quota halt active; no further investigation until owner-authorized resume');
    const root = await this.root(input), requirements = input.requirements ?? [];
    const config = await configuration(this.home);
    const limit = integer(input.resultLimit, 4, 1, 8, 'resultLimit');
    const candidateLimit = integer(input.candidateLimit, 20, 1, 20, 'candidateLimit');
    const maxFiles = integer(input.maxFiles, LIMITS.files, 1, LIMITS.files, 'maxFiles');
    const maxBytes = integer(input.maxScanBytes, LIMITS.scanBytes, 1024, LIMITS.scanBytes, 'maxScanBytes');
    if (input.recoveryOf) {
      const original = this.store.getSession(input.recoveryOf, this.owner);
      if (original.root !== root || original.query === hash(input.query)) throw new SafeError('invalid_recovery', 'Recovery needs the same workspace and a changed missing-fact query');
      this.store.useRecovery(input.recoveryOf, this.owner);
    }
    pathFilters(input.pathFilters);
    const discovery = large ? null : await discover(root, input, config, this.store);
    const paths = large ? [input.path] : discovery.files.map(file => file.path);
    if (large && (typeof input.path !== 'string' || excludedPath(input.path, config))) throw new SafeError('path_denied', 'Source is excluded by local privacy policy');
    let visited = 0, scanned = 0, skipped = discovery?.skipped ?? 0, truncated = discovery?.truncated ?? false;
    const scanStarted = Date.now();
    const all = [];
    const scores = new Map();
    for (let offset = 0; offset < paths.length; offset += 16) {
      if (visited >= maxFiles || scanned >= maxBytes || Date.now() - scanStarted > 10000) { truncated = true; break; }
      const batch = paths.slice(offset, Math.min(offset + 16, offset + maxFiles - visited));
      const perFileLimit = Math.min(large ? LIMITS.fileBytes : 1024 * 1024, Math.floor((maxBytes - scanned) / batch.length));
      for (const row of await safeReadBatch(root, batch, perFileLimit)) {
        visited++;
        if (row.error) {
          if (large) throw new SafeError(row.error, 'Source is excluded, unavailable or exceeds the read limit.');
          skipped++; continue;
        }
        const { source } = row;
        if (this.evaluationScope) verifyFixtureSource(this.evaluationScope, source);
        scanned += source.bytes;
        const candidates = candidatesFrom({ ...source, text: redactSource(source.text, root, config) }, input.query, requirements);
        scores.set(source.path, Math.max(0, ...candidates.map(item => item.localScore)));
        all.push(...candidates);
      }
      // Keep bounded local metadata and require a narrower query when saturated.
      if (all.length > 512) {
        truncated = true;
        all.sort((a, b) => b.localScore - a.localScore || a.path.localeCompare(b.path) || a.lines.start - b.lines.start);
        all.length = 512;
      }
    }
    if (visited < paths.length) truncated = true;
    all.sort((a, b) => b.localScore - a.localScore || a.path.localeCompare(b.path) || a.lines.start - b.lines.start);
    all.splice(0, all.length, ...diverseShortlist(all, candidateLimit));
    const candidates = all.slice(0, candidateLimit);
    let metadataSaved = true;
    if (discovery) {
      for (const file of discovery.files) if (scores.has(file.path)) file.score = scores.get(file.path);
      metadataSaved = this.store.saveDiscoveryIndex(discovery.workspaceHash, discovery.identity, discovery.files);
    }
    // Revalidate selected source hashes, current exclusions and workspace authority
    // after the complete scan, before any candidate text can leave this host.
    await this.root(input);
    const latestConfig = await configuration(this.home);
    if (privacyIdentity(latestConfig) !== privacyIdentity(config)) throw new SafeError('privacy_changed', 'Privacy policy changed during discovery; search again.');
    const selectedPaths = [...new Set(candidates.map(item => item.path))];
    if (selectedPaths.some(path => excludedPath(path, latestConfig))) throw new SafeError('path_denied', 'Source privacy policy changed during discovery.');
    for (let offset = 0; offset < selectedPaths.length; offset += 16) {
      for (const row of await safeReadBatch(root, selectedPaths.slice(offset, offset + 16), large ? LIMITS.fileBytes : 1024 * 1024)) {
        if (row.error) throw new SafeError(row.error, 'Selected source is no longer readable.');
        if (candidates.some(item => item.path === row.path && item.hash !== row.source.hash)) throw new SafeError('source_changed', 'Selected source changed during discovery; search again.');
      }
    }
    const selectionStarted = performance.now();
    const selection = await this.select(root, input.query, requirements, candidates);
    await this.root(input);
    if (privacyIdentity(await configuration(this.home)) !== privacyIdentity(config)) throw new SafeError('privacy_changed', 'Privacy policy changed during selection; search again.');
    const selectionMs = Math.round(performance.now() - selectionStarted);
    const kept = new Set(selection.keep);
    const records = all.slice(0, 512).map(({ excerpt, localScore, ...item }, index) => ({ ...item, evidenceId: `e${index + 1}`,
      disposition: index >= candidateLimit || (selection.scoredIndices && !selection.scoredIndices.includes(index)) ? 'unscored' : kept.has(index) ? 'retained' : 'omitted' }));
    const sessionId = this.store.session(this.owner, root, { records, query: hash(input.query), isRecovery: Boolean(input.recoveryOf),
      jevFailed: selection.jevFailed === true, measurementTrialId: config.default_authorization?.id ?? config.trial?.id ?? 'qualified',
      measurementOrigin: this.measurementOrigin, measurementRevision: this.buildHash });
    const clean = text => config.redaction_literals.reduce((value, literal) => value.split(literal).join('[REDACTED]'), redact(text, root));
    const order = selection.order ?? candidates.map((_, index) => index);
    const returned = order.filter(index => kept.has(index)).map(index => ({ ...records[index], excerpt: clean(candidates[index].excerpt) }));
    const selected = page(input.detailLevel === 'full' ? returned : returned.map(preview), 0, limit);
    const warnings = [];
    if (selected.items.some(item => item.omittedText)) warnings.push('Progressive disclosure: source text is omitted from previews/references; follow exact source ranges before drawing conclusions.');
    if (!metadataSaved) warnings.push('Metadata index size bound reached; discovery still used current source reads.');
    if (selection.reason) warnings.push(`Local evidence selection: ${selection.reason}.`);
    if (selection.requestLimited) warnings.push('Request-size packing: some whole source ranges were not scored by Jev; use list_evidence and exact reads to recover unscored evidence.');
    if (selection.providerStatus) warnings.push(`Provider returned HTTP ${selection.providerStatus}; no automatic retry was made.`);
    if (truncated || all.length > candidateLimit || skipped) warnings.push('Search is incomplete: excluded, unscored or unvisited sources may contain relevant evidence.');
    if (selected.next !== null) warnings.push('More retained evidence exists. Use list_evidence with the returned session, then exact follow-up reads.');
    if (selected.items.filter(item => item.critical).length < records.filter(item => item.critical).length) warnings.push('Critical evidence overflow: additional diagnostic/constraint/test blocks require pagination.');
    const measurement = {};
    if (config.measurement_enabled) {
      const baseline = candidates.map((item, index) => ({ ...records[index], disposition: 'retained', excerpt: clean(item.excerpt) }));
      Object.assign(measurement, { candidateEvidenceBytes: Buffer.byteLength(JSON.stringify(baseline)),
        localPageEvidenceBytes: Buffer.byteLength(JSON.stringify(page(baseline, 0, limit).items)),
        selectedEvidenceBytes: Buffer.byteLength(JSON.stringify(selected.items)),
        retrievalMs: Math.round(performance.now() - started), selectionMs, nativeTokensMeasured: false });
      try { this.store.measure({ trialId: config.default_authorization?.id ?? config.trial?.id ?? 'qualified', workspaceHash: hash(root), sessionId, mode: selection.mode,
        revision: this.buildHash, origin: this.measurementOrigin,
        metrics: { ...measurement, jevRequests: selection.jevRequests, jevInputTokens: selection.usage?.input_tokens, jevOutputTokens: selection.usage?.output_tokens } }); }
      catch { warnings.push('Local measurement storage failed; this retrieval is not included in aggregate statistics.'); }
    }
    return { mode: selection.mode, selectionReason: selection.reason ?? null, sessionId, evidence: selected.items, omittedCount: records.filter(item => item.disposition === 'omitted').length,
      unscoredCount: records.filter(item => item.disposition === 'unscored').length,
      hasMore: selected.next !== null || records.length > selected.items.length,
      metrics: { candidatesConsidered: candidates.length, evidenceReturned: selected.items.length, filesVisited: visited, skippedFiles: skipped, scanBytes: scanned,
        metadataCacheHits: discovery?.metadataHits ?? 0,
        scanTruncated: truncated || all.length > candidateLimit, jevRequests: selection.jevRequests,
        jevCandidatesScored: selection.scoredIndices?.length ?? 0, requestLimited: selection.requestLimited ?? false,
        ...measurement, ...(selection.usage ? { jevUsage: selection.usage } : {}) },
      warnings, sourcePolicy: POLICY };
  }
  search(input) { return this.investigate(input); }
  large(input) { return this.investigate(input, true); }
  async list(input) {
    if (await lstat(join(this.home, 'halt.json')).catch(() => null)) throw new SafeError('halted', 'Quota halt active; no further evidence reads.');
    const session = this.store.getSession(input.sessionId, this.owner);
    await this.root({ workspaceRoot: session.root });
    const offset = integer(input.offset, 0, 0, 512, 'offset');
    const result = page(session.records, offset, 20);
    const config = await configuration(this.home);
    for (const path of new Set(result.items.map(item => item.path))) {
      if (excludedPath(path, config)) throw new SafeError('path_denied', 'Source is now excluded by local privacy policy.');
      const source = await this.source(session.root, path);
      if (result.items.some(item => item.path === path && item.hash !== source.hash)) throw new SafeError('source_changed', 'Source hash changed; search again.');
    }
    await this.root({ workspaceRoot: session.root });
    if (privacyIdentity(await configuration(this.home)) !== privacyIdentity(config)) throw new SafeError('privacy_changed', 'Privacy policy changed during reference validation.');
    return { sessionId: input.sessionId, evidence: result.items, nextOffset: result.next, total: session.records.length };
  }
  async read(input) {
    if (await lstat(join(this.home, 'halt.json')).catch(() => null)) throw new SafeError('halted', 'Quota halt active; no further evidence reads.');
    const started = performance.now();
    const session = this.store.getSession(input.sessionId, this.owner);
    await this.root({ workspaceRoot: session.root });
    const record = session.records.find(item => input.evidenceId ? item.evidenceId === input.evidenceId : item.path === input.path);
    if (!record || (input.path && input.path !== record.path)) throw new SafeError('path_denied', 'Source is not in this evidence session');
    const config = await configuration(this.home);
    if (config.additional_exclusions.some(prefix => record.path === prefix || record.path.startsWith(`${prefix.replace(/\/$/, '')}/`))) throw new SafeError('path_denied', 'Source is now excluded by local privacy policy');
    const source = await this.source(session.root, record.path);
    if (source.hash !== record.hash) throw new SafeError('source_changed', 'Source hash changed; search again before trusting the old selection');
    await this.root({ workspaceRoot: session.root });
    if (privacyIdentity(await configuration(this.home)) !== privacyIdentity(config)) throw new SafeError('privacy_changed', 'Privacy policy changed during source read.');
    const lines = redactSource(source.text, session.root, config).split(/\r?\n/);
    const start = integer(input.startLine, input.complete ? 1 : record.lines.start, 1, lines.length, 'startLine');
    if (input.columnOffset !== undefined || input.maxCharacters !== undefined) {
      if (input.complete || (input.endLine !== undefined && input.endLine !== start)) throw new SafeError('invalid_input', 'Column reads address exactly one redacted line.');
      const line = lines[start - 1];
      const offset = integer(input.columnOffset, 0, 0, line.length, 'columnOffset');
      const length = integer(input.maxCharacters, 4000, 1, 4000, 'maxCharacters');
      const high = code => code >= 0xD800 && code <= 0xDBFF, low = code => code >= 0xDC00 && code <= 0xDFFF;
      if (low(line.charCodeAt(offset)) && high(line.charCodeAt(offset - 1))) throw new SafeError('invalid_input', 'Column offset splits a Unicode character.');
      let end = Math.min(line.length, offset + length);
      if (high(line.charCodeAt(end - 1)) && low(line.charCodeAt(end))) end--;
      if (end === offset && offset < line.length) throw new SafeError('source_limit', 'Increase maxCharacters to fit one Unicode character.');
      const content = `${start}: ${line.slice(offset, end)}`;
      const measurementWarning = this.measureRead(session, input.sessionId, content, started, config);
      return { sessionId: input.sessionId, path: record.path, hash: source.hash, lines: { start, end: start },
        content, redacted: true, redactedLineHash: hash(line),
        columns: { start: offset, end, unit: 'redacted_line_utf16' }, nextColumnOffset: end < line.length ? end : null,
        ...(measurementWarning ? { measurementWarning } : {}) };
    }
    const end = input.complete ? lines.length : Math.min(lines.length, integer(input.endLine, Math.min(lines.length, start + 119), start, Number.MAX_SAFE_INTEGER, 'endLine'));
    if ((input.complete && source.bytes > 256 * 1024) || (!input.complete && end - start >= 400)) throw new SafeError('source_limit', 'Use a smaller bounded source range');
    const content = lines.slice(start - 1, end).map((line, index) => `${start + index}: ${line}`).join('\n');
    if (Buffer.byteLength(content) > LIMITS.responseBytes) throw new SafeError('source_limit', 'Use a smaller source range to preserve the output budget');
    const measurementWarning = this.measureRead(session, input.sessionId, content, started, config);
    return { sessionId: input.sessionId, path: record.path, hash: source.hash, lines: { start, end }, content, redacted: true,
      ...(measurementWarning ? { measurementWarning } : {}) };
  }
  measureRead(session, sessionId, content, started, config) {
    if (config.measurement_enabled) {
      try { this.store.measure({ trialId: session.measurementTrialId ?? config.trial?.id ?? 'qualified', workspaceHash: hash(session.root), sessionId, mode: 'exact-read',
        revision: session.measurementRevision ?? this.buildHash, origin: session.measurementOrigin ?? 'unattributed',
        metrics: { followupReads: 1, followupReadBytes: Buffer.byteLength(content), retrievalMs: Math.round(performance.now() - started) } }); }
      catch { return 'Local measurement storage failed; read excluded from aggregate statistics.'; }
    }
  }
}

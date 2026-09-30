import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { candidatesFrom, evidenceKind } from '../src/evidence-ranges.mjs';
import { EvidenceService } from '../src/hardened-service.mjs';
import { defaults, exec, hash } from '../src/hardened-policy.mjs';

async function fixture(t) {
  const base = await mkdtemp(join(tmpdir(), 'jev-ranges-')), home = join(base, 'private'), root = join(base, 'root');
  await mkdir(home, { mode: 0o700 }); await mkdir(root); await exec('git', ['init', '-q', root]);
  await writeFile(join(home, 'config.json'), JSON.stringify({ ...defaults, allowed_roots: [root] }), { mode: 0o600 });
  const service = await new EvidenceService({ home, boundRoot: root }).init();
  t.after(async () => { service.close(); await rm(base, { recursive: true, force: true }); });
  return { root, service };
}

test('types are explicit and unrelated warning words do not receive critical priority', () => {
  assert.deepEqual(['src/a.js', 'tests/a.js', 'config.toml', 'notes.md', 'output.log'].map(path => evidenceKind(path)),
    ['code', 'test', 'configuration', 'documentation', 'diagnostic']);
  const noise = candidatesFrom({ path: 'output.log', hash: hash('noise'), text: 'WARNING warehouse background routine\n'.repeat(36) }, 'checkout signing failure', []);
  assert.ok(noise.length); assert.ok(noise.every(item => !item.critical && item.protectionReasons.length === 0));
  const facts = candidatesFrom({ path: 'notes.md', hash: hash('notes'), text: 'Checkout must not use legacy signing. The retry fix is unverified.' }, 'checkout signing', []);
  assert.deepEqual(facts[0].protectionReasons, ['query_constraint', 'query_uncertainty']);
});

test('redaction on long identifiers stays bounded without dropping prefixed credential masking', async () => {
  const module = new URL('../src/hardened-policy.mjs', import.meta.url).href;
  const code = `import {redact} from ${JSON.stringify(module)};
    const text = 'x'.repeat(200000) + '\\nSERVICE.api_key="synthetic-hidden-value"';
    const result = redact(text);
    if (result.includes('synthetic-hidden-value') || !result.includes('[REDACTED]')) process.exit(1);`;
  await exec(process.execPath, ['--input-type=module', '-e', code], { timeout: 5000 });
});

test('long relevant exception chains retain typed continuation references beyond the block limit', () => {
  const text = ['ERROR checkout startup failed', ...Array.from({ length: 85 }, (_, i) => `    at frame_${i}`)].join('\n');
  const ranges = candidatesFrom({ path: 'output.log', hash: hash(text), text }, 'checkout startup', []);
  assert.equal(ranges[0].continuationLine, 49);
  assert.ok(ranges.every(item => item.critical));
  assert.equal(ranges.at(-1).lines.end, 86);
  assert.match(ranges.at(-1).excerpt, /frame_84/);
  assert.ok(ranges[1].protectionReasons.includes('exception_chain'));
});

test('preview is optional, preserves exact source ranges and does not replace critical diagnostics', async t => {
  const f = await fixture(t);
  await writeFile(join(f.root, 'logic.js'), Array.from({ length: 12 }, (_, i) => `const handler_${i} = ${i};`).join('\n'));
  const result = await f.service.search({ workspaceRoot: f.root, query: 'handler', detailLevel: 'preview' });
  const item = result.evidence[0];
  assert.equal(item.detailLevel, 'preview'); assert.equal(item.lines.end, 4); assert.equal(item.sourceLines.end, 12);
  const read = await f.service.read({ sessionId: result.sessionId, evidenceId: item.evidenceId, startLine: item.sourceLines.start, endLine: item.sourceLines.end });
  assert.match(read.content, /handler_11/); assert.equal(read.hash, item.hash);
  const precise = await f.service.read({ sessionId: result.sessionId, evidenceId: item.evidenceId, startLine: item.lines.start, endLine: item.lines.end });
  assert.equal(precise.content, item.excerpt);
});

test('oversized first evidence returns a usable reference and bounded single-line reads make progress', async t => {
  const f = await fixture(t), text = 'checkout ' + 'x'.repeat(40000);
  await writeFile(join(f.root, 'output.log'), text);
  const result = await f.service.large({ workspaceRoot: f.root, path: 'output.log', query: 'checkout' });
  assert.equal(result.evidence.length, 1);
  const item = result.evidence[0];
  assert.equal(item.detailLevel, 'reference'); assert.equal(item.omittedText, true);
  assert.equal(result.hasMore, false);
  assert.ok(result.warnings.some(value => /Progressive disclosure/.test(value)));
  const listed = await f.service.list({ sessionId: result.sessionId });
  assert.equal(listed.nextOffset, null); assert.equal(listed.total, 1);
  let offset = 0, recovered = '', calls = 0;
  do {
    const read = await f.service.read({ sessionId: result.sessionId, evidenceId: item.evidenceId, startLine: 1, columnOffset: offset, maxCharacters: 4000 });
    assert.equal(read.hash, item.hash); assert.equal(read.redactedLineHash, hash(text));
    assert.ok(read.nextColumnOffset === null || read.nextColumnOffset > offset);
    recovered += read.content.slice(3); offset = read.nextColumnOffset; calls++;
  } while (offset !== null && calls < 20);
  assert.equal(offset, null); assert.equal(recovered, text);
});

test('column reads never split Unicode or expose a body from the middle of a multiline private key', async t => {
  const f = await fixture(t);
  const marker = 'SYNTHETIC_PRIVATE_BODY_MUST_NOT_ESCAPE';
  const text = ['checkout example', '-----BEGIN PRIVATE KEY-----', ...Array(20).fill(marker), '-----END PRIVATE KEY-----', '\uD83D\uDE80 checkout'].join('\n');
  await writeFile(join(f.root, 'sample.txt'), text);
  const result = await f.service.search({ workspaceRoot: f.root, query: 'checkout' });
  assert.doesNotMatch(JSON.stringify(result), new RegExp(marker));
  const inside = await f.service.read({ sessionId: result.sessionId, evidenceId: result.evidence[0].evidenceId, startLine: 10, columnOffset: 0 });
  assert.doesNotMatch(inside.content, new RegExp(marker)); assert.match(inside.content, /REDACTED PRIVATE KEY/);
  const unicode = { sessionId: result.sessionId, evidenceId: result.evidence[0].evidenceId, startLine: 24 };
  await assert.rejects(f.service.read({ ...unicode, columnOffset: 1 }), { code: 'invalid_input' });
  await assert.rejects(f.service.read({ ...unicode, columnOffset: 0, maxCharacters: 1 }), { code: 'source_limit' });
  const read = await f.service.read({ ...unicode, columnOffset: 0, maxCharacters: 2 });
  assert.equal(read.nextColumnOffset, 2); assert.match(read.content, /\uD83D\uDE80/);
});

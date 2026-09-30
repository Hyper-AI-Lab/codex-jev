import { queryTerms } from './discovery.mjs';

const DIAGNOSTIC = /\b(error|fatal|panic|failed|exception|warning|denied|forbidden|exit code)\b/i;
const CONSTRAINT = /\b(except|unless|must not|cannot|never|rollback|not the cause|contradict|however)\b/i;
const UNCERTAINTY = /\b(unknown|uncertain|unverified|disputed|hypothesis|not confirmed)\b/i;
const COVERAGE_GAP = /\b(?:not (?:tested|covered|supported)|untested|uncovered|missing (?:tests?|coverage)|(?:tests?|coverage) (?:missing|absent))\b/i;
const TEST_SOURCE = /(?:^|\/)(?:tests?|__tests__|specs?)(?:\/|$)|[._-](?:test|spec)\.[^/]+$/i;
const STACK = /^(\s+|Caused by:|Traceback|During handling of)/;

export function evidenceKind(path, diagnostic = false) {
  if (TEST_SOURCE.test(path)) return 'test';
  if (diagnostic || /\.(log|trace)$/i.test(path)) return 'diagnostic';
  if (/\.(md|rst|txt)$/i.test(path)) return 'documentation';
  if (/\.(json|toml|ini|conf|ya?ml)$/i.test(path) || /(?:^|\/)Dockerfile$/.test(path)) return 'configuration';
  return 'code';
}

export function candidatesFrom(source, query, requirements) {
  const lines = source.text.split(/\r?\n/), terms = queryTerms(query, requirements);
  const pathMatch = terms.some(term => source.path.toLowerCase().includes(term));
  const related = text => terms.some(term => text.toLowerCase().includes(term));
  const protectTests = /\b(tests?|testing|coverage|regressions?)\b/i.test(`${query} ${requirements.join(' ')}`) && TEST_SOURCE.test(source.path);
  const result = [];
  let continuation = false;
  for (let index = 0; index < lines.length;) {
    const start = index;
    let end = Math.min(lines.length, index + 12);
    const block = lines.slice(start, end).join('\n');
    const relevant = pathMatch || related(block);
    const diagnostic = DIAGNOSTIC.test(block);
    const nearby = relevant || related(lines.slice(Math.max(0, start - 12), Math.min(lines.length, end + 12)).join('\n'));
    const reasons = [];
    if (continuation) reasons.push('exception_chain');
    if (diagnostic && nearby) reasons.push('query_diagnostic');
    if (CONSTRAINT.test(block) && nearby) reasons.push('query_constraint');
    if (UNCERTAINTY.test(block) && nearby) reasons.push('query_uncertainty');
    if (COVERAGE_GAP.test(block) && nearby) reasons.push('coverage_gap');
    if (protectTests && relevant) reasons.push('related_test');
    if (reasons.length && (diagnostic || continuation)) {
      while (end < lines.length && end < index + 48 && STACK.test(lines[end])) end++;
    }
    continuation = reasons.length > 0 && (diagnostic || continuation) && end < lines.length && STACK.test(lines[end]);
    const raw = lines.slice(start, end).join('\n'), lower = raw.toLowerCase();
    const score = terms.reduce((n, term) => n + Number(lower.includes(term)) + 2 * Number(source.path.toLowerCase().includes(term)), 0);
    index = end;
    // Unrelated diagnostics remain addressable but do not get protected priority.
    if (!score && !diagnostic && !reasons.length) continue;
    result.push({ path: source.path, lines: { start: start + 1, end }, hash: source.hash,
      kind: evidenceKind(source.path, diagnostic), protectionReasons: reasons,
      ...(continuation ? { continuationLine: end + 1 } : {}),
      excerpt: lines.slice(start, end).map((line, offset) => `${start + offset + 1}: ${line}`).join('\n'),
      critical: reasons.length > 0, localScore: 10 * score + (reasons.length ? 5 : 0) });
  }
  return result;
}

export function preview(item) {
  const rows = item.excerpt.split('\n');
  if (rows.length <= 4 || item.critical) return { ...item, detailLevel: 'full' };
  return { ...item, sourceLines: item.lines, lines: { start: item.lines.start, end: item.lines.start + 3 },
    excerpt: rows.slice(0, 4).join('\n'), detailLevel: 'preview', omittedText: true };
}

import { lstat } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { exec, hash, ignoredMany, POLICY, redact, SafeError, safeEnvironment, sensitivePath } from './hardened-policy.mjs';

const STOP = new Set('the and for with from this that these those what which where when why how does are was were have has should could would please identify find explain'.split(' '));
export function queryTerms(query, requirements = []) {
  return [...new Set(redact(`${query} ${requirements.join(' ')}`).toLowerCase().match(/[\p{L}\p{N}_-]{3,}/gu) ?? [])]
    .filter(term => !STOP.has(term)).slice(0, 64);
}
export function pathFilters(value = []) {
  if (!Array.isArray(value) || value.length > 16 || value.some(path => typeof path !== 'string' || !path || path.length > 256 ||
      isAbsolute(path) || path.split(/[\\/]/).some(part => !part || part === '..' || part === '.') || /[\0\r\n*?\[\]]/.test(path) || sensitivePath(path)))
    throw new SafeError('invalid_input', 'pathFilters must be at most sixteen relative file/directory prefixes.');
  return value;
}
export const excludedPath = (path, config) => sensitivePath(path) || config.additional_exclusions.some(prefix => path === prefix || path.startsWith(`${prefix.replace(/\/$/, '')}/`));

export async function discover(root, input, config, store) {
  const filters = pathFilters(input.pathFilters);
  const options = { cwd: root, timeout: 10000, maxBuffer: 4 * 1024 * 1024, env: safeEnvironment() };
  let paths;
  try {
    let output;
    try { output = await exec('rg', ['--files', '--hidden', '-0'], options); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      output = await exec('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], options);
    }
    paths = [...new Set(output.stdout.split('\0').filter(Boolean))].sort();
  } catch (error) {
    if (error.code === 1) paths = [];
    else throw new SafeError('scan_failed', 'Workspace enumeration exceeded its bound or failed.');
  }
  const eligible = paths.filter(path => !excludedPath(path, config) && (!filters.length || filters.some(prefix => path === prefix || path.startsWith(`${prefix}/`))));
  const terms = queryTerms(input.query, input.requirements);
  const pathScore = path => terms.reduce((score, term) => score + Number(path.toLowerCase().includes(term)) * (term.includes('_') ? 8 : 4), 0);
  eligible.sort((a, b) => pathScore(b) - pathScore(a) || a.localeCompare(b));
  const bounded = eligible.slice(0, 5000);
  const ignored = await ignoredMany(root, bounded);
  const allowed = bounded.filter(path => !ignored.has(path));
  const identity = hash(JSON.stringify({ policy: POLICY, paths: allowed, exclusions: config.additional_exclusions,
    query: hash(input.query), requirements: input.requirements ?? [] }));
  const cached = store.discoveryIndex(hash(root), identity);
  const prior = new Map((cached?.files ?? []).map(file => [file.path, file]));
  const files = [];
  let metadataHits = 0;
  for (let offset = 0; offset < allowed.length; offset += 16) {
    for (const row of await Promise.all(allowed.slice(offset, offset + 16).map(async path => {
      const info = await lstat(join(root, path)).catch(() => null);
      if (!info?.isFile() || info.nlink !== 1) return null;
      const signature = hash(`${info.dev}:${info.ino}:${info.size}:${info.mtimeMs}:${info.ctimeMs}`);
      const hit = prior.get(path);
      if (hit?.signature === signature) metadataHits++;
      return { path, signature, score: hit?.signature === signature ? hit.score : 0, pathScore: pathScore(path) };
    }))) if (row) files.push(row);
  }
  files.sort((a, b) => b.pathScore - a.pathScore || b.score - a.score || a.path.localeCompare(b.path));
  return { files, identity, metadataHits, truncated: eligible.length > bounded.length,
    skipped: paths.length - files.length, filters, workspaceHash: hash(root) };
}

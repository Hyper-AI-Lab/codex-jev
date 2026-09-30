import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { privateRead } from './private-read.mjs';

export const exec = promisify(execFile);
export const MODEL = 'jev-1.13.0';
export const POLICY = 'astra-context-v4';
export const SAFETY_REVISION = 'evidence-safety-v3-public';
export const privacyIdentity = config => hash(JSON.stringify({ revision: SAFETY_REVISION,
  exclusions: [...config.additional_exclusions].sort(), literals: [...config.redaction_literals].sort() }));
export const hash = value => createHash('sha256').update(value).digest('hex');
export const defaultHome = () => process.env.JEV_CONTEXT_HOME || join(process.env.CODEX_HOME || join(homedir(), '.codex'), 'jev-context');
export const safeEnvironment = () => Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_') && key !== 'RIPGREP_CONFIG_PATH'));
export const defaults = Object.freeze({ schema_version: 1, enabled: false, live_validated: false,
  model: MODEL, validation_budget_usd: 0, monthly_budget_usd: 0, total_budget_usd: 0, max_requests_per_day: 100, allowed_roots: [],
  additional_exclusions: [], redaction_literals: [], cache_enabled: true, trial: null, default_authorization: null, measurement_enabled: false });

export function trialActive(config, root, now = Date.now()) {
  const trial = config.trial;
  return Boolean(trial && trial.policy === POLICY && Date.parse(trial.starts_at) <= now &&
    now < Date.parse(trial.expires_at) && (!root || trial.roots.includes(root)));
}

export function selectionMode(config, root, now = Date.now()) {
  if (!config.enabled) return 'local_only';
  if (config.default_authorization?.policy === POLICY) return 'jev_default';
  if (config.live_validated) return 'jev_eligible';
  return trialActive(config, root, now) ? 'jev_trial' : 'local_only';
}

export const dailyRequestLimit = config => config.max_requests_per_day;

export class SafeError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

export async function privateDirectory(path) {
  const absolute = resolve(path);
  // Existing ancestors must not redirect private state into another location.
  for (let current = absolute; current !== dirname(current); current = dirname(current)) {
    const info = await lstat(current).catch(error => { if (error.code !== 'ENOENT') throw error; return null; });
    if (info?.isSymbolicLink()) throw new SafeError('unsafe_state', 'Private state cannot use symbolic links');
  }
  await mkdir(absolute, { recursive: true, mode: 0o700 });
  const { chmod } = await import('node:fs/promises');
  await chmod(absolute, 0o700);
}

export async function readPrivateJson(path, missing = null) {
  let text;
  try { text = await privateRead(path); }
  catch { throw new SafeError('unsafe_state', 'Private configuration must be a stable bounded owner-only regular file.'); }
  if (text === null) return missing;
  try { return JSON.parse(text); }
  catch { throw new SafeError('invalid_config', 'Private configuration is not valid JSON'); }
}

export async function configuration(home) {
  const config = { ...defaults, ...await readPrivateJson(join(home, 'config.json'), {}) };
  if (config.schema_version !== 1 || config.model !== MODEL || !Array.isArray(config.allowed_roots) ||
      !config.allowed_roots.every(item => typeof item === 'string' && isAbsolute(item)) ||
      typeof config.enabled !== 'boolean' || typeof config.live_validated !== 'boolean' ||
      typeof config.measurement_enabled !== 'boolean' ||
      typeof config.cache_enabled !== 'boolean' || !Array.isArray(config.additional_exclusions) || config.additional_exclusions.length > 128 ||
      !config.additional_exclusions.every(item => typeof item === 'string' && item.length > 0 && item.length <= 256 && !isAbsolute(item) && !item.split(/[\\/]/).includes('..')) ||
      !Array.isArray(config.redaction_literals) || config.redaction_literals.length > 64 ||
      !config.redaction_literals.every(item => typeof item === 'string' && item.length >= 4 && item.length <= 256) ||
      !['validation_budget_usd', 'monthly_budget_usd', 'total_budget_usd'].every(key => Number.isFinite(config[key]) && config[key] >= 0) ||
      (config.max_requests_per_day !== null && (!Number.isSafeInteger(config.max_requests_per_day) || config.max_requests_per_day < 1 || config.max_requests_per_day > 10000))) {
    throw new SafeError('invalid_config', 'Invalid policy, model or spending limits; no request was sent');
  }
  const authorization = config.default_authorization;
  if (authorization !== null && (typeof authorization !== 'object' || Array.isArray(authorization) ||
      !/^[a-f0-9-]{36}$/.test(authorization.id) || typeof authorization.policy !== 'string' ||
      !Number.isFinite(Date.parse(authorization.authorized_at)))) {
    throw new SafeError('invalid_config', 'Invalid default selection authorization');
  }
  const trial = config.trial;
  if (trial !== null && (typeof trial !== 'object' || Array.isArray(trial) ||
      typeof trial.id !== 'string' || !/^[a-f0-9-]{36}$/.test(trial.id) || typeof trial.policy !== 'string' ||
      !Number.isFinite(Date.parse(trial.starts_at)) || !Number.isFinite(Date.parse(trial.expires_at)) ||
      Date.parse(trial.expires_at) <= Date.parse(trial.starts_at) ||
      Date.parse(trial.expires_at) - Date.parse(trial.starts_at) > 7 * 86400000 ||
      !Array.isArray(trial.roots) || trial.roots.length === 0 || !trial.roots.every(root => config.allowed_roots.includes(root)))) {
    throw new SafeError('invalid_config', 'Invalid bounded trial; no request was sent');
  }
  return config;
}

export function sensitivePath(path) {
  return path.split(/[\\/]/).some(part => {
    const name = part.toLowerCase();
    return ['.git', '.codex', '.ssh', '.aws', '.config', '.gnupg', '.kube', 'backups', 'secrets', 'credentials',
      'node_modules', '.venv', '.venv-quality', 'auth.json', 'application_default_credentials.json',
      'id_rsa', 'id_ed25519', '.npmrc', '.pypirc', '.netrc'].includes(name) ||
      name.startsWith('.env') || /\.(env|pem|key|p12|pfx|sqlite|sqlite3|db|dump)$/.test(name) ||
      /(^|[._-])(secret|credential|token|password)s?([._-]|$)/.test(name);
  });
}

export function redact(text, root = '') {
  let value = String(text);
  if (root) value = value.split(root).join('[workspace]');
  value = value.replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g,
    match => match.split(/\r?\n/).map(() => '[REDACTED PRIVATE KEY]').join('\n'))
    .replace(/\b(?:sk-[A-Za-z0-9_-]{12,}|tsk[-_][A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9_]{15,}|github_pat_[A-Za-z0-9_]{15,}|AIza[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b/g, '[REDACTED TOKEN]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED JWT]')
    .replace(/\b((?:token|bearer[_-]?token)["']?\s*[:=]\s*)(["'])([^\r\n]*?)\2/gi, '$1"[REDACTED]"')
    .replace(/\b((?:token|bearer[_-]?token)\s*[:=]\s*)(?!["'\[])[^\s,;)}]+/gi, '$1[REDACTED]')
    .replace(/(\b(?:authorization|proxy-authorization|cookie|set-cookie)["']?\s*[:=]\s*)(["'])(?:\\.|(?!\2)[^\r\n])*?\2/gi, '$1"[REDACTED]"')
    .replace(/(\b(?:authorization|proxy-authorization|cookie|set-cookie)["']?\s*[:=]\s*)(?!["'])(?:Bearer|Basic)?\s*[^\s,"'}]+/gi, '$1[REDACTED]')
    .replace(/(?<![\w.-])((?:[\w.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)[\w.-]*)["']?\s*[:=]\s*)(["'])([^\r\n]*?)\2/gi, '$1"[REDACTED]"')
    .replace(/(\b[\w.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)[\w.-]*\s*[:=]\s*)(?!["'\[])[^\s,;)}]+/gi, '$1[REDACTED]')
    .replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, '$1[REDACTED]@')
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[REDACTED EMAIL]')
    .replace(/(?<![\w:/.])(?:\/(?:[^\s/"'<>),;]+\/)+|[A-Z]:\\)[^\s"'<>),;]+/g, '[PRIVATE PATH]');
  return value;
}

export function redactSource(text, root, config) {
  // Redact before taking ranges so a read inside a multi-line credential cannot
  // expose its body. Keep source line numbers stable for exact follow-up reads.
  return config.redaction_literals.reduce((value, literal) => value.split(literal).join(
    literal.split(/\r?\n/).map(() => '[REDACTED]').join('\n')), redact(text, root));
}

export async function authorizedRoot(input, home, boundRoot) {
  if (typeof input !== 'string' || !isAbsolute(input)) throw new SafeError('workspace_denied', 'An absolute authorized workspace is required');
  const root = await realpath(input);
  if (root === sep || root === homedir()) throw new SafeError('workspace_denied', 'Home and filesystem roots are not workspaces');
  if (boundRoot && root !== await realpath(boundRoot)) throw new SafeError('workspace_denied', 'Workspace differs from this MCP connection');
  const config = await configuration(home);
  const registry = await readPrivateJson(join(home, 'authorized-workspaces.json'), {});
  const allowed = [...config.allowed_roots, ...(Array.isArray(registry.roots) ? registry.roots : [])];
  if (!allowed.includes(root)) throw new SafeError('workspace_denied', 'Workspace not authorized by owner configuration or a trusted session hook');
  return root;
}

export async function ignored(root, path) {
  try { await exec('git', ['-C', root, 'check-ignore', '--no-index', '-q', '--', path], { timeout: 3000, env: safeEnvironment() }); return true; }
  catch (error) {
    if (error.code === 1) return false;
    // Non-Git workspaces use ripgrep's ignore rules when enumerated.
    if (error.code === 128 && /not a git repository/.test(error.stderr || '')) return false;
    throw new SafeError('scan_failed', 'Could not validate Git exclusions');
  }
}

export async function ignoredMany(root, paths) {
  if (!Array.isArray(paths) || paths.length > 5000 || paths.some(path => typeof path !== 'string' || path.includes('\0')))
    throw new SafeError('scan_failed', 'Invalid exclusion batch');
  const input = paths.join('\0') + '\0';
  if (Buffer.byteLength(input) > 4 * 1024 * 1024) throw new SafeError('scan_failed', 'Exclusion batch is oversized');
  if (!paths.length) return new Set();
  return new Promise((accept, reject) => {
    const child = execFile('git', ['-C', root, 'check-ignore', '--no-index', '-z', '--stdin'],
      { timeout: 3000, maxBuffer: 4 * 1024 * 1024, env: safeEnvironment() }, (error, stdout, stderr) => {
        if (!error || error.code === 1) accept(new Set(stdout.split('\0').filter(Boolean)));
        else if (error.code === 128 && /not a git repository/.test(stderr)) accept(new Set());
        else reject(new SafeError('scan_failed', 'Could not validate batched Git exclusions'));
      });
    child.stdin.on('error', () => {}); // Early Git failure is handled by the exit callback.
    child.stdin.end(input);
  });
}

const exclusionPermits = new WeakMap();
export async function safeReadBatch(root, paths, maxBytes = 1024 * 1024) {
  if (paths.length > 16) throw new SafeError('scan_failed', 'Source read batch exceeds its bound');
  const excluded = await ignoredMany(root, paths);
  const permit = {};
  exclusionPermits.set(permit, { root, paths: new Set(paths.filter(path => !excluded.has(path))) });
  const results = [];
  try {
    for (let offset = 0; offset < paths.length; offset += 4) {
      results.push(...await Promise.all(paths.slice(offset, offset + 4).map(async path => {
        if (excluded.has(path)) return { path, error: 'path_denied' };
        try { return { path, source: await safeRead(root, path, maxBytes, permit) }; }
        catch (error) { return { path, error: error instanceof SafeError ? error.code : 'source_unavailable' }; }
      })));
    }
    // Nothing escapes this batch until current exclusions have been checked again.
    const nowExcluded = await ignoredMany(root, paths);
    return results.map(row => nowExcluded.has(row.path) ? { path: row.path, error: 'path_denied' } : row);
  } finally { exclusionPermits.delete(permit); }
}

export async function safeRead(root, path, maxBytes = 8 * 1024 * 1024, permit) {
  if (typeof path !== 'string' || !path || isAbsolute(path) || sensitivePath(path)) throw new SafeError('path_denied', 'Private or invalid source path');
  const absolute = resolve(root, path);
  const rel = relative(root, absolute);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) throw new SafeError('path_denied', 'Source leaves workspace');
  const ancestors = [];
  for (let current = dirname(absolute); ; current = dirname(current)) {
    const info = await lstat(current);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new SafeError('path_denied', 'Symbolic-link sources are excluded');
    ancestors.push({ path: current, ino: info.ino, dev: info.dev });
    if (current === root) break;
  }
  const verifyAncestors = async () => {
    for (const ancestor of ancestors) {
      const current = await lstat(ancestor.path);
      if (!current.isDirectory() || current.isSymbolicLink() || current.ino !== ancestor.ino || current.dev !== ancestor.dev)
        throw new SafeError('path_denied', 'Source directory changed during read');
    }
  };
  const directories = [];
  let handle;
  try {
    // Linux opens each component relative to a pinned descriptor. O_NOFOLLOW on
    // only the leaf cannot prevent a concurrent parent-directory symlink swap.
    if (process.platform === 'linux') {
      for (const ancestor of [...ancestors].reverse()) {
        const parent = directories.at(-1);
        const next = parent ? `/proc/self/fd/${parent.fd}/${relative(dirname(ancestor.path), ancestor.path)}` : root;
        const directory = await open(next, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
        directories.push(directory);
        const info = await directory.stat();
        if (info.ino !== ancestor.ino || info.dev !== ancestor.dev) throw new SafeError('path_denied', 'Source directory changed during open');
      }
    }
    const batch = permit && exclusionPermits.get(permit);
    if (!(batch?.root === root && batch.paths.has(rel)) && await ignored(root, rel))
      throw new SafeError('path_denied', 'Git-ignored sources are excluded');
    await verifyAncestors();
    const parent = directories.at(-1);
    handle = await open(parent ? `/proc/self/fd/${parent.fd}/${relative(dirname(absolute), absolute)}` : absolute,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    await verifyAncestors();
    const before = await handle.stat();
    if (before.nlink !== 1) throw new SafeError('path_denied', 'Hard-linked sources are excluded');
    if (!before.isFile() || before.size > maxBytes) throw new SafeError('source_limit', 'Source exceeds the bounded regular-file limit');
    const buffer = Buffer.alloc(before.size + 1);
    let bytesRead = 0;
    while (bytesRead < buffer.length) {
      const part = await handle.read(buffer, bytesRead, buffer.length - bytesRead, bytesRead);
      if (!part.bytesRead) break;
      bytesRead += part.bytesRead;
    }
    const after = await handle.stat();
    const current = await lstat(absolute);
    await verifyAncestors();
    if (current.isSymbolicLink() || bytesRead !== before.size || before.mtimeMs !== after.mtimeMs || current.ino !== after.ino || current.dev !== after.dev) {
      throw new SafeError('source_changed', 'Source changed during read; search again');
    }
    const data = buffer.subarray(0, bytesRead);
    if (data.includes(0)) throw new SafeError('binary_source', 'Binary sources are excluded');
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(data); }
    catch { throw new SafeError('binary_source', 'Source is not valid UTF-8 text'); }
    return { text, hash: hash(data), bytes: data.length, path: rel.split(sep).join('/') };
  } catch (error) {
    if (['ELOOP', 'ENOTDIR'].includes(error.code)) throw new SafeError('path_denied', 'Symbolic-link sources are excluded');
    throw error;
  } finally {
    await handle?.close();
    for (const directory of directories.reverse()) await directory.close();
  }
}

#!/usr/bin/env node
import { writeFile, rename, lstat, mkdir, rmdir, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { configuration, dailyRequestLimit, defaultHome, POLICY, privateDirectory, readPrivateJson, SafeError, selectionMode } from '../src/hardened-policy.mjs';
import { Store } from '../src/hardened-store.mjs';

export async function savePrivate(path, value) {
  const temp = `${path}.${randomUUID()}.tmp`;
  await writeFile(temp, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  await rename(temp, path);
}

export async function withEvaluationLock(home, operation) {
  await privateDirectory(home);
  const lock = join(home, '.evaluation-lock');
  try { await mkdir(lock, { mode: 0o700 }); }
  catch (error) { if (error.code === 'EEXIST') throw new SafeError('evaluation_busy', 'Inspect the existing evaluation before changing settings'); throw error; }
  try {
    await savePrivate(join(lock, 'owner.json'), { pid: process.pid, kind: 'trial', at: new Date().toISOString() });
    return await operation();
  } finally { await unlink(join(lock, 'owner.json')).catch(error => { if (error.code !== 'ENOENT') throw error; }); await rmdir(lock); }
}

export const startTrial = (home = defaultHome(), options = {}) => withEvaluationLock(home, () => activate(home, options));

async function retentionProof(home) {
  const pointer = await readPrivateJson(join(home, 'evaluation-latest.json'));
  const report = pointer && await readPrivateJson(pointer.reportPath);
  if (report?.status !== 'retention_passed' || report.sourcePolicy !== POLICY || report.live !== true ||
      !Array.isArray(report.arms) || report.arms.length < 8 || !report.arms.every(row => row.grade?.passed && row.unchanged)) {
    throw new SafeError('preflight_required', 'Current-policy live evidence-retention validation is required');
  }
}

export const enableDefault = (home = defaultHome(), { acknowledgeCost = false } = {}) => withEvaluationLock(home, async () => {
  if (!acknowledgeCost) throw new SafeError('acknowledgement_required', 'Owner authorization required for persistent paid selection');
  if (await lstat(join(home, 'halt.json')).catch(() => null)) throw new SafeError('halted', 'Do not activate during a quota halt');
  const config = await configuration(home);
  if (!config.allowed_roots.length || !['validation_budget_usd', 'monthly_budget_usd', 'total_budget_usd'].every(key => config[key] > 0))
    throw new SafeError('budget_required', 'Existing approved budgets are required; activation never increases them');
  await retentionProof(home);
  const authorization = config.default_authorization?.policy === POLICY ? config.default_authorization :
    { id: randomUUID(), policy: POLICY, authorized_at: new Date().toISOString() };
  await savePrivate(join(home, 'config.json'), { ...config, enabled: true, trial: null, default_authorization: authorization,
    // Persistent selection does not authorize changing an owner's count limit.
    measurement_enabled: true });
  return trialReport(home);
});

async function activate(home, { days = 7, acknowledgeCost = false, now = Date.now() } = {}) {
  if (!acknowledgeCost) throw new SafeError('acknowledgement_required', 'Owner authorization required for paid trial');
  if (!Number.isInteger(days) || days < 1 || days > 7) throw new SafeError('invalid_trial', 'Trial must be 1-7 days');
  await privateDirectory(home);
  if (await lstat(join(home, 'halt.json')).catch(() => null)) throw new SafeError('halted', 'Do not activate during a quota halt');
  const config = await configuration(home);
  if (config.enabled || config.live_validated || config.trial) throw new SafeError('trial_conflict', 'Inspect/stop existing selection state before starting a new trial');
  if (!config.allowed_roots.length || !['validation_budget_usd', 'monthly_budget_usd', 'total_budget_usd'].every(key => config[key] > 0)) {
    throw new SafeError('budget_required', 'Existing approved roots and budgets are required; trial does not increase them');
  }
  await retentionProof(home);
  const trial = { id: randomUUID(), policy: POLICY, starts_at: new Date(now).toISOString(),
    expires_at: new Date(now + days * 86400000).toISOString(), roots: [...config.allowed_roots] };
  await savePrivate(join(home, 'config.json'), { ...config, enabled: true, live_validated: false,
    measurement_enabled: true, max_requests_per_day: Math.min(config.max_requests_per_day ?? 20, 20), trial });
  return trialReport(home);
}

export async function stopTrial(home = defaultHome()) {
  return withEvaluationLock(home, async () => {
    const config = await configuration(home);
    await savePrivate(join(home, 'config.json'), { ...config, enabled: false, trial: null, default_authorization: null });
    return trialReport(home);
  });
}

export async function trialReport(home = defaultHome()) {
  const config = await configuration(home), store = new Store(home);
  try { return { selectionMode: selectionMode(config), liveValidated: config.live_validated, sourcePolicy: POLICY,
    trial: config.trial ? { id: config.trial.id, startsAt: config.trial.starts_at, expiresAt: config.trial.expires_at } : null,
    maxRequestsPerDay: dailyRequestLimit(config), totalCapUsd: config.total_budget_usd,
    defaultAuthorization: config.default_authorization, effectivenessQualified: config.live_validated,
    accounting: store.status(), measurements: store.measurements(config.default_authorization?.id ?? config.trial?.id),
    caveat: 'Evidence bytes and Jev ledger costs are not Codex billed tokens or account-quota savings.' };
  } finally { store.close(); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.umask(0o077);
  const args = process.argv.slice(2);
  try {
    let result;
    if (args.join(' ') === 'start --acknowledge-cost') result = await startTrial(defaultHome(), { acknowledgeCost: true });
    else if (args.join(' ') === 'enable-default --acknowledge-cost') result = await enableDefault(defaultHome(), { acknowledgeCost: true });
    else if (args.join(' ') === 'stop') result = await stopTrial();
    else if (args.join(' ') === 'report') result = await trialReport();
    else throw new SafeError('invalid_arguments', 'Use start --acknowledge-cost, enable-default --acknowledge-cost, stop, or report');
    console.log(JSON.stringify(result));
  } catch (error) { console.error(JSON.stringify({ error: error instanceof SafeError ? error.code : 'trial_failed' })); process.exitCode = 1; }
}

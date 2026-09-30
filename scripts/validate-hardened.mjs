#!/usr/bin/env node
// A bounded synthetic contract probe, not an effectiveness benchmark.
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeFile, rename } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { configuration, defaultHome, exec, hash } from '../src/hardened-policy.mjs';
import { EvidenceService } from '../src/hardened-service.mjs';

process.umask(0o077);
const home = defaultHome();
const live = process.argv.slice(2).includes('--live');
const access = process.argv.slice(2).includes('--check-access');
if (process.argv.slice(2).some(arg => !['--live', '--acknowledge-cost', '--check-access'].includes(arg)) ||
    (live && !process.argv.includes('--acknowledge-cost')) || (access && (live || process.argv.includes('--acknowledge-cost')))) {
  console.error('Use no flags for local status, --check-access for one models GET, or --live --acknowledge-cost for one budgeted evaluation.');
  process.exit(2);
}
const service = await new EvidenceService({ home, purpose: 'validation' }).init();
try {
  const config = await configuration(home);
  if (access) {
    const report = { at: new Date().toISOString(), kind: 'models-access-check', ...await service.checkAccess(),
      inferenceRequests: 0, effectivenessMeasured: false, activationChanged: false };
    const target = join(home, 'validation-access.json'), temp = join(home, `.validation-${randomUUID()}`);
    await writeFile(temp, JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    await rename(temp, target);
    console.log(JSON.stringify(report));
    if (!report.passed) process.exitCode = 1;
  } else if (!live) {
    console.log(JSON.stringify({ live: false, enabled: config.enabled, validationBudgetUsd: config.validation_budget_usd,
      monthlyBudgetUsd: config.monthly_budget_usd, totalBudgetUsd: config.total_budget_usd, requestsSent: 0 }));
  } else {
    const candidates = Array.from({ length: 6 }, (_, index) => ({
      path: `synthetic-${index}`, hash: hash(`synthetic-contract-${index}`), lines: { start: 1, end: 12 },
      critical: index === 0, excerpt: index === 0
        ? 'ERROR: account operations must reject requests whose tenant does not match.\n'.repeat(24)
        : 'An unrelated interface presents a navigation label with consistent spacing.\n'.repeat(24),
    }));
    const result = await service.select('synthetic-contract-probe', 'Which evidence explains tenant access rejection?', [], candidates);
    const report = { at: new Date().toISOString(), kind: 'synthetic-contract-probe', model: config.model,
      mode: result.mode, passed: result.mode === 'jev' && result.keep.includes(0), requests: result.jevRequests,
      usage: result.usage ?? null, reason: result.reason ?? null,
      providerStatus: result.providerStatus ?? null,
      effectivenessMeasured: false, activationChanged: false };
    const target = join(home, 'validation-latest.json'), temp = join(dirname(target), `.validation-${randomUUID()}`);
    await writeFile(temp, JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    await rename(temp, target);
    console.log(JSON.stringify(report));
    if (!report.passed) process.exitCode = 1;
  }
} catch (error) {
  let checkpoint = 'not_required';
  if (['halted', 'usage_invalid'].includes(error.code)) {
    try {
      const manager = resolve(dirname(fileURLToPath(import.meta.url)), '../runtime/manage.py');
      await exec(process.env.JEV_PYTHON || 'python3', [manager, 'halt', '--provider', 'typesafe', '--codex-home', dirname(home)],
        { timeout: 30000, maxBuffer: 65536 });
      checkpoint = 'requested';
    } catch { checkpoint = 'failed_inspect_local_recovery'; }
  }
  console.error(JSON.stringify({ error: error.code || 'validation_failed', requestsMayHaveBeenReserved: true,
    checkpoint,
    instruction: 'Inspect local state; do not retry or enable live selection automatically.' }));
  process.exitCode = 1;
} finally { service.close(); }

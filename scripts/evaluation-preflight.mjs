#!/usr/bin/env node
// Selection safety gate only: packet bytes are not native model token savings.
import { mkdir, rename, rmdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { TASKS, createFixtures, hashTree } from '../benchmarks/confirmation-v4-tasks.mjs';
import { EvidenceService } from '../src/hardened-service.mjs';
import { POLICY, configuration, defaultHome, hash, privateDirectory, SafeError } from '../src/hardened-policy.mjs';
import { fixtureScope } from '../src/evaluation-scope.mjs';
import { entrypointError } from '../src/entrypoint-error.mjs';

export const TASK_IDS = Object.freeze(['webhook-byte-verification', 'inventory-pool-incident',
  'session-cache-region-scope', 'environment-precedence-contract']);

export function validLiveSelection(result) {
  return result.mode === 'jev' || (result.metrics.jevRequests === 0 &&
    (result.mode === 'bypass' || (result.mode === 'local-fallback' && result.selectionReason === 'request_limit')));
}

async function save(path, value) {
  const temp = join(dirname(path), `.evaluation-${randomUUID()}`);
  await writeFile(temp, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  await rename(temp, path);
}

export function gradeSelection(task, result, records) {
  const requiredPaths = task.files ? Object.keys(task.files) : [task.path];
  const returned = result.evidence.map(item => item.path);
  const retained = records.filter(item => item.disposition === 'retained').map(item => item.path);
  const missingReturned = requiredPaths.filter(path => !returned.includes(path));
  const missingRetained = requiredPaths.filter(path => !retained.includes(path));
  const missingIndexed = requiredPaths.filter(path => !records.some(item => item.path === path));
  const requiredDiagnostics = task.log ? [task.log.exception, task.log.key,
    ...task.log.firstFrame, ...task.log.secondFrame] : [];
  const packet = result.evidence.map(item => item.excerpt).join('\n');
  const missingDiagnostics = requiredDiagnostics.filter(value => !packet.includes(value));
  return { passed: !missingReturned.length && !missingRetained.length && !missingDiagnostics.length,
    missingReturned, missingRetained, missingIndexed, missingDiagnostics,
    note: 'Frozen source/diagnostic retention only; no semantic answer or native token score.' };
}

export async function runPreflight({ home = defaultHome(), live = false, fetcher, taskIds = TASK_IDS } = {}) {
  const config = await configuration(home);
  if (live && !config.enabled) throw new SafeError('disabled', 'Live validation requires existing owner enablement; evaluation never enables paid access.');
  await privateDirectory(home);
  const lock = join(home, '.evaluation-lock');
  try { await mkdir(lock, { mode: 0o700 }); }
  catch (error) { if (error.code === 'EEXIST') throw new SafeError('evaluation_busy', 'An evaluation lock exists; inspect its owner before recovery'); throw error; }
  const runDir = join(home, 'evaluations', `${new Date().toISOString().replace(/[:.]/g, '-')}-${randomUUID()}`);
  const report = { schemaVersion: 1, kind: 'selection-retention-preflight', sourcePolicy: POLICY, at: new Date().toISOString(), live,
    status: 'running', taskIds, arms: [], nativeTokens: null, effectivenessMeasured: false,
    automaticActivation: false, reportPath: join(runDir, 'report.json') };
  try {
    await privateDirectory(runDir);
    await save(join(lock, 'owner.json'), { pid: process.pid, runDir, at: report.at });
    const tasks = taskIds.map(id => { const task = TASKS.find(item => item.id === id);
      if (!task) throw new SafeError('invalid_fixture', 'Unknown frozen fixture'); return task; });
    const fixtures = join(runDir, 'fixtures');
    const baseline = await createFixtures(fixtures, tasks);
    const manifest = { taskIds, baseline, tasks: tasks.map(({ id, query, requirements }) => ({ id, query, requirements })),
      model: config.model, sourcePolicy: POLICY, candidateLimit: 20, resultLimit: 8, limits: 'one selection per task/arm; zero automatic retries' };
    await save(join(runDir, 'manifest.json'), manifest);
    report.manifestHash = hash(JSON.stringify(manifest));
    await save(report.reportPath, report);
    for (const arm of live ? ['local', 'jev'] : ['local']) {
      const current = await configuration(home);
      if (current.model !== config.model || (arm === 'jev' && !current.enabled)) {
        throw new SafeError('evaluation_config_changed', 'Live settings changed during evaluation; inspect before continuing');
      }
      for (const task of tasks) {
        const root = join(fixtures, task.id);
        const evaluationScope = await fixtureScope(home, root, baseline[task.id]);
        const service = await new EvidenceService({ home, boundRoot: root, purpose: 'validation', measurementOrigin: 'synthetic',
          evaluationScope, forceLocal: arm === 'local',
          ...(fetcher ? { fetcher } : {}) }).init();
        const started = performance.now();
        try {
          const input = { workspaceRoot: root, query: task.query, requirements: task.requirements,
            candidateLimit: 20, resultLimit: 8, ...(task.path ? { path: task.path } : {}) };
          const result = task.path ? await service.large(input) : await service.search(input);
          const records = []; let offset = 0;
          do { const page = await service.list({ sessionId: result.sessionId, offset }); records.push(...page.evidence); offset = page.nextOffset; }
          while (offset !== null);
          const exact = [];
          for (const item of result.evidence) {
            const value = await service.read({ sessionId: result.sessionId, evidenceId: item.evidenceId,
              startLine: item.lines.start, endLine: item.lines.end });
            exact.push({ path: value.path, lines: value.lines, hash: value.hash });
          }
          const grade = gradeSelection(task, result, records);
          const unchanged = JSON.stringify(await hashTree(root)) === JSON.stringify(baseline[task.id]);
          const row = { taskId: task.id, arm, sourcePolicy: result.sourcePolicy, elapsedMs: Math.round(performance.now() - started), mode: result.mode,
            metrics: result.metrics, packetBytes: Buffer.byteLength(JSON.stringify(result)),
            grade, unchanged, exactReads: exact.length, exact, warnings: result.warnings };
          report.arms.push(row);
          await save(join(runDir, `${task.id}-${arm}.json`), { result, records, row });
          await save(report.reportPath, report);
          if (!unchanged) throw new SafeError('fixture_changed', 'Frozen fixture changed during evaluation');
          if (arm === 'jev' && !validLiveSelection(result)) throw new SafeError('live_selection_failed', 'Live selection did not run successfully; no retry');
        } finally { service.close(); }
      }
    }
    report.status = report.arms.every(row => row.grade.passed) ? 'retention_passed' : 'retention_failed';
  } catch (error) {
    report.status = 'blocked'; report.error = error instanceof SafeError ? error.code : 'evaluation_failed';
    if (['halted', 'usage_invalid'].includes(error.code)) {
      report.recovery = await entrypointError(error, home);
    }
  } finally {
    report.finishedAt = new Date().toISOString();
    await save(report.reportPath, report);
    await save(join(home, 'evaluation-latest.json'), { reportPath: report.reportPath, status: report.status });
    // Only this run's lock is removed; evidence and restoration instructions are retained.
    const { unlink } = await import('node:fs/promises');
    await unlink(join(lock, 'owner.json')).catch(error => { if (error.code !== 'ENOENT') throw error; });
    await rmdir(lock);
  }
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.umask(0o077);
  const args = process.argv.slice(2), live = args.includes('--live');
  if (args.some(arg => !['--live', '--acknowledge-cost'].includes(arg)) || (live !== args.includes('--acknowledge-cost'))) {
    console.error('Use no flags for offline selection, or --live --acknowledge-cost for bounded frozen selection evaluation.'); process.exitCode = 2;
  } else {
    try {
      const report = await runPreflight({ live });
      console.log(JSON.stringify({ status: report.status, reportPath: report.reportPath, nativeTokens: null,
        error: report.error ?? null, results: report.arms.map(({ taskId, arm, mode, grade, metrics }) =>
          ({ taskId, arm, mode, passed: grade.passed, requests: metrics.jevRequests, usage: metrics.jevUsage ?? null })) }));
      if (report.status !== 'retention_passed') process.exitCode = 1;
    } catch (error) { console.error(JSON.stringify({ error: error instanceof SafeError ? error.code : 'evaluation_failed' })); process.exitCode = 1; }
  }
}

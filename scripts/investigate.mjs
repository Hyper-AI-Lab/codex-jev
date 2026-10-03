#!/usr/bin/env node
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EvidenceService } from '../src/hardened-service.mjs';
import { defaultHome, SafeError } from '../src/hardened-policy.mjs';
import { entrypointError } from '../src/entrypoint-error.mjs';
import { cliTask } from '../src/cli-task.mjs';

const HELP = `codex-jev [search|list|read] [options]

Run from the current owner-authorized workspace. Uses the same protected key,
redaction, shared budgets and quota halt as MCP. Does not read keys from env.
  --root PATH             Must match the current workspace (default: cwd)
  --task ID               Registered task; required for persistent list/read
  --session ID            Evidence session from a search (list/read)
  --evidence ID           Exact evidence reference (read)
  --offset N              Reference page offset (list)
  --start-line N          First exact source line (read)
  --end-line N            Last exact source line (read)
  --column-offset N       Offset into one redacted source line (read)
  --max-characters N      Bounded single-line read size (read)
  --detail preview|full   Source detail (search)
  --path RELATIVE_PATH    Select evidence from one eligible text/log file
  --requirement TEXT      Repeat up to 6 times
  --path-filter PREFIX   Search only these relative file/directory prefixes
  --candidate-limit N    Maximum candidates (1-20)
  --result-limit N       Maximum evidence blocks (1-8)
  --local                Force local-only selection
  --jev --allow-network  Require existing paid authorization; never enable it
  --help                 Show this help
Model overrides and raw diagnostic dumps are no longer supported.
`;

export function parseArgs(argv) {
  argv = [...argv];
  const operation = ['search', 'list', 'read'].includes(argv[0]) ? argv.shift() : 'search';
  const input = { workspaceRoot: process.cwd(), requirements: [], pathFilters: [] };
  let local = false, jev = false, acknowledge = false, task;
  const names = { '--root': 'workspaceRoot', '--path': 'path', '--query': 'query',
    '--candidate-limit': 'candidateLimit', '--result-limit': 'resultLimit', '--detail': 'detailLevel',
    '--session': 'sessionId', '--evidence': 'evidenceId', '--offset': 'offset', '--start-line': 'startLine',
    '--end-line': 'endLine', '--column-offset': 'columnOffset', '--max-characters': 'maxCharacters' };
  const numeric = new Set(['candidateLimit', 'resultLimit', 'offset', 'startLine', 'endLine', 'columnOffset', 'maxCharacters']);
  const permitted = {
    search: new Set(['--root', '--task', '--path', '--query', '--candidate-limit', '--result-limit', '--detail', '--requirement', '--path-filter', '--local', '--jev', '--allow-network']),
    list: new Set(['--root', '--task', '--session', '--offset']),
    read: new Set(['--root', '--task', '--session', '--evidence', '--start-line', '--end-line', '--column-offset', '--max-characters']),
  };
  const seen = new Set();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help') return { help: true };
    if (!permitted[operation].has(arg) || (seen.has(arg) && !['--requirement', '--path-filter'].includes(arg)))
      throw new SafeError('invalid_arguments', 'Unsupported or duplicate CLI option; see --help.');
    seen.add(arg);
    if (arg === '--local') { local = true; continue; }
    if (arg === '--jev') { jev = true; continue; }
    if (arg === '--allow-network') { acknowledge = true; continue; }
    const value = argv[++i];
    if (value === undefined) throw new SafeError('invalid_arguments', 'An option is missing its value.');
    if (arg === '--task') task = value;
    else if (arg === '--requirement') input.requirements.push(value);
    else if (arg === '--path-filter') input.pathFilters.push(value);
    else if (numeric.has(names[arg])) {
      if (!/^[0-9]{1,9}$/.test(value)) throw new SafeError('invalid_arguments', 'Expected a bounded non-negative integer.');
      input[names[arg]] = Number(value);
    } else input[names[arg]] = value;
  }
  if (jev !== acknowledge || (jev && local)) throw new SafeError('invalid_arguments', 'Use --jev with --allow-network, or --local.');
  if (operation !== 'search' && (!task || !input.sessionId || (operation === 'read' && !input.evidenceId)))
    throw new SafeError('invalid_arguments', 'List/read requires a registered --task and --session; read also needs --evidence.');
  return { input, local, requireJev: jev, operation, task };
}

export async function runCli(argv, { home = defaultHome(), boundRoot = process.cwd(), fetcher, nativeTask = process.env.CODEX_THREAD_ID } = {}) {
  const options = parseArgs(argv);
  if (options.help) return HELP;
  const scope = options.task ? await cliTask(home, options.input.workspaceRoot, boundRoot, options.task, nativeTask) : null;
  const service = await new EvidenceService({ home, boundRoot, forceLocal: options.local,
    ...(scope ? { owner: scope.owner } : {}),
    measurementOrigin: 'ordinary', ...(fetcher ? { fetcher } : {}) }).init();
  try {
    const result = options.operation === 'list' ? await service.list(options.input) :
      options.operation === 'read' ? await service.read(options.input) :
        await service.investigate(options.input, Boolean(options.input.path));
    if (scope) Object.assign(result, { taskScope: scope.taskScope, taskAttribution: scope.taskAttribution });
    if (options.requireJev && !['jev', 'cache', 'bypass'].includes(result.mode)) {
      return { ...result, requestedSelectionUnavailable: true };
    }
    return result;
  } finally { service.close(); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.umask(0o077);
  try {
    const result = await runCli(process.argv.slice(2));
    console.log(typeof result === 'string' ? result : JSON.stringify(result));
    if (result.requestedSelectionUnavailable) process.exitCode = 1;
  } catch (error) {
    console.error(JSON.stringify(await entrypointError(error, defaultHome())));
    process.exitCode = 1;
  }
}

#!/usr/bin/env node
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EvidenceService } from '../src/hardened-service.mjs';
import { defaultHome, SafeError } from '../src/hardened-policy.mjs';
import { entrypointError } from '../src/entrypoint-error.mjs';

const HELP = `jev-codex-investigate --query TEXT [options]

Run from the current owner-authorized workspace. Uses the same protected key,
redaction, shared budgets and quota halt as MCP. Does not read keys from env.
  --root PATH             Must match the current workspace (default: cwd)
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
  const input = { workspaceRoot: process.cwd(), requirements: [], pathFilters: [] };
  let local = false, jev = false, acknowledge = false;
  const names = { '--root': 'workspaceRoot', '--path': 'path', '--query': 'query',
    '--candidate-limit': 'candidateLimit', '--result-limit': 'resultLimit' };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help') return { help: true };
    if (arg === '--local') { local = true; continue; }
    if (arg === '--jev') { jev = true; continue; }
    if (arg === '--allow-network') { acknowledge = true; continue; }
    if (!['--requirement', '--path-filter'].includes(arg) && !Object.hasOwn(names, arg)) throw new SafeError('invalid_arguments', 'Unsupported CLI option; see --help.');
    const value = argv[++i];
    if (value === undefined) throw new SafeError('invalid_arguments', 'An option is missing its value.');
    if (arg === '--requirement') input.requirements.push(value);
    else if (arg === '--path-filter') input.pathFilters.push(value);
    else input[names[arg]] = arg.endsWith('-limit') ? Number(value) : value;
  }
  if (jev !== acknowledge || (jev && local)) throw new SafeError('invalid_arguments', 'Use --jev with --allow-network, or --local.');
  return { input, local, requireJev: jev };
}

export async function runCli(argv, { home = defaultHome(), boundRoot = process.cwd(), fetcher } = {}) {
  const options = parseArgs(argv);
  if (options.help) return HELP;
  const service = await new EvidenceService({ home, boundRoot, forceLocal: options.local,
    measurementOrigin: 'ordinary', ...(fetcher ? { fetcher } : {}) }).init();
  try {
    const result = await service.investigate(options.input, Boolean(options.input.path));
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

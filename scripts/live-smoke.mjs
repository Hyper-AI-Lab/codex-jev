#!/usr/bin/env node
// Validate the installed protected transport, not an independent HTTP client.
import { verifyDefault } from './verify-default.mjs';
import { defaultHome, SafeError } from '../src/hardened-policy.mjs';
import { entrypointError } from '../src/entrypoint-error.mjs';

process.umask(0o077);
try {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== '--acknowledge-cost') {
    throw new SafeError('invalid_arguments', 'Use --acknowledge-cost ABSOLUTE_WORKSPACE RELATIVE_PATH QUERY. Existing owner authorization and caps still apply.');
  }
  console.log(JSON.stringify(await verifyDefault({ root: args[1], path: args[2], query: args[3] })));
} catch (error) {
  console.error(JSON.stringify(await entrypointError(error, defaultHome())));
  process.exitCode = 1;
}

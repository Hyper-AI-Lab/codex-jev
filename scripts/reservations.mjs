#!/usr/bin/env node
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store } from '../src/hardened-store.mjs';
import { defaultHome, privateDirectory, SafeError } from '../src/hardened-policy.mjs';

export async function reservationsCommand(args, home = defaultHome()) {
  const [command, id, ...flags] = args;
  if (!((command === 'status' && args.length === 1) || (command === 'reconcile' &&
      /^[a-f0-9-]{36}$/.test(id ?? '') && new Set(flags).size === flags.length &&
      flags.every(value => ['--acknowledge-uncertain-charge', '--confirm-unidentified-process-stopped'].includes(value)))))
    throw new SafeError('invalid_arguments', 'Use status, or reconcile ID --acknowledge-uncertain-charge. No request is retried.');
  await privateDirectory(home);
  const store = new Store(home);
  try { return command === 'status' ? store.reservations() : store.reconcileReservation(id, {
    acknowledge: flags.includes('--acknowledge-uncertain-charge'),
    confirmUnidentifiedStopped: flags.includes('--confirm-unidentified-process-stopped'),
  }); } finally { store.close(); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.umask(0o077);
  try { console.log(JSON.stringify(await reservationsCommand(process.argv.slice(2)), null, 2)); }
  catch (error) { console.error(JSON.stringify({ code: error instanceof SafeError ? error.code : 'reservation_failed' })); process.exitCode = 1; }
}

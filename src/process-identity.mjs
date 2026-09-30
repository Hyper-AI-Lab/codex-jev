import { readFileSync, readlinkSync } from 'node:fs';
import { hostname } from 'node:os';
import { randomUUID } from 'node:crypto';
import { hash } from './hardened-policy.mjs';

function start(pid) {
  const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
  const fields = stat.slice(stat.lastIndexOf(')') + 2).trim().split(/\s+/);
  if (!/^\d+$/.test(fields[19] ?? '')) throw new Error('Invalid process identity');
  return fields[19];
}

function identity() {
  const value = { instance: randomUUID(), pid: process.pid, host: hash(hostname()), platform: process.platform };
  if (process.platform === 'linux') {
    try {
      Object.assign(value, { boot: hash(readFileSync('/proc/sys/kernel/random/boot_id', 'utf8')),
        namespace: hash(readlinkSync('/proc/self/ns/pid')), start: start(process.pid) });
    } catch { /* Missing OS identity remains explicitly unverifiable. */ }
  }
  return Object.freeze(value);
}

export const processIdentity = identity();

export function processState(owner) {
  if (!owner || !Number.isSafeInteger(owner.pid) || owner.pid < 1 || owner.host !== processIdentity.host ||
      owner.platform !== process.platform) return 'unknown';
  if (process.platform === 'linux') {
    if (!owner.boot || !owner.namespace || !owner.start || owner.boot !== processIdentity.boot ||
        owner.namespace !== processIdentity.namespace) return 'unknown';
    try { return start(owner.pid) === owner.start ? 'alive' : 'stopped'; }
    catch (error) { return error.code === 'ENOENT' ? 'stopped' : 'unknown'; }
  }
  try { process.kill(owner.pid, 0); return 'alive'; }
  catch (error) { return error.code === 'ESRCH' ? 'stopped' : 'unknown'; }
}

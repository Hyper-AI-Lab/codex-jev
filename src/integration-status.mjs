import { dirname, join } from 'node:path';
import { hash } from './hardened-policy.mjs';
import { privateRead } from './private-read.mjs';

const files = ['SKILL.md', 'references/typed-judgments.md', 'references/typesafe-guidance.md', 'references/LICENSES.txt'];
export async function skillStatus(home, release) {
  const base = { clientLoaded: 'not_observable_by_mcp', bundledHash: release.components?.skill ?? null };
  try {
    const installation = JSON.parse(await privateRead(join(home, 'installation.json')) || '{}');
    if (!installation.skill || !Object.keys(installation.skill).length) return { ...base, state: 'not_installed' };
    if (Object.keys(installation.skill).length !== files.length) return { ...base, state: 'mismatch' };
    for (const name of files) {
      const content = await privateRead(join(dirname(home), 'skills/codex-jev', name), { maxBytes: 32768 });
      if (content === null || hash(content) !== installation.skill[name]) return { ...base, state: 'mismatch' };
    }
    return { ...base, state: 'installed_verified', installedHash: installation.skill['SKILL.md'],
      matchesLoadedRelease: installation.release_id === release.id && installation.skill['SKILL.md'] === base.bundledHash };
  } catch { return { ...base, state: 'unavailable' }; }
}

export async function historyStatus(home) {
  const base = { supportedClients: ['0.130.x', '0.156.x', '0.157.x', '0.160.0'], wholeTaskCoverageVerified: false };
  try {
    const value = JSON.parse(await privateRead(join(home, 'usage-history-status.json'), { maxBytes: 8192 }) || '{}');
    const states = ['caught_up', 'incomplete', 'scan_limit', 'partial_record', 'partial_oversized_record',
      'oversized_record', 'history_unavailable_or_requires_reconciliation'];
    return { ...base, state: states.includes(value.state) ? value.state : 'not_observed',
      ...Object.fromEntries(['recorded', 'invalid_records', 'skipped_records', 'skipped_bytes'].filter(key =>
        Number.isSafeInteger(value[key]) && value[key] >= 0).map(key => [key, value[key]])),
      ...(typeof value.discarding_oversized === 'boolean' ? { discarding_oversized: value.discarding_oversized } : {}),
      ...(typeof value.at === 'string' && /^\d{4}-\d{2}-\d{2}T[0-9:.+Z-]{8,32}$/.test(value.at) ? { checkedAt: value.at } : {}) };
  } catch { return { ...base, state: 'unavailable' }; }
}

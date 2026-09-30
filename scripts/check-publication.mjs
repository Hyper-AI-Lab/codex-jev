import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

// Report names/rules only, never matched credential values. This complements,
// rather than replaces, a dedicated secret scanner and human publication review.
const skip = new Set(['.git', 'node_modules', '__pycache__', '.ruff_cache', '.pytest_cache']);
const rules = [
  ['private-host-path', /\/(?:root\/\.codex|home\/projects)\//],
  ['live-provider-token', /\b(?:sk-[A-Za-z0-9_-]{30,}|gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,}|AIza[A-Za-z0-9_-]{30,})\b/],
];
const failures = [];
async function scan(dir = '.') {
  for (const item of await readdir(dir, { withFileTypes: true })) {
    if (skip.has(item.name)) continue;
    const path = join(dir, item.name);
    if (item.isSymbolicLink()) { failures.push([path, 'symlink']); continue; }
    if (item.isDirectory()) { await scan(path); continue; }
    if (/^(?:\.env(?:\.|$)|auth\.json$)|\.(?:sqlite3?|db|dump|pem|key|tgz|log)$/.test(item.name)) failures.push([path, 'private-artifact']);
    if (item.name === 'check-publication.mjs') continue;
    const value = await readFile(path, 'utf8');
    for (const [rule, pattern] of rules) if (pattern.test(value)) failures.push([path, rule]);
  }
}
await scan();
if (failures.length) { console.error(JSON.stringify({ failures })); process.exitCode = 1; }
else console.log('Public tree checks passed; matched values are never printed.');

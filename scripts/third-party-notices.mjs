import { readFile, writeFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

const lock = JSON.parse(await readFile('package-lock.json', 'utf8'));
const sections = [];
for (const [path, info] of Object.entries(lock.packages).sort(([a], [b]) => a.localeCompare(b))) {
  if (!path.startsWith('node_modules/')) continue;
  let names;
  try { names = await readdir(path); } catch (error) { if (error.code === 'ENOENT' && info.optional) continue; throw error; }
  const files = names.filter(name => /^(licen[cs]e|copying|notice)(\.|$)/i.test(name));
  const texts = await Promise.all(files.map(async name => `${name}:\n${(await readFile(join(path, name), 'utf8')).replace(/\r\n/g, '\n').replace(/[\t ]+$/gm, '')}`));
  sections.push(`${path.slice('node_modules/'.length)} ${info.version}\nLicense: ${info.license || 'See package license'}\n${texts.join('\n')}`);
}
await writeFile('THIRD_PARTY_NOTICES.txt', 'Third-party dependency notices (locked development and bundled runtime tree)\n\n' + sections.join('\n\n' + '='.repeat(72) + '\n\n'));
console.log(`Wrote notices for ${sections.length} installed dependencies.`);

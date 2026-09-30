import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { dirname, basename, resolve } from 'node:path';

// Private reads share one descriptor-pinned path for keys and configuration.
// The caller maps failures to its public error vocabulary, never raw OS errors.
export async function privateRead(path, { maxBytes = 1024 * 1024, missing = null } = {}) {
  const absolute = resolve(path), ancestors = [];
  for (let current = dirname(absolute); ; current = dirname(current)) {
    const info = await lstat(current);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('unsafe_private_file');
    ancestors.push({ path: current, ino: info.ino, dev: info.dev });
    if (current === dirname(current)) break;
  }
  const verifyAncestors = async () => {
    for (const before of ancestors) {
      const now = await lstat(before.path);
      if (!now.isDirectory() || now.isSymbolicLink() || before.ino !== now.ino || before.dev !== now.dev)
        throw new Error('unsafe_private_file');
    }
  };
  const directories = []; let handle;
  const valid = info => info.isFile() && info.nlink === 1 && !(info.mode & 0o077) &&
    info.size <= maxBytes && (!process.getuid || info.uid === process.getuid());
  try {
    if (process.platform === 'linux') {
      for (const ancestor of [...ancestors].reverse()) {
        const parent = directories.at(-1);
        const path = parent ? `/proc/self/fd/${parent.fd}/${basename(ancestor.path)}` : ancestor.path;
        const directory = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
        directories.push(directory);
        const info = await directory.stat();
        if (info.ino !== ancestor.ino || info.dev !== ancestor.dev) throw new Error('unsafe_private_file');
      }
    }
    await verifyAncestors();
    const parent = directories.at(-1);
    try { handle = await open(parent ? `/proc/self/fd/${parent.fd}/${basename(absolute)}` : absolute,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await verifyAncestors();
      // A dangling symlink is not a missing private configuration.
      if (await lstat(absolute).catch(error => { if (error.code !== 'ENOENT') throw error; return null; })) throw error;
      return missing;
    }
    const before = await handle.stat();
    if (!valid(before)) throw new Error('unsafe_private_file');
    const buffer = Buffer.alloc(before.size + 1); let size = 0;
    while (size < buffer.length) {
      const part = await handle.read(buffer, size, buffer.length - size, size);
      if (!part.bytesRead) break;
      size += part.bytesRead;
    }
    const after = await handle.stat(), current = await lstat(absolute);
    await verifyAncestors();
    if (!valid(after) || !valid(current) || current.isSymbolicLink() || size !== before.size ||
        before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs ||
        current.ino !== before.ino || current.dev !== before.dev || current.ctimeMs !== after.ctimeMs)
      throw new Error('unsafe_private_file');
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, size));
  } finally {
    await handle?.close();
    for (const directory of directories.reverse()) await directory.close();
  }
}

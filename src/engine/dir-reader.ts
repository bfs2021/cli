import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Lists one directory. Throws when the directory cannot be read — callers
 * skip that branch, the same way a direct `readdir` failure is skipped.
 *
 * Node's `fs` exports are live bindings and cannot be spied on, so `vg build`
 * takes this hook when a test needs to count directory reads.
 */
export type DirectoryReader = (absDir: string) => fs.Dirent[];

/** Filesystem listing: one `readdir` with file types. */
export function readDirectory(absDir: string): fs.Dirent[] {
  return fs.readdirSync(absDir, { withFileTypes: true });
}

/**
 * One filesystem read per directory. Later calls reuse that listing (a
 * shallow copy, so a caller may sort its own array). A failed read is
 * remembered and rethrown without touching the filesystem again.
 *
 * `vg build` shares one of these across lockfile validation, source
 * discovery, manifests, docs, and workspace package globs. Each of those
 * passes keeps its own skip rules; they no longer re-list the tree.
 */
export function cacheDirectoryReads(read: DirectoryReader): DirectoryReader {
  const listings = new Map<string, fs.Dirent[]>();
  const failures = new Map<string, unknown>();
  return (absDir: string) => {
    const key = path.resolve(absDir);
    if (failures.has(key)) throw failures.get(key);
    const hit = listings.get(key);
    if (hit) return hit.slice();
    try {
      const entries = read(key).slice();
      listings.set(key, entries);
      return entries.slice();
    } catch (err) {
      failures.set(key, err);
      throw err;
    }
  };
}

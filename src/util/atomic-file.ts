/**
 * Replace a file by writing a temp in the same directory, then renaming it
 * into place.
 *
 * `writeFile` truncates the destination as soon as it opens. A Ctrl-C, CI
 * timeout, or OOM between that open and the last byte leaves a zero-length
 * or half-written artifact, and the next `vg` run fails trying to parse it.
 * A rename in the same directory is atomic: readers keep seeing the previous
 * file until the new one is complete.
 *
 * Temps are named `.vg-partial.<pid>.<seq>.<basename>` in the destination
 * directory. The next write in that directory removes only those names (and
 * the older `<basename>.<pid>.tmp` temps this repo used to leave), in sorted
 * order. Other files, including editor `*.tmp` backups, are left alone.
 */
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';

/** Directory entry prefix for a temp this module created. */
export const ATOMIC_TEMP_PREFIX = '.vg-partial.';

const OURS = /^\.vg-partial\.\d+\.\d+\./;
const SQLITE_SIDECAR = ['-journal', '-wal', '-shm'] as const;

let tempSeq = 0;

export interface AtomicWriteOptions {
  /** Mode for a new file. An existing file keeps its mode when this is omitted. */
  mode?: number;
  /**
   * Runs after the temp is fully written and fsynced, before rename.
   * A throw aborts the replace and leaves the destination untouched.
   * Tests use this to kill the process and prove the previous file survives.
   */
  beforeRename?: () => void;
  /**
   * When false, filesystem failures are rethrown as-is (callers that already
   * map `error.code` into a CLI message). Default: throw {@link AtomicWriteError}.
   */
  wrapError?: boolean;
  /**
   * Extra same-directory names to remove before writing. Only a basename is
   * accepted — a name with a slash or `..` is ignored. Used for a known
   * legacy temp such as `layout.json.tmp`.
   */
  legacyTempNames?: readonly string[];
}

export class AtomicWriteError extends Error {
  readonly filePath: string;
  readonly code: string;

  constructor(filePath: string, cause: unknown) {
    const code = codeOf(cause);
    super(
      `cannot write ${filePath} (${reasonOf(code)}): the previous file was left unchanged. Check the path and permissions, free disk space if it is full, then re-run the command.`,
    );
    this.name = 'AtomicWriteError';
    this.filePath = filePath;
    this.code = code;
    if (cause !== undefined) this.cause = cause;
  }
}

function codeOf(cause: unknown): string {
  if (typeof cause === 'object' && cause !== null && 'code' in cause) {
    const code = (cause as { code?: unknown }).code;
    if (typeof code === 'string') return code;
  }
  return '';
}

function reasonOf(code: string): string {
  switch (code) {
    case 'EACCES':
    case 'EPERM':
      return 'permission denied';
    case 'EROFS':
      return 'filesystem is read-only';
    case 'ENOENT':
      return 'parent directory is missing';
    case 'ENOTDIR':
    case 'EEXIST':
      return 'a parent path is not a directory';
    case 'EISDIR':
      return 'output path is a directory';
    case 'ENOSPC':
    case 'EDQUOT':
      return 'disk full';
    case 'EIO':
      return 'the write did not finish';
    default:
      return 'write failed';
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Older temps this repo wrote beside the destination before `.vg-partial`. */
function legacyTempPattern(basename: string): RegExp {
  const base = escapeRegExp(basename);
  return new RegExp(`^(?:${base}\\.\\d+(?:\\.\\d+)?\\.tmp|${base}\\.tmp\\.\\d+)$`);
}

function safeBasename(name: string): string | null {
  if (!name || name === '.' || name === '..') return null;
  if (name.includes('/') || name.includes('\\') || name.includes('\0')) return null;
  return name;
}

function compareName(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function tempCandidates(names: readonly string[], basename: string | undefined, legacyTempNames: readonly string[] | undefined): string[] {
  const legacy = basename ? legacyTempPattern(basename) : null;
  const extra = new Set<string>();
  for (const name of legacyTempNames ?? []) {
    const safe = safeBasename(name);
    if (safe) extra.add(safe);
  }
  const matched = new Set<string>();
  for (const name of names) {
    if (OURS.test(name) || (legacy?.test(name) ?? false) || extra.has(name)) matched.add(name);
  }
  for (const name of names) {
    for (const suffix of SQLITE_SIDECAR) {
      if (!name.endsWith(suffix)) continue;
      const stem = name.slice(0, -suffix.length);
      if (matched.has(stem)) matched.add(name);
    }
  }
  return [...matched].sort(compareName);
}

function unlinkFile(full: string): boolean {
  try {
    const st = fs.lstatSync(full);
    if (!st.isFile()) return false;
    fs.unlinkSync(full);
    return true;
  } catch {
    return false;
  }
}

/**
 * Remove leftover temps in `dir`. Returns the removed paths, sorted by name.
 * Missing directories and unrelated names are ignored.
 */
export function cleanupStrayAtomicTemps(
  dir: string,
  basename?: string,
  legacyTempNames?: readonly string[],
): string[] {
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return [];
  }
  const removed: string[] = [];
  for (const name of tempCandidates(names, basename, legacyTempNames)) {
    const full = path.join(dir, name);
    if (unlinkFile(full)) removed.push(full);
  }
  return removed;
}

/** Same-directory temp path for a destination. Each call uses a new sequence. */
export function atomicTempPath(filePath: string): string {
  const base = safeBasename(path.basename(filePath)) ?? 'file';
  const safe = base.replace(/[^A-Za-z0-9._@+-]+/g, '_') || 'file';
  tempSeq += 1;
  return path.join(path.dirname(filePath), `${ATOMIC_TEMP_PREFIX}${process.pid}.${tempSeq}.${safe}`);
}

/** Best-effort removal of a temp and any SQLite sidecar beside it. */
export function discardAtomicTemp(tmp: string): void {
  unlinkFile(tmp);
  for (const suffix of SQLITE_SIDECAR) unlinkFile(tmp + suffix);
}

function existingMode(filePath: string): number | undefined {
  try {
    const st = fs.lstatSync(filePath);
    if (!st.isFile()) return undefined;
    return st.mode & 0o777;
  } catch {
    return undefined;
  }
}

function toBuffer(data: string | NodeJS.ArrayBufferView): Buffer {
  if (typeof data === 'string') return Buffer.from(data, 'utf8');
  if (Buffer.isBuffer(data)) return data;
  return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
}

function writeAllSync(fd: number, data: string | NodeJS.ArrayBufferView): void {
  const buf = toBuffer(data);
  let offset = 0;
  while (offset < buf.length) {
    const wrote = fs.writeSync(fd, buf, offset, buf.length - offset);
    if (wrote <= 0) {
      const err = new Error('short write') as NodeJS.ErrnoException;
      err.code = 'EIO';
      throw err;
    }
    offset += wrote;
  }
}

function fsyncDir(dir: string): void {
  try {
    const fd = fs.openSync(dir, 'r');
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    // A directory fsync is durability, not correctness of the rename.
  }
}

function finishError(filePath: string, err: unknown, opts: AtomicWriteOptions): never {
  if (opts.wrapError === false) throw err;
  if (err instanceof AtomicWriteError) throw err;
  throw new AtomicWriteError(filePath, err);
}

export function writeAtomicSync(
  filePath: string,
  data: string | NodeJS.ArrayBufferView,
  opts: AtomicWriteOptions = {},
): void {
  const dir = path.dirname(filePath);
  const base = path.basename(filePath);
  let tmp: string | undefined;
  let passthrough = false;
  try {
    fs.mkdirSync(dir, { recursive: true });
    cleanupStrayAtomicTemps(dir, base, opts.legacyTempNames);
    tmp = atomicTempPath(filePath);
    const mode = opts.mode ?? existingMode(filePath);
    const fd = fs.openSync(tmp, 'w', mode ?? 0o666);
    try {
      if (mode !== undefined) {
        try {
          fs.fchmodSync(fd, mode);
        } catch {
          /* platforms without POSIX modes */
        }
      }
      writeAllSync(fd, data);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    try {
      opts.beforeRename?.();
    } catch (err) {
      discardAtomicTemp(tmp);
      tmp = undefined;
      passthrough = true;
      throw err;
    }
    fs.renameSync(tmp, filePath);
    tmp = undefined;
    fsyncDir(dir);
  } catch (err) {
    if (tmp) discardAtomicTemp(tmp);
    if (passthrough) throw err;
    finishError(filePath, err, opts);
  }
}

export async function writeAtomic(
  filePath: string,
  data: string | NodeJS.ArrayBufferView,
  opts: AtomicWriteOptions = {},
): Promise<void> {
  const dir = path.dirname(filePath);
  const base = path.basename(filePath);
  let tmp: string | undefined;
  let passthrough = false;
  try {
    await fsp.mkdir(dir, { recursive: true });
    cleanupStrayAtomicTemps(dir, base, opts.legacyTempNames);
    tmp = atomicTempPath(filePath);
    const mode = opts.mode ?? existingMode(filePath);
    const fh = await fsp.open(tmp, 'w', mode ?? 0o666);
    try {
      if (mode !== undefined) {
        try {
          await fh.chmod(mode);
        } catch {
          /* platforms without POSIX modes */
        }
      }
      const buf = toBuffer(data);
      let offset = 0;
      while (offset < buf.length) {
        const { bytesWritten } = await fh.write(buf, offset, buf.length - offset);
        if (bytesWritten <= 0) {
          const err = new Error('short write') as NodeJS.ErrnoException;
          err.code = 'EIO';
          throw err;
        }
        offset += bytesWritten;
      }
      await fh.sync();
    } finally {
      await fh.close();
    }
    try {
      opts.beforeRename?.();
    } catch (err) {
      discardAtomicTemp(tmp);
      tmp = undefined;
      passthrough = true;
      throw err;
    }
    await fsp.rename(tmp, filePath);
    tmp = undefined;
    fsyncDir(dir);
  } catch (err) {
    if (tmp) discardAtomicTemp(tmp);
    if (passthrough) throw err;
    finishError(filePath, err, opts);
  }
}

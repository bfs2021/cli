// VENDORED from @vibgrate/core-open (packages/vibgrate-core-open) by
// scripts/vendor-core-open.mjs. Do not edit here — change the source package
// and re-run the vendor script. Apache-2.0.
/**
 * Replace a file by writing a temp in the same directory and renaming it
 * into place. A crash mid-write leaves the previous file intact: the temp
 * is a different name, and rename is atomic on one filesystem.
 *
 * Temp name: `.<basename>.<pid>.vg-tmp`. The next write in that directory
 * removes temps whose process is gone, in sorted name order, so cleanup does
 * not depend on directory enumeration order, the clock, or randomness.
 * Temps belonging to a live process are left alone.
 */

import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';

export type AtomicBytes = string | NodeJS.ArrayBufferView;

const TEMP_SUFFIX = '.vg-tmp';

/** True when `pid` is a running process (or one we are not allowed to signal). */
export function isPidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

function byName(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function safePid(text: string): number | null {
  if (!/^\d+$/.test(text)) return null;
  const pid = Number(text);
  return Number.isSafeInteger(pid) ? pid : null;
}

/** `.<basename>.<pid>.vg-tmp` → pid. Basename may contain dots. */
function pidOfCurrentTemp(name: string): number | null {
  if (!name.startsWith('.') || !name.endsWith(TEMP_SUFFIX)) return null;
  const body = name.slice(1, -TEMP_SUFFIX.length);
  const dot = body.lastIndexOf('.');
  if (dot <= 0) return null;
  return safePid(body.slice(dot + 1));
}

/**
 * Earlier writers used `<basename>.<pid>.tmp`, `<basename>.<pid>.<n>.tmp`,
 * and `<basename>.tmp.<pid>` beside the destination. Only those names, and
 * only for this destination, are treated as leftovers.
 */
function pidOfLegacyTemp(name: string, basename: string): number | null {
  const prefixed = `${basename}.`;
  if (name.startsWith(prefixed) && name.endsWith('.tmp')) {
    const mid = name.slice(prefixed.length, -'.tmp'.length);
    const m = /^(\d+)(?:\.\d+)?$/.exec(mid);
    if (m?.[1]) return safePid(m[1]);
  }
  const tmpPid = `${basename}.tmp.`;
  if (name.startsWith(tmpPid)) return safePid(name.slice(tmpPid.length));
  return null;
}

export function atomicTempPath(filePath: string, pid: number = process.pid): string {
  const base = path.basename(filePath);
  return path.join(path.dirname(filePath), `.${base}.${pid}${TEMP_SUFFIX}`);
}

export interface SweepOptions {
  /** Also remove legacy temps for this destination basename. */
  basename?: string;
  /** Process-liveness check. Default asks the OS. */
  alive?: (pid: number) => boolean;
  /** Never delete this path (the destination itself). */
  keep?: string;
}

/**
 * Remove leftover atomic temps in `dir`. Returns the removed names in sorted
 * order. Live writers are kept. A missing directory is a no-op.
 */
export function sweepStrayAtomicTemps(dir: string, opts: SweepOptions = {}): string[] {
  const alive = opts.alive ?? isPidAlive;
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return [];
  }
  const keep = opts.keep ? path.resolve(opts.keep) : '';
  const stray = names.filter((name) => {
    if (keep && path.resolve(dir, name) === keep) return false;
    const pid = pidOfCurrentTemp(name) ?? (opts.basename ? pidOfLegacyTemp(name, opts.basename) : null);
    if (pid === null) return false;
    return !alive(pid);
  });
  stray.sort(byName);
  const removed: string[] = [];
  for (const name of stray) {
    const full = path.join(dir, name);
    try {
      if (!fs.lstatSync(full).isFile()) continue;
      fs.rmSync(full, { force: true });
      removed.push(name);
    } catch {
      /* next run retries */
    }
  }
  return removed;
}

function fsCode(cause: unknown): string {
  if (typeof cause === 'object' && cause !== null && 'code' in cause) {
    const code = (cause as { code?: unknown }).code;
    if (typeof code === 'string') return code;
  }
  return '';
}

function writeFailureReason(cause: unknown): string {
  switch (fsCode(cause)) {
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
    default:
      return 'write failed';
  }
}

function nextStep(cause: unknown): string {
  switch (fsCode(cause)) {
    case 'ENOSPC':
    case 'EDQUOT':
      return 'free disk space and run the command again';
    case 'EISDIR':
      return 'choose a file path';
    case 'EROFS':
      return 'choose a writable location';
    default:
      return 'check the path and permissions, or choose another location';
  }
}

/** Actionable write failure. The Node message, stack, and temp path stay out. */
export function artifactWriteMessage(filePath: string, cause: unknown): string {
  return `cannot write ${filePath} (${writeFailureReason(cause)}): ${nextStep(cause)}`;
}

/**
 * Test seam. When set, it replaces the temp-file write so a test can emit a
 * short prefix and throw before rename. Production leaves this unset.
 */
let writeFault: ((tmp: string, data: AtomicBytes) => void) | null = null;

export function setAtomicWriteFaultForTests(fault: ((tmp: string, data: AtomicBytes) => void) | null): void {
  writeFault = fault;
}

function writeTempSync(tmp: string, data: AtomicBytes): void {
  if (writeFault) {
    writeFault(tmp, data);
    return;
  }
  if (typeof data === 'string') fs.writeFileSync(tmp, data, 'utf8');
  else fs.writeFileSync(tmp, data);
}

async function writeTemp(tmp: string, data: AtomicBytes): Promise<void> {
  if (writeFault) {
    writeFault(tmp, data);
    return;
  }
  if (typeof data === 'string') await fsp.writeFile(tmp, data, 'utf8');
  else await fsp.writeFile(tmp, data);
}

export function writeAtomicSync(filePath: string, data: AtomicBytes): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  sweepStrayAtomicTemps(dir, { basename: path.basename(filePath), keep: filePath });
  const tmp = atomicTempPath(filePath);
  try {
    writeTempSync(tmp, data);
    fs.renameSync(tmp, filePath);
  } catch (err) {
    try {
      fs.rmSync(tmp, { force: true });
    } catch {
      /* the next write sweeps it */
    }
    throw err;
  }
}

export async function writeAtomic(filePath: string, data: AtomicBytes): Promise<void> {
  const dir = path.dirname(filePath);
  await fsp.mkdir(dir, { recursive: true });
  sweepStrayAtomicTemps(dir, { basename: path.basename(filePath), keep: filePath });
  const tmp = atomicTempPath(filePath);
  try {
    await writeTemp(tmp, data);
    await fsp.rename(tmp, filePath);
  } catch (err) {
    try {
      await fsp.rm(tmp, { force: true });
    } catch {
      /* the next write sweeps it */
    }
    throw err;
  }
}

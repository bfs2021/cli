// VENDORED from @vibgrate/core-open (packages/vibgrate-core-open) by
// scripts/vendor-core-open.mjs. Do not edit here — change the source package
// and re-run the vendor script. Apache-2.0.
import * as path from 'node:path';
import { codedWarning, formatWarningLine, warningPathLabel, WARNING_CODES, type CodedWarning } from '../warnings.js';

/**
 * How many root-relative paths one notice lists. Further links are a count.
 * The walk sorts before capping, so the same tree always names the same paths.
 */
export const SKIPPED_SYMLINK_NOTICE_CAP = 5;

function comparePath(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Root-relative POSIX path, or '' when `absPath` is the root or escapes it.
 * Absolute paths are never returned.
 */
export function walkRelativePath(root: string, absPath: string): string {
  const rel = path.relative(root, absPath);
  if (!rel || rel === '.' || rel.startsWith('..')) return '';
  return rel.split(path.sep).join('/');
}

/** Record one skipped symlink. Empty and out-of-root paths are dropped. */
export function rememberSkippedSymlink(bucket: string[], relPath: string): void {
  const rel = relPath.split(path.sep).join('/');
  if (!rel || rel === '.' || rel.startsWith('..') || rel.startsWith('/')) return;
  bucket.push(rel);
}

/**
 * Label safe to print for one skipped symlink.
 *
 * {@link warningPathLabel} collapses an absolute path or a `..` path to its
 * base name, so a home directory or a link target never appears. Empty labels
 * are dropped. The link's own path is labeled; the target is not read.
 */
export function skippedSymlinkLabel(raw: string): string | null {
  const rel = raw.split('\\').join('/');
  if (!rel || rel === '.' || rel === '..') return null;
  const label = warningPathLabel(rel);
  if (!label || label === 'path' || label === '.' || label === '..') return null;
  if (label.startsWith('/') || label.startsWith('..') || /^[A-Za-z]:/.test(label)) return null;
  return label;
}

/**
 * One coalesced warning when a walk skips symlinks. `null` when nothing
 * safe remains. Labels are de-duplicated, sorted, and capped.
 */
export function skippedSymlinkWarning(relPaths: readonly string[]): CodedWarning | null {
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const raw of relPaths) {
    const label = skippedSymlinkLabel(raw);
    if (!label || seen.has(label)) continue;
    seen.add(label);
    unique.push(label);
  }
  unique.sort(comparePath);
  if (unique.length === 0) return null;
  const shown = unique.slice(0, SKIPPED_SYMLINK_NOTICE_CAP);
  const extra = unique.length - shown.length;
  const list = extra > 0 ? `${shown.join(', ')}, +${extra} more` : shown.join(', ');
  const noun = unique.length === 1 ? 'symlink' : 'symlinks';
  return codedWarning(
    WARNING_CODES.SYMLINK_SKIPPED,
    `skipped ${unique.length} ${noun} (${list}). ` +
      'vg does not follow symlinks. Point the root at the link target, or pass --exclude or a narrower root.',
  );
}

/**
 * One stderr line when a walk skips symlinks. `null` when `relPaths` is empty.
 * Paths are de-duplicated, sorted, and capped. The line is
 * `warning [VG_WARN_SYMLINK_SKIPPED]: …`.
 */
export function formatSkippedSymlinkNotice(relPaths: readonly string[]): string | null {
  const warning = skippedSymlinkWarning(relPaths);
  return warning ? formatWarningLine(warning) : null;
}

/** Write {@link formatSkippedSymlinkNotice} to stderr. No-op when there is nothing to say. */
export function emitSkippedSymlinkNotice(relPaths: readonly string[]): void {
  const line = formatSkippedSymlinkNotice(relPaths);
  if (!line) return;
  process.stderr.write(`${line}\n`);
}

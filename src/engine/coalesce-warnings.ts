import chalk from 'chalk';
import {
  codedWarning,
  formatWarningLine,
  isWarningCode,
  stampWarning,
  warningPathLabel,
  WARNING_CODES,
  type CodedWarning,
  type WarningCode,
} from '../core-open/warnings.js';
import { redactForDisplay } from '../core-open/utils/redact.js';

/**
 * How many repo-relative paths one human stderr line names. Further files
 * are a count. Paths are sorted before the cap, so the same tree always
 * names the same samples.
 */
export const HUMAN_WARNING_SAMPLE_CAP = 5;

const REASON_MAX = 240;

const FILE_URL = /file:\/\/\S+/g;
const ABS_WIN = /[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]+/g;
const ABS_WIN_POSIX = /[A-Za-z]:\/(?:[^/\s]+\/)*[^/\s]+/g;
const ABS_UNIX = /(?:^|[\s('"])\/(?:[\w.+@~-]+\/)+[\w.+@~-]*/g;
const REL_ESCAPE = /(?:^|[\s('"])(?:[\w.+@~-]+\/)*\.\.\/(?:[\w.+@~-]+\/)*[\w.+@~-]*/g;

/** A leading `path timed out …` or `path skipped — …` degrade sentence. */
const LEADING_PATH = /^(.*\S) (timed out \(>.*|skipped — .*)$/;

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Reason text safe to group and print: secrets and absolute paths removed,
 * whitespace collapsed, length capped. Repo-relative paths are left as written.
 */
export function normalizeReason(reason: string): string {
  let text = redactForDisplay(reason);
  text = text.replace(FILE_URL, 'a file');
  text = text.replace(ABS_WIN, 'a file');
  text = text.replace(ABS_WIN_POSIX, 'a file');
  text = text.replace(ABS_UNIX, (match) => {
    const lead = match.startsWith('/') ? '' : match[0];
    return `${lead}a file`;
  });
  text = text.replace(REL_ESCAPE, (match) => {
    const lead = match.startsWith('.') || match.startsWith('/') ? '' : match[0];
    return `${lead}a file`;
  });
  text = text.replace(/\s+/g, ' ').trim();
  if (text.length > REASON_MAX) return `${text.slice(0, REASON_MAX - 1)}…`;
  return text;
}

function looksLikeRepoPath(posix: string): boolean {
  if (!posix || posix === '.' || posix.length > 512) return false;
  if (posix.startsWith('/') || posix.startsWith('..') || /^[A-Za-z]:/.test(posix)) return false;
  if (posix.includes('/../') || posix.includes('/./') || posix.endsWith('/..') || posix.endsWith('/.')) return false;
  if (posix.includes('\0') || posix.includes(':')) return false;
  if (/\s/.test(posix) && !posix.includes('/')) return false;
  return warningPathLabel(posix) === posix;
}

/** Repo-relative sample, or undefined when the text is absolute, escaping, or empty. */
function acceptPath(raw: string): string | undefined {
  const posix = raw.split('\\').join('/');
  if (!looksLikeRepoPath(posix)) return undefined;
  const redacted = redactForDisplay(posix);
  if (redacted.startsWith('/') || redacted.startsWith('..') || /^[A-Za-z]:/.test(redacted)) return undefined;
  if (redacted.includes('\0')) return undefined;
  return redacted;
}

/**
 * Split a degrade message into a repo-relative path and the reason class.
 * `path: reason` and the scan forms `path timed out …` / `path skipped — …`
 * yield a path. A sentence that only looks similar stays one reason.
 */
export function splitDegradeMessage(message: string): { path?: string; reason: string } {
  const colon = message.indexOf(': ');
  if (colon > 0) {
    const path = acceptPath(message.slice(0, colon));
    if (path) return { path, reason: message.slice(colon + 2) };
  }
  const leading = LEADING_PATH.exec(message);
  if (leading) {
    const path = acceptPath(leading[1]);
    if (path) return { path, reason: leading[2] };
  }
  return { reason: message };
}

interface WarningGroup {
  code: WarningCode;
  reason: string;
  count: number;
  paths: Set<string>;
  /** Original row, kept only while the group is a single file. */
  single?: CodedWarning;
}

function formatGroup(group: WarningGroup): string {
  if (group.count === 1 && group.single) {
    const message = normalizeReason(group.single.message) || group.single.message;
    return formatWarningLine({ code: group.code, message });
  }
  const paths = [...group.paths].sort(compare);
  const shown = paths.slice(0, HUMAN_WARNING_SAMPLE_CAP);
  const hidden = paths.length - shown.length;
  const noun = group.count === 1 ? 'file' : 'files';
  const reason = group.reason || 'degraded';
  let detail = `${reason} — ${group.count} ${noun}`;
  if (shown.length > 0) {
    const extra = hidden > 0 ? ` (+${hidden} more)` : '';
    detail += `; samples: ${shown.join(', ')}${extra}`;
  }
  return formatWarningLine({ code: group.code, message: detail });
}

/**
 * Human stderr lines. Identical warning code and reason class become one
 * line: the count, and up to {@link HUMAN_WARNING_SAMPLE_CAP} repo-relative
 * sample paths in sorted order. A single file keeps its own sentence.
 * Machine-readable rows are not this list — callers keep every file there.
 */
export function coalesceHumanWarnings(warnings: readonly CodedWarning[]): string[] {
  const groups = new Map<string, WarningGroup>();
  for (const warning of warnings) {
    const split = splitDegradeMessage(warning.message);
    const reason = normalizeReason(split.reason);
    const key = `${warning.code}\0${reason}`;
    let group = groups.get(key);
    if (!group) {
      group = { code: warning.code, reason, count: 0, paths: new Set(), single: warning };
      groups.set(key, group);
    }
    group.count += 1;
    if (group.count > 1) group.single = undefined;
    if (split.path) group.paths.add(split.path);
  }
  return [...groups.values()]
    .sort((a, b) => compare(a.code, b.code) || compare(a.reason, b.reason))
    .map(formatGroup);
}

/**
 * Uncoded warning strings (a cache row from an older build). Identical
 * sentences become one line with a count. One sentence stays `warning: …`.
 */
export function coalescePlainWarnings(lines: readonly string[]): string[] {
  const counts = new Map<string, number>();
  for (const line of lines) {
    const message = normalizeReason(line) || line;
    counts.set(message, (counts.get(message) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => compare(a[0], b[0]))
    .map(([message, count]) => (count === 1 ? `warning: ${message}` : `warning: ${message} — ${count} files`));
}

/** Parser-crash prose with absolute paths and credentials removed. */
export function sanitizeParseFailureReason(err: unknown): string {
  const raw = err instanceof Error && typeof err.message === 'string' ? err.message : '';
  const text = normalizeReason(raw);
  if (!text) return 'the parser stopped unexpectedly';
  return text;
}

/**
 * One `VG_WARN_PARSE_FAILED` row. The path is repo-relative. The reason is
 * the class of failure, not a home directory or a credential.
 */
export function stampedParseFailure(rel: string, err: unknown): string {
  const label = warningPathLabel(rel.split('\\').join('/'));
  const reason = sanitizeParseFailureReason(err);
  return stampWarning(WARNING_CODES.PARSE_FAILED, `${label}: parse failed: ${reason}`);
}

/** True for a failed source parse, including rows written before the path prefix. */
export function isFailedParseWarning(warning: string): boolean {
  return warning.includes('parse failed:');
}

const ANSI = /\u001b\[[0-9;]*m/g;
const WARNING_LINE = /^warning \[(VG_WARN_[A-Z0-9_]+)\]: ([\s\S]*)$/;

/**
 * Buffer `warning [VG_WARN_…]` lines written to stderr while `fn` runs, then
 * print them coalesced. Other stderr is unchanged. JSON and SARIF are written
 * by the scan itself and are not passed through here.
 */
export async function withCoalescedWarningStderr<T>(fn: () => Promise<T>): Promise<T> {
  const originalError = console.error.bind(console);
  const originalLog = console.log.bind(console);
  const warnings: CodedWarning[] = [];
  const flush = (): void => {
    if (warnings.length === 0) return;
    const pending = warnings.splice(0, warnings.length);
    for (const line of coalesceHumanWarnings(pending)) originalError(chalk.yellow(line));
  };
  console.error = (...args: unknown[]) => {
    const text = args.map((part) => (typeof part === 'string' ? part : String(part))).join(' ').replace(ANSI, '');
    const match = WARNING_LINE.exec(text);
    if (match && isWarningCode(match[1])) {
      warnings.push(codedWarning(match[1], match[2]));
      return;
    }
    originalError(...args);
  };
  console.log = (...args: unknown[]) => {
    flush();
    originalLog(...args);
  };
  try {
    return await fn();
  } finally {
    console.error = originalError;
    console.log = originalLog;
    flush();
  }
}

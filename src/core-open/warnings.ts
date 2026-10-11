// VENDORED from @vibgrate/core-open (packages/vibgrate-core-open) by
// scripts/vendor-core-open.mjs. Do not edit here — change the source package
// and re-run the vendor script. Apache-2.0.
import { redactForDisplay } from './utils/redact.js';

/**
 * Stable codes for degrade-and-continue warnings on `vg build`, `vg scan`,
 * `vg report`, and `vg sbom`.
 *
 * A published code keeps its meaning. Add a new entry here for a new
 * condition, then emit it from the call site. Do not reuse or rewrite a
 * code that has shipped. Codes are identifiers only: they never embed a
 * path, a secret, or file contents.
 *
 * A truncated or invalid lockfile stops the command. It is not a warning.
 * A later warn-and-continue lockfile condition adds one entry to this
 * object and one emit site.
 */

export const WARNING_CODES = {
  /** A source file failed to parse. The build continues without its symbols. */
  PARSE_FAILED: 'VG_WARN_PARSE_FAILED',
  /** A file exceeded the per-file size cap and was left out of the map. */
  BUILD_FILE_OVERSIZE: 'VG_WARN_BUILD_FILE_OVERSIZE',
  /** The TypeScript resolver was skipped because the corpus exceeded its file cap. */
  TSC_RESOLVER_SKIPPED: 'VG_WARN_TSC_RESOLVER_SKIPPED',
  /** YAML for an infrastructure file failed to parse. */
  YAML_PARSE_FAILED: 'VG_WARN_YAML_PARSE_FAILED',
  /** A YAML document in a stream had errors and was skipped. */
  YAML_DOCUMENT_SKIPPED: 'VG_WARN_YAML_DOCUMENT_SKIPPED',
  /** A YAML document could not be materialised. */
  YAML_DOCUMENT_UNMATERIALISED: 'VG_WARN_YAML_DOCUMENT_UNMATERIALISED',
  /** An infrastructure extractor threw. That file contributes no structure. */
  TOOLCHAIN_EXTRACTION_FAILED: 'VG_WARN_TOOLCHAIN_EXTRACTION_FAILED',
  /** An extractor stopped at the per-file node cap. */
  TOOLCHAIN_NODE_CAP: 'VG_WARN_TOOLCHAIN_NODE_CAP',
  /** The HCL grammar was unavailable, so no Terraform structure was extracted. */
  HCL_GRAMMAR_UNAVAILABLE: 'VG_WARN_HCL_GRAMMAR_UNAVAILABLE',
  /** HCL parse produced no tree. */
  HCL_NO_TREE: 'VG_WARN_HCL_NO_TREE',
  /** HCL parse recovered from a syntax error. Extraction may be partial. */
  HCL_PARTIAL: 'VG_WARN_HCL_PARTIAL',
  /** A workflow job listed more steps than the extractor enumerates. */
  WORKFLOW_STEP_CAP: 'VG_WARN_WORKFLOW_STEP_CAP',
  /** A scan path timed out and was skipped. */
  SCAN_PATH_SKIPPED: 'VG_WARN_SCAN_PATH_SKIPPED',
  /** A scan file exceeded the size cap and was skipped. */
  SCAN_FILE_OVERSIZE: 'VG_WARN_SCAN_FILE_OVERSIZE',
  /** A baseline file could not be read. The scan continues without a comparison. */
  BASELINE_UNREADABLE: 'VG_WARN_BASELINE_UNREADABLE',
  /** A declared license string could not be resolved to SPDX. */
  LICENSE_UNPARSEABLE: 'VG_WARN_LICENSE_UNPARSEABLE',
  /** A declared license cannot be represented in an SBOM. */
  LICENSE_UNREPRESENTABLE: 'VG_WARN_LICENSE_UNREPRESENTABLE',
  /** A CVSS vector was present and could not be parsed. */
  CVSS_UNPARSEABLE: 'VG_WARN_CVSS_UNPARSEABLE',
  /** A package URL could not be formed. The component is included without a purl. */
  PURL_UNAVAILABLE: 'VG_WARN_PURL_UNAVAILABLE',
  /** Root package.json omitted name, version, or both. The root component keeps a directory-name fallback. */
  ROOT_PACKAGE_IDENTITY: 'VG_WARN_ROOT_PACKAGE_IDENTITY',
  /** SBOM merge dropped a different dependency list for one package. */
  SBOM_LOSSY_EDGES: 'VG_WARN_SBOM_LOSSY_EDGES',
  /** SBOM merge dropped differing manifest metadata for one package. */
  SBOM_LOSSY_MANIFEST: 'VG_WARN_SBOM_LOSSY_MANIFEST',
  /** SBOM merge recorded an unknown ecosystem as npm. */
  SBOM_UNKNOWN_ECOSYSTEM: 'VG_WARN_SBOM_UNKNOWN_ECOSYSTEM',
  /** A lockfile format does not record dependency edges. */
  SBOM_UNTRACKED_EDGES: 'VG_WARN_SBOM_UNTRACKED_EDGES',
} as const;

export type WarningCode = (typeof WARNING_CODES)[keyof typeof WARNING_CODES];

export interface CodedWarning {
  code: WarningCode;
  /** Human prose. The code lives in {@link CodedWarning.code}, not in this string. */
  message: string;
}

const CODE_LIST: readonly WarningCode[] = Object.values(WARNING_CODES);
const CODE_SET: ReadonlySet<string> = new Set(CODE_LIST);

/** Every published code, in registry order. */
export function warningCodeList(): readonly WarningCode[] {
  return CODE_LIST;
}

export function isWarningCode(value: unknown): value is WarningCode {
  return typeof value === 'string' && CODE_SET.has(value);
}

export function codedWarning(code: WarningCode, message: string): CodedWarning {
  return { code, message };
}

/**
 * Human line. The code is a stable token at the front so a search for
 * `VG_WARN_` does not depend on the prose.
 */
export function formatWarningLine(warning: CodedWarning): string {
  return `warning [${warning.code}]: ${warning.message}`;
}

/**
 * Store a code on a string channel that already carries prose.
 * The prose stays a prefix so existing substring checks still match.
 */
export function stampWarning(code: WarningCode, message: string): string {
  return `${message} [${code}]`;
}

const STAMP_RE = / \[VG_WARN_[A-Z0-9_]+\]$/;

/** Split a stamped string. Returns undefined when the line has no known code. */
export function splitStampedWarning(stored: string): CodedWarning | undefined {
  const match = STAMP_RE.exec(stored);
  if (!match) return undefined;
  const code = match[0].slice(2, -1);
  if (!isWarningCode(code)) return undefined;
  return { code, message: stored.slice(0, match.index) };
}

/**
 * Order by code, then by message. Equal pairs keep their input order
 * (the runtime sort is stable).
 */
export function sortCodedWarnings(warnings: readonly CodedWarning[]): CodedWarning[] {
  return [...warnings].sort((a, b) => a.code.localeCompare(b.code) || a.message.localeCompare(b.message));
}

/**
 * Path text safe to put in a warning message: a repo-relative path, or the
 * file name when the path would leave the repo or is absolute. Never file
 * contents.
 */
export function warningPathLabel(rel: string): string {
  const posix = rel.split('\\').join('/');
  if (posix.startsWith('/') || /^[A-Za-z]:/.test(posix) || posix.startsWith('..') || posix === '') {
    const base = posix.split('/').pop();
    return base && base.length > 0 ? base : 'path';
  }
  return posix;
}

export function findingWarningCode(details: unknown): WarningCode | undefined {
  if (!details || typeof details !== 'object') return undefined;
  const record = details as { warnCode?: unknown; cvssDiagnostic?: { warnCode?: unknown } | null };
  if (isWarningCode(record.warnCode)) return record.warnCode;
  const nested = record.cvssDiagnostic?.warnCode;
  if (isWarningCode(nested)) return nested;
  return undefined;
}

/** Rule id for a text or markdown row, with the warning code when one is set. */
export function findingRuleLabel(ruleId: string, details: unknown): string {
  const code = findingWarningCode(details);
  return code ? `${ruleId} [${code}]` : ruleId;
}

/**
 * How many repo-relative paths one coalesced human warning lists.
 * Further paths are a `+N more` suffix. The list is sorted before the cap,
 * so the same warnings always name the same paths.
 */
export const WARNING_SAMPLE_CAP = 5;

const DETAIL_MAX = 240;

/** A stored parse-failure warning, including text written before the path prefix. */
export function isParseFailureWarning(stored: string): boolean {
  return stored.includes(`[${WARNING_CODES.PARSE_FAILED}]`) || stored.includes('parse failed:');
}

/**
 * One line of parser detail safe to store and print. Absolute paths, file
 * URLs, and credential-shaped text are removed. The result is deterministic.
 */
export function warningErrorDetail(err: unknown): string {
  const raw = err instanceof Error && err.message
    ? err.message
    : typeof err === 'string'
      ? err
      : '';
  const line = scrubPathsAndSecrets(raw).replace(/^parse failed:\s*/i, '').trim();
  if (!line) return 'the file could not be parsed';
  return line.length > DETAIL_MAX ? `${line.slice(0, DETAIL_MAX - 1)}…` : line;
}

/** `rel: parse failed: …`, stamped with {@link WARNING_CODES.PARSE_FAILED}. */
export function parseFailedWarning(rel: string, err: unknown): string {
  return stampWarning(
    WARNING_CODES.PARSE_FAILED,
    `${warningPathLabel(rel)}: parse failed: ${warningErrorDetail(err)}`,
  );
}

/**
 * Human lines for degrade-and-continue warnings.
 *
 * Rows that share a warning code and a reason class (the sentence after the
 * repo-relative path, with counts and byte sizes treated as the same slot)
 * become one line: the reason, the count, and up to `sampleCap` paths. A
 * warning that stands alone keeps {@link formatWarningLine}. Input order does
 * not matter. This does not drop or reorder machine-readable rows — callers
 * keep passing the full list to JSON and SARIF.
 */
export function formatCoalescedWarningLines(
  warnings: readonly CodedWarning[],
  sampleCap = WARNING_SAMPLE_CAP,
): string[] {
  return formatGroups(warnings.map((warning) => ({ code: warning.code, message: warning.message })), sampleCap);
}

/**
 * Human lines for warning prose that has no code. Identical reasons collapse
 * the same way as {@link formatCoalescedWarningLines}. One warning stays
 * `warning: <message>`.
 */
export function formatCoalescedPlainLines(lines: readonly string[], sampleCap = WARNING_SAMPLE_CAP): string[] {
  return formatGroups(lines.map((message) => ({ message })), sampleCap);
}

/**
 * Human degradation lines for a text or markdown report.
 * JSON keeps every row on `degradations`; this view coalesces them.
 */
export function formatDegradationLines(degradations: readonly CodedWarning[] | undefined): string[] {
  if (!degradations || degradations.length === 0) return [];
  return formatCoalescedWarningLines(degradations);
}

interface WarningPiece {
  code?: WarningCode;
  message: string;
}

interface WarningGroup {
  code?: WarningCode;
  leadMessage: string;
  reasons: string[];
  paths: string[];
  only?: WarningPiece;
}

function formatGroups(pieces: readonly WarningPiece[], sampleCap: number): string[] {
  const cap = Number.isFinite(sampleCap) && sampleCap > 0 ? Math.floor(sampleCap) : 0;
  const groups = new Map<string, WarningGroup>();
  for (const piece of pieces) {
    const subject = splitWarningSubject(piece.message);
    const classKey = reasonClass(subject.reason);
    const id = `${piece.code ?? ''}\0${classKey}`;
    let group = groups.get(id);
    if (!group) {
      group = {
        code: piece.code,
        leadMessage: piece.message,
        reasons: [],
        paths: [],
        only: piece,
      };
      groups.set(id, group);
    }
    group.reasons.push(subject.reason);
    if (subject.path) group.paths.push(subject.path);
    if (compareText(piece.message, group.leadMessage) < 0) group.leadMessage = piece.message;
    if (group.reasons.length > 1) group.only = undefined;
  }

  const ordered = [...groups.values()].sort(
    (a, b) => compareText(a.code ?? '', b.code ?? '') || compareText(a.leadMessage, b.leadMessage),
  );

  return ordered.map((group) => renderGroup(group, cap));
}

function renderGroup(group: WarningGroup, cap: number): string {
  if (group.only) {
    return group.only.code ? formatWarningLine({ code: group.only.code, message: group.only.message }) : `warning: ${group.only.message}`;
  }
  const count = group.reasons.length;
  const reason = displayReason(group.reasons);
  const unique = uniqueSorted(group.paths);
  const head = group.code ? `warning [${group.code}]: ${reason}` : `warning: ${reason}`;
  if (unique.length === 0 || cap === 0) return `${head} (×${count})`;
  const shown = unique.slice(0, cap);
  const extra = unique.length - shown.length;
  const list = extra > 0 ? `${shown.join(', ')}, +${extra} more` : shown.join(', ');
  const noun = unique.length === count ? (count === 1 ? 'file' : 'files') : (count === 1 ? 'warning' : 'warnings');
  return `${head} (${count} ${noun}: ${list})`;
}

/** Code-point order. Independent of the process locale. */
function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function uniqueSorted(paths: readonly string[]): string[] {
  return [...new Set(paths)].sort(compareText);
}

const LEADING_PATH = /^(\S+): (.+)$/;
const SCAN_TIMEOUT = /^(\S+) (timed out \(>[^)]*\) and was skipped)$/;
const SCAN_OVERSIZE = /^(\S+) (skipped — .+)$/;

function splitWarningSubject(message: string): { path?: string; reason: string } {
  const lead = LEADING_PATH.exec(message);
  if (lead?.[1] && lead[2] && isPathToken(lead[1])) {
    return subjectFromPath(lead[1], lead[2]);
  }
  // Scan sentences put the path first with no colon: `dir timed out …`,
  // `file.bin skipped — …`. A single path segment is still repo-relative.
  for (const pattern of [SCAN_TIMEOUT, SCAN_OVERSIZE]) {
    const match = pattern.exec(message);
    if (!match?.[1] || !match[2]) continue;
    if (match[1].includes('://') || /\s/.test(match[1])) continue;
    return subjectFromPath(match[1], match[2]);
  }
  return { reason: scrubPathsAndSecrets(message) };
}

function subjectFromPath(token: string, reason: string): { path?: string; reason: string } {
  const path = samplePath(token);
  return { ...(path ? { path } : {}), reason: scrubPathsAndSecrets(reason) };
}

function isPathToken(token: string): boolean {
  const posix = token.split('\\').join('/');
  if (!posix || posix.length > 300 || /\s/.test(posix) || posix.includes('://')) return false;
  if (posix.startsWith('/') || /^[A-Za-z]:/.test(posix)) return true;
  if (posix === '..' || posix.startsWith('../') || posix.split('/').includes('..')) return false;
  if (posix.includes('/') || posix.includes('.')) return true;
  return /^(?:Dockerfile|Makefile|Jenkinsfile|Containerfile|Gemfile|Rakefile|Procfile|Justfile)$/.test(posix);
}

function samplePath(token: string): string | undefined {
  const label = warningPathLabel(token.split('\\').join('/'));
  if (!label || label.startsWith('/') || label.startsWith('..') || /^[A-Za-z]:/.test(label)) return undefined;
  if (label.split('/').includes('..')) return undefined;
  return label;
}

const SLOT_SOURCE = String.raw`\d+(?:\.\d+)?\s*(?:[KMGT]iB|[KMGT]B|B)\b|\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?`;

function reasonClass(reason: string): string {
  return reason.replace(new RegExp(SLOT_SOURCE, 'g'), '#').replace(/\s+/g, ' ').trim();
}

function displayReason(reasons: readonly string[]): string {
  const sorted = [...reasons].sort(compareText);
  const first = sorted[0] ?? '';
  if (sorted.every((reason) => reason === first)) return first;
  const key = reasonClass(first);
  const columns = sorted.map((reason) => reason.match(new RegExp(SLOT_SOURCE, 'g')) ?? []);
  const width = columns[0]?.length ?? 0;
  if (!columns.every((column) => column.length === width)) return key;
  let index = 0;
  return key.replace(/#/g, () => {
    const values = columns.map((column) => column[index] ?? '#');
    index += 1;
    return values.every((value) => value === values[0]) ? values[0]! : '#';
  });
}

/** Drop home directories, file URLs, and credential-shaped text. Deterministic. */
function scrubPathsAndSecrets(text: string): string {
  let line = redactForDisplay(text).replace(/\s+/g, ' ').trim();
  line = line.replace(/file:\/\/\S+/g, 'a file');
  line = line.replace(/(?:[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]+)|(?:\/(?:[\w.+@~-]+\/)+[\w.+@~-]+)/g, 'a file');
  line = line.replace(/~\/\S+/g, 'a file');
  return line.trim();
}

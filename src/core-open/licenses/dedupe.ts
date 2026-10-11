// VENDORED from @vibgrate/core-open (packages/vibgrate-core-open) by
// scripts/vendor-core-open.mjs. Do not edit here — change the source package
// and re-run the vendor script. Apache-2.0.
/**
 * Equality for a license finding, and the dedupe applied before JSON, human,
 * and SARIF emit.
 *
 * Two findings are the same finding when all three of these match:
 *
 *   1. Component key — the package name carried on the finding.
 *   2. License id — the canonical SPDX id or `LicenseRef-…` when the
 *      declaration resolves to one. A compound expression stays that
 *      expression, so `MIT OR Apache-2.0` is not `MIT`. A declaration that
 *      does not resolve keeps its declared text, so two different failures
 *      stay two rows.
 *   3. Source path — the manifest or license file the scan recorded, or the
 *      project path when it recorded none.
 *
 * A different license id or a different path is a different finding.
 * Callers sort with {@link compareLicenseFindings} first. Dedupe then keeps
 * the first row for each key and does not reorder anything else.
 */
import { normalizeLicenseSourcePath } from './dependency-license.js';
import { declaredLicenseSnippet, LICENSE_PARSE_FAILED } from './diagnostic.js';
import { isExplicitUnknownLicense, normalizeLicense } from './normalize.js';

/** Fields the equality key reads. Structural so report types can share it. */
export interface LicenseFindingShape {
  ruleId: string;
  message: string;
  location: string;
  details?: Record<string, unknown> | null;
}

const COMPONENT_MARK = ' for ';

/**
 * Canonical license id for equality.
 *
 * An exact id, an alias (`mit`, `Apache2`), and a `LicenseRef-…` all become
 * that id. An expression becomes the normalized expression. Anything else
 * stays the declared text.
 */
export function licenseFindingId(raw: string | null | undefined): string {
  const shown = declaredLicenseSnippet(raw ?? '');
  if (!shown || isExplicitUnknownLicense(shown)) return shown;
  const verdict = normalizeLicense(shown);
  if (verdict.matchStatus === 'unknown') return shown;
  // One expression is one id. `MIT OR Apache-2.0` does not collapse into MIT,
  // and `MIT OR LicenseRef-Acme` does not collapse into either constituent.
  if (verdict.matchStatus === 'expression') return verdict.expression;
  return verdict.spdxId;
}

/**
 * Package name from a license-parse finding message.
 * The message names the package between `for ` and ` at <path>`.
 * When the message has no package, the whole message is the key, so two
 * different sentences are not treated as one component.
 */
export function licenseComponentKey(finding: Pick<LicenseFindingShape, 'message' | 'location'>): string {
  const marker = ` at ${finding.location}. `;
  const at = finding.message.lastIndexOf(marker);
  if (at === -1) return finding.message;
  const forAt = finding.message.lastIndexOf(COMPONENT_MARK, at);
  if (forAt === -1) return finding.message;
  return finding.message.slice(forAt + COMPONENT_MARK.length, at);
}

/** Source path used for equality. Forward slashes, no `./` prefix. */
export function licenseFindingSourcePath(finding: Pick<LicenseFindingShape, 'location' | 'details'>): string {
  const recorded = finding.details?.sourcePath;
  const candidate = typeof recorded === 'string' && recorded.length > 0 ? recorded : finding.location;
  return normalizeLicenseSourcePath(candidate) ?? candidate;
}

/**
 * Component key, license id, and source path joined by a NUL. Null when
 * `finding` is not a license finding.
 */
export function licenseFindingEqualityKey(finding: LicenseFindingShape): string | null {
  if (finding.ruleId !== LICENSE_PARSE_FAILED) return null;
  const raw = typeof finding.details?.raw === 'string' ? finding.details.raw : '';
  return [licenseComponentKey(finding), licenseFindingId(raw), licenseFindingSourcePath(finding)].join('\0');
}

/** Stable order for license findings: component, license id, source path, message. */
export function compareLicenseFindings(a: LicenseFindingShape, b: LicenseFindingShape): number {
  const rawA = typeof a.details?.raw === 'string' ? a.details.raw : '';
  const rawB = typeof b.details?.raw === 'string' ? b.details.raw : '';
  return (
    licenseComponentKey(a).localeCompare(licenseComponentKey(b)) ||
    licenseFindingId(rawA).localeCompare(licenseFindingId(rawB)) ||
    licenseFindingSourcePath(a).localeCompare(licenseFindingSourcePath(b)) ||
    a.message.localeCompare(b.message)
  );
}

/**
 * Drop later license findings that repeat an earlier component + license id +
 * path. Other findings stay put, in their original order. The same input
 * always returns the same list. When nothing is repeated, the same array is
 * returned.
 */
export function dedupeLicenseFindings<T extends LicenseFindingShape>(findings: readonly T[]): T[] {
  const seen = new Set<string>();
  let dropped = false;
  const out: T[] = [];
  for (const finding of findings) {
    const key = licenseFindingEqualityKey(finding);
    if (key === null) {
      out.push(finding);
      continue;
    }
    if (seen.has(key)) {
      dropped = true;
      continue;
    }
    seen.add(key);
    out.push(finding);
  }
  return dropped ? out : (findings as T[]);
}

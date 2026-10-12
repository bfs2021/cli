/**
 * Collapse identical license findings before text, JSON, and SARIF output.
 *
 * Equality key: component identity + license id + source path.
 * Component identity is the scan coordinate: project type, package name, and
 * resolved version (a missing version stays empty — it is not zero).
 * The license id is the SPDX id or LicenseRef when the declaration is one of
 * those; an alias uses the canonical SPDX id. Anything else, including an
 * expression and an unresolved string, stays the declared text, so a different
 * id stays a different finding. The source path is the recorded path, or the
 * finding location when none was recorded.
 *
 * The first finding in the existing order is kept. Other findings stay put.
 * The same inputs always keep the same rows.
 */

import type { Finding } from '../types.js';
import { LICENSE_PARSE_FAILED } from './diagnostic.js';
import { isSpdxLicenseRef, normalizeLicense } from './normalize.js';
import { isCompoundExpression } from './spdx-expression.js';

const FINDING_TAIL =
  '. Replace it with a canonical SPDX id or expression, or NOASSERTION if the license is intentionally unknown.';
const FINDING_HEAD = 'Could not resolve SPDX license "';

/**
 * Keys are not part of the finding document. A copy made for output does not
 * carry them; dedupe runs on the original objects before that copy.
 */
const findingKeys = new WeakMap<Finding, string>();

export interface LicenseFindingIdentity {
  projectType: string;
  packageName: string;
  resolvedVersion: string | null | undefined;
  licenseRaw: string | null | undefined;
  sourcePath: string;
}

/** SPDX id, LicenseRef, or the declared text. Same input, same id. */
export function licenseIdForEquality(raw: string | null | undefined): string {
  const declared = (raw ?? '').trim();
  if (declared.length === 0) return '';
  // A LicenseRef is checked before compound detection: a hyphen is a word
  // boundary, so `LicenseRef-OR-1.0` would otherwise look like an OR expression.
  if (isSpdxLicenseRef(declared)) return declared;
  if (isCompoundExpression(declared)) return declared;
  const verdict = normalizeLicense(declared);
  if (
    (verdict.matchStatus === 'exact' || verdict.matchStatus === 'alias') &&
    verdict.spdxId !== 'NOASSERTION'
  ) {
    return verdict.spdxId;
  }
  if (isSpdxLicenseRef(verdict.spdxId)) return verdict.spdxId;
  return declared;
}

/** Stable equality key. A missing version is an empty slot, not `"0"`. */
export function licenseFindingEqualityKey(input: LicenseFindingIdentity): string {
  const version = input.resolvedVersion ?? '';
  return [
    input.projectType,
    input.packageName,
    version,
    licenseIdForEquality(input.licenseRaw),
    input.sourcePath,
  ].join('\0');
}

export function setLicenseFindingKey(finding: Finding, key: string): void {
  findingKeys.set(finding, key);
}

/**
 * Package name from a license-parse message, or `''` when the message names
 * no package. `null` when the message is not that shape.
 * The location is taken from the finding, so a license string that itself
 * contains `for` or `at` does not steal the package name.
 */
export function componentNameFromLicenseFinding(finding: Finding): string | null {
  const message = finding.message;
  if (!message.startsWith(FINDING_HEAD) || !message.endsWith(FINDING_TAIL)) return null;
  const body = message.slice(FINDING_HEAD.length, message.length - FINDING_TAIL.length);
  const atLocation = ` at ${finding.location}`;
  if (!body.endsWith(atLocation)) return null;
  const mid = body.slice(0, body.length - atLocation.length);
  if (mid.endsWith('"')) return '';
  const marker = '" for ';
  const idx = mid.lastIndexOf(marker);
  if (idx === -1) return null;
  const name = mid.slice(idx + marker.length);
  return name.length > 0 ? name : null;
}

function sourcePathOf(finding: Finding): string {
  const recorded = finding.details?.sourcePath;
  if (typeof recorded === 'string' && recorded.length > 0) return recorded;
  return finding.location;
}

function derivedLicenseFindingKey(finding: Finding): string {
  const raw = typeof finding.details?.raw === 'string' ? finding.details.raw : '';
  const component = componentNameFromLicenseFinding(finding);
  // No stored coordinate: the package name in the message is the component.
  // A message we cannot parse stays distinct unless the whole message matches.
  const packageName = component === null ? `\u0001${finding.message}` : component;
  return licenseFindingEqualityKey({
    projectType: '',
    packageName,
    resolvedVersion: null,
    licenseRaw: raw,
    sourcePath: sourcePathOf(finding),
  });
}

function readLicenseFindingKey(finding: Finding): string | null {
  if (finding.ruleId !== LICENSE_PARSE_FAILED) return null;
  return findingKeys.get(finding) ?? derivedLicenseFindingKey(finding);
}

/**
 * Drop license findings whose equality key was already kept.
 * Walks the list once and does not reorder it.
 */
export function dedupeLicenseFindings(findings: readonly Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const finding of findings) {
    const key = readLicenseFindingKey(finding);
    if (key === null) {
      out.push(finding);
      continue;
    }
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(finding);
  }
  return out;
}

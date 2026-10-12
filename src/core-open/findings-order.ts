// VENDORED from @vibgrate/core-open (packages/vibgrate-core-open) by
// scripts/vendor-core-open.mjs. Do not edit here — change the source package
// and re-run the vendor script. Apache-2.0.
import type { Finding, ScanArtifact, SecurityFinding, VulnerabilityAdvisory } from './types.js';

/**
 * Stable order for `vg scan` JSON findings.
 *
 * Discovery walks the tree concurrently, so project and file order is not a
 * safe emit order. JSON sorts by path (`location`), then rule id, then
 * advisory id, then package URL. Code-unit order, not locale order, so two
 * machines agree. `via` and `fixedVersions` stay in their semantic order:
 * one is a dependency path, the other is the advisory's fix list.
 */

/** Code-unit order. Locale-independent, unlike `localeCompare`. */
function cmp(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function sortStrings(values: readonly string[]): string[] {
  return [...values].sort(cmp);
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

/** Package URL used as a sort key. An explicit `details.purl` wins. */
export function findingPackagePurl(finding: Finding): string {
  const details = finding.details;
  if (!details) return '';
  const explicit = asString(details.purl);
  if (explicit) return explicit;
  const name = asString(details.package);
  if (!name) return '';
  const ecosystem = asString(details.ecosystem) || 'generic';
  const version = asString(details.installedVersion) || asString(details.version);
  return version ? `pkg:${ecosystem}/${name}@${version}` : `pkg:${ecosystem}/${name}`;
}

function advisoryId(finding: Finding): string {
  return asString(finding.details?.advisoryId);
}

/**
 * JSON order: path, rule id, advisory id, package URL, then message and level
 * so two findings with the same identity still have one order.
 */
export function compareScanFindings(a: Finding, b: Finding): number {
  return cmp(a.location, b.location)
    || cmp(a.ruleId, b.ruleId)
    || cmp(advisoryId(a), advisoryId(b))
    || cmp(findingPackagePurl(a), findingPackagePurl(b))
    || cmp(a.message, b.message)
    || cmp(a.level, b.level);
}

const DISPLAY_LEVEL: Record<Finding['level'], number> = { error: 0, warning: 1, note: 2 };

/**
 * Text-report order. Errors, then warnings, then notes, and within a level
 * the same key as JSON. The terminal stays scannable; JSON stays path-ordered.
 */
export function compareFindingsForDisplay(a: Finding, b: Finding): number {
  return (DISPLAY_LEVEL[a.level] - DISPLAY_LEVEL[b.level]) || compareScanFindings(a, b);
}

export function findingsForDisplay(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(compareFindingsForDisplay);
}

/** Identifier lists copied off a set or an unordered advisory payload. */
function orderDetails(details: Finding['details']): Finding['details'] {
  if (!details || !Array.isArray(details.aliases) || details.aliases.some((item) => typeof item !== 'string')) {
    return details;
  }
  const aliases = sortStrings(details.aliases as string[]);
  if (sameStrings(aliases, details.aliases as string[])) return details;
  return { ...details, aliases };
}

function orderFinding(finding: Finding): Finding {
  const details = orderDetails(finding.details);
  if (details === finding.details) return finding;
  return { ...finding, details };
}

export function orderScanFindings(findings: readonly Finding[]): Finding[] {
  return findings.map(orderFinding).sort(compareScanFindings);
}

function orderAdvisory(advisory: VulnerabilityAdvisory): VulnerabilityAdvisory {
  if (!Array.isArray(advisory.aliases)) return advisory;
  const aliases = sortStrings(advisory.aliases.filter((item): item is string => typeof item === 'string'));
  if (sameStrings(aliases, advisory.aliases)) return advisory;
  return { ...advisory, aliases };
}

function orderSecurityFinding(finding: SecurityFinding): SecurityFinding {
  const owasp = finding.owasp ? sortStrings(finding.owasp) : undefined;
  const cwe = finding.cwe ? sortStrings(finding.cwe) : undefined;
  const cis = finding.cis ? sortStrings(finding.cis) : undefined;
  const owaspSame = !owasp || (finding.owasp && sameStrings(owasp, finding.owasp));
  const cweSame = !cwe || (finding.cwe && sameStrings(cwe, finding.cwe));
  const cisSame = !cis || (finding.cis && sameStrings(cis, finding.cis));
  if (owaspSame && cweSame && cisSame) return finding;
  return {
    ...finding,
    ...(owasp ? { owasp } : {}),
    ...(cwe ? { cwe } : {}),
    ...(cis ? { cis } : {}),
  };
}

/**
 * Sort findings, and the identifier lists nested on them, before JSON emit.
 * Security findings keep their path/line/rule order; only their set-like
 * identifier lists are sorted. Dependency paths (`via`) are left alone.
 */
export function orderScanArtifactForEmit(artifact: ScanArtifact): ScanArtifact {
  const findings = orderScanFindings(artifact.findings ?? []);
  const extended = artifact.extended;
  let nextExtended = extended;
  if (extended?.vulnerabilities) {
    nextExtended = {
      ...extended,
      vulnerabilities: {
        ...extended.vulnerabilities,
        packages: extended.vulnerabilities.packages.map((pkg) => ({
          ...pkg,
          advisories: pkg.advisories.map(orderAdvisory),
        })),
      },
    };
  }
  if (nextExtended?.security) {
    nextExtended = {
      ...nextExtended,
      security: {
        ...nextExtended.security,
        findings: nextExtended.security.findings.map(orderSecurityFinding),
      },
    };
  }
  return {
    ...artifact,
    findings,
    ...(nextExtended ? { extended: nextExtended } : {}),
  };
}

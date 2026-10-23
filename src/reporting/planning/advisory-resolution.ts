import type { AppliedUpgrade } from './apply.js';
import type { PlannedAdvisoryRef, PlannedUpgrade, PlannedUpgradeBlock } from './types.js';

/**
 * Why an upgrade did not land, so the advisory it would have cleared stays open.
 * An advisory is resolved only when every attempt for it landed on a published fix.
 */
export type UpgradeBlockReason = PlannedUpgradeBlock | 'install-failed';

export interface AdvisoryUpgradeAttempt {
  advisoryId: string;
  /** Published fix. Null or empty means there is no version that clears it. */
  fixedVersion: string | null;
  /** Null only when this attempt installed a version at or beyond {@link fixedVersion}. */
  block: UpgradeBlockReason | null;
}

/** Advisory ids whose upgrade actually landed. A block always keeps the id open. */
export function resolvedAdvisoryIds(attempts: AdvisoryUpgradeAttempt[]): string[] {
  const byId = new Map<string, AdvisoryUpgradeAttempt[]>();
  for (const attempt of attempts) {
    const rows = byId.get(attempt.advisoryId) ?? [];
    rows.push(attempt);
    byId.set(attempt.advisoryId, rows);
  }
  const resolved: string[] = [];
  for (const [id, rows] of byId) {
    const cleared = rows.every((row) => row.block === null && hasFixedVersion(row.fixedVersion));
    if (cleared) resolved.push(id);
  }
  return resolved.sort((a, b) => a.localeCompare(b));
}

function hasFixedVersion(version: string | null): boolean {
  return version != null && version !== '';
}

/**
 * Classify why an upgrade did not land. A landed install (`applied`) returns
 * null — the per-advisory fixed version is checked separately, so a successful
 * install of a release that is still affected is not treated as a resolution.
 */
export function blockFor(upgrade: PlannedUpgrade, result: AppliedUpgrade | undefined): UpgradeBlockReason | null {
  if (upgrade.block === 'policy' || upgrade.block === 'peer' || upgrade.block === 'no-fixed-version') {
    return upgrade.block;
  }
  if (!upgrade.to) return 'no-fixed-version';
  if (!result || result.status !== 'applied') {
    const detail = (result?.detail ?? '').toLowerCase();
    if (detail.includes('policy')) return 'policy';
    if (detail.includes('peer')) return 'peer';
    if (detail.includes('no target') || detail.includes('no fixed')) return 'no-fixed-version';
    return 'install-failed';
  }
  return null;
}

/** One attempt per advisory the planner attached to an upgrade in this apply. */
export function attemptsForApply(upgrades: PlannedUpgrade[], results: AppliedUpgrade[]): AdvisoryUpgradeAttempt[] {
  const byPackage = new Map(results.map((result) => [result.package, result]));
  const attempts: AdvisoryUpgradeAttempt[] = [];
  for (const upgrade of upgrades) {
    const block = blockFor(upgrade, byPackage.get(upgrade.package));
    for (const advisory of upgrade.advisories ?? []) {
      attempts.push(attemptFor(advisory, block));
    }
  }
  return attempts;
}

function attemptFor(advisory: PlannedAdvisoryRef, upgradeBlock: UpgradeBlockReason | null): AdvisoryUpgradeAttempt {
  const block = upgradeBlock ?? (hasFixedVersion(advisory.fixedVersion) ? null : 'no-fixed-version');
  return { advisoryId: advisory.id, fixedVersion: advisory.fixedVersion, block };
}

function openReason(block: UpgradeBlockReason | null): string {
  switch (block) {
    case 'policy':
      return 'upgrade blocked by policy';
    case 'peer':
      return 'upgrade blocked by a peer conflict';
    case 'no-fixed-version':
      return 'no fixed version';
    case 'install-failed':
      return 'upgrade install failed';
    default:
      return 'upgrade did not land';
  }
}

/**
 * Lines `vg fix` prints after an apply. Resolved ids are only those
 * {@link resolvedAdvisoryIds} returns — a blocked upgrade is never in that list.
 */
export function formatAdvisoryResolution(attempts: AdvisoryUpgradeAttempt[]): string[] {
  if (attempts.length === 0) return [];
  const resolved = resolvedAdvisoryIds(attempts);
  const resolvedSet = new Set(resolved);
  const lines: string[] = [];
  if (resolved.length > 0) lines.push(`Advisories resolved: ${resolved.join(', ')}`);
  const open = attempts
    .filter((attempt) => !resolvedSet.has(attempt.advisoryId))
    .sort((a, b) => a.advisoryId.localeCompare(b.advisoryId) || String(a.block).localeCompare(String(b.block)));
  for (const attempt of open) {
    lines.push(`Advisory ${attempt.advisoryId} stayed open — ${openReason(attempt.block)}`);
  }
  return lines;
}

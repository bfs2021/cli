import { describe, expect, it } from 'vitest';
import {
  attemptsForApply,
  blockFor,
  formatAdvisoryResolution,
  resolvedAdvisoryIds,
  type AdvisoryUpgradeAttempt,
} from './advisory-resolution.js';
import type { AppliedUpgrade } from './apply.js';
import type { PlannedUpgrade, VulnDelta } from './types.js';

function emptyDelta(): VulnDelta {
  return { total: 0, bySeverity: { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 } };
}

function upgrade(over: Partial<PlannedUpgrade> = {}): PlannedUpgrade {
  return {
    package: 'lodash',
    ecosystem: 'npm',
    from: '4.17.20',
    to: '4.17.21',
    kind: 'patch',
    blastRadius: 'low',
    fixes: { ...emptyDelta(), total: 1, bySeverity: { ...emptyDelta().bySeverity, high: 1 } },
    reason: 'remediates GHSA-lodash',
    advisories: [{ id: 'GHSA-lodash', fixedVersion: '4.17.21' }],
    ...over,
  };
}

function applied(over: Partial<AppliedUpgrade> = {}): AppliedUpgrade {
  return { package: 'lodash', to: '4.17.21', status: 'applied', ...over };
}

describe('resolvedAdvisoryIds', () => {
  const blocked: Array<[AdvisoryUpgradeAttempt['block'], string]> = [
    ['policy', 'blocked by policy'],
    ['peer', 'peer conflict'],
    ['no-fixed-version', 'no fixed version'],
    ['install-failed', 'failed install'],
  ];

  it.each(blocked)('never marks an advisory resolved when the upgrade is %s (%s)', (block) => {
    const attempts: AdvisoryUpgradeAttempt[] = [
      { advisoryId: 'GHSA-lodash', fixedVersion: '4.17.21', block },
    ];
    expect(resolvedAdvisoryIds(attempts)).toEqual([]);
    const lines = formatAdvisoryResolution(attempts);
    expect(lines.join('\n')).not.toMatch(/Advisories resolved:/);
    expect(lines.join('\n')).toContain('GHSA-lodash stayed open');
  });

  it('marks an advisory resolved only when the install landed on a published fix', () => {
    expect(
      resolvedAdvisoryIds([{ advisoryId: 'GHSA-lodash', fixedVersion: '4.17.21', block: null }]),
    ).toEqual(['GHSA-lodash']);
  });

  it('keeps the advisory open when one attempt landed and another was blocked', () => {
    expect(
      resolvedAdvisoryIds([
        { advisoryId: 'GHSA-lodash', fixedVersion: '4.17.21', block: null },
        { advisoryId: 'GHSA-lodash', fixedVersion: '4.17.21', block: 'peer' },
      ]),
    ).toEqual([]);
  });

  it('does not treat a landed install as a resolution when no fixed version exists', () => {
    expect(
      resolvedAdvisoryIds([{ advisoryId: 'GHSA-open', fixedVersion: null, block: null }]),
    ).toEqual([]);
  });
});

describe('blockFor', () => {
  it('reads a planner block before the apply result', () => {
    expect(blockFor(upgrade({ block: 'policy' }), applied())).toBe('policy');
    expect(blockFor(upgrade({ block: 'peer' }), applied())).toBe('peer');
    expect(blockFor(upgrade({ block: 'no-fixed-version' }), applied())).toBe('no-fixed-version');
  });

  it('classifies a failed install, including policy and peer wording from the package manager', () => {
    expect(blockFor(upgrade(), { package: 'lodash', to: '4.17.21', status: 'failed', detail: 'exit 1' })).toBe('install-failed');
    expect(blockFor(upgrade(), { package: 'lodash', to: '4.17.21', status: 'failed', detail: 'blocked by policy' })).toBe('policy');
    expect(blockFor(upgrade(), { package: 'lodash', to: '4.17.21', status: 'failed', detail: 'peer conflict: ERESOLVE' })).toBe('peer');
  });

  it('treats a missing target version as no fixed version', () => {
    expect(blockFor(upgrade({ to: null }), undefined)).toBe('no-fixed-version');
  });

  it('returns null only for an applied upgrade', () => {
    expect(blockFor(upgrade(), applied())).toBeNull();
  });
});

describe('attemptsForApply', () => {
  it('keeps a blocked upgrade out of the resolved set', () => {
    const lines = formatAdvisoryResolution(
      attemptsForApply(
        [upgrade()],
        [{ package: 'lodash', to: '4.17.21', status: 'failed', detail: 'blocked by policy' }],
      ),
    );
    expect(lines).toEqual(['Advisory GHSA-lodash stayed open — upgrade blocked by policy']);
  });

  it('names a resolved advisory only after a landed install that has a fix', () => {
    expect(formatAdvisoryResolution(attemptsForApply([upgrade()], [applied()]))).toEqual([
      'Advisories resolved: GHSA-lodash',
    ]);
  });

  it('stays silent when the planner did not name advisories', () => {
    expect(formatAdvisoryResolution(attemptsForApply([upgrade({ advisories: undefined })], [applied()]))).toEqual([]);
  });
});

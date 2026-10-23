import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { AppliedUpgrade } from '../planning/apply.js';
import type { FixPlanResponse, PlannedUpgrade, VulnDelta } from '../planning/types.js';

/**
 * `vg fix` prints "Advisories resolved" only after an upgrade lands on a
 * published fix. These tests drive the command with a mocked planner and a
 * mocked package-manager apply, and assert the four blocked outcomes stay open.
 */

const applyPlan = vi.hoisted(() => vi.fn());

vi.mock('../planning/apply.js', async () => {
  const actual = await vi.importActual<typeof import('../planning/apply.js')>('../planning/apply.js');
  return { ...actual, applyPlan };
});

import { fixCommand } from './fix.js';

const DSN = 'vibgrate+https://key123:secretabc@us.ingest.vibgrate.com/ws_test';

let dir: string;
let logSpy: ReturnType<typeof vi.spyOn>;
let errSpy: ReturnType<typeof vi.spyOn>;
const prevCredsEnv = process.env.VIBGRATE_CREDENTIALS;

function emptyDelta(): VulnDelta {
  return { total: 0, bySeverity: { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 } };
}

function planned(over: Partial<PlannedUpgrade> = {}): PlannedUpgrade {
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

function response(upgrade: PlannedUpgrade, over: Partial<FixPlanResponse> = {}): FixPlanResponse {
  return {
    status: 'ok',
    requestId: 'req_blocked',
    totalCandidates: 1,
    recommended: 'safe',
    rationale: 'Low-risk patch.',
    unresolved: emptyDelta(),
    vulnerabilityData: 'osv',
    deepAnalysis: false,
    plans: [
      {
        tier: 'safe',
        label: 'Low-risk',
        description: 'Patch only.',
        upgrades: [upgrade],
        excluded: [],
        riskScore: 4,
        confidence: 'high',
        fixes: emptyDelta(),
        introduces: emptyDelta(),
      },
      { tier: 'balanced', label: 'Balanced', description: '', upgrades: [], excluded: [], riskScore: 0, confidence: 'high', fixes: emptyDelta(), introduces: emptyDelta() },
      { tier: 'aggressive', label: 'Full', description: '', upgrades: [], excluded: [], riskScore: 0, confidence: 'high', fixes: emptyDelta(), introduces: emptyDelta() },
    ],
    ...over,
  };
}

function fakeResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    clone: () => fakeResponse(body, status),
  } as unknown as Response;
}

function writeArtifact(): void {
  const artifact = {
    schemaVersion: '1.0',
    timestamp: '2024-01-01T00:00:00.000Z',
    vibgrateVersion: 'test',
    rootPath: dir,
    projects: [
      {
        type: 'node',
        path: '.',
        name: 'fixture',
        frameworks: [],
        dependencies: [
          { package: 'lodash', section: 'dependencies', currentSpec: '4.17.20', resolvedVersion: '4.17.20', latestStable: '4.17.21', majorsBehind: 0, drift: 'patch-behind' },
        ],
        dependencyAgeBuckets: { current: 0, oneBehind: 1, twoPlusBehind: 0, unknown: 0 },
      },
    ],
    drift: { score: 40, riskLevel: 'moderate', components: {} },
    findings: [],
  };
  fs.mkdirSync(path.join(dir, '.vibgrate'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.vibgrate', 'scan_result.json'), JSON.stringify(artifact));
}

function output(): string {
  return logSpy.mock.calls.map((call: unknown[]) => String(call[0]).replace(/\u001b\[[0-9;]*m/g, '')).join('\n');
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-fix-advisory-cmd-'));
  process.env.VIBGRATE_DSN = DSN;
  process.env.VIBGRATE_CREDENTIALS = path.join(dir, 'no-credentials.json');
  process.exitCode = undefined;
  applyPlan.mockReset();
  logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  writeArtifact();
});

afterEach(() => {
  delete process.env.VIBGRATE_DSN;
  if (prevCredsEnv === undefined) delete process.env.VIBGRATE_CREDENTIALS;
  else process.env.VIBGRATE_CREDENTIALS = prevCredsEnv;
  process.exitCode = undefined;
  logSpy.mockRestore();
  errSpy.mockRestore();
  vi.unstubAllGlobals();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('vg fix advisory resolution', () => {
  it.each([
    {
      name: 'policy',
      upgrade: planned({ block: 'policy' }),
      result: { package: 'lodash', to: '4.17.21', status: 'skipped', detail: 'blocked by policy' } satisfies AppliedUpgrade,
      reason: 'upgrade blocked by policy',
    },
    {
      name: 'a peer conflict',
      upgrade: planned({ block: 'peer' }),
      result: { package: 'lodash', to: '4.17.21', status: 'skipped', detail: 'peer conflict' } satisfies AppliedUpgrade,
      reason: 'upgrade blocked by a peer conflict',
    },
    {
      name: 'no fixed version',
      upgrade: planned({
        to: null,
        block: 'no-fixed-version',
        advisories: [{ id: 'GHSA-lodash', fixedVersion: null }],
      }),
      result: { package: 'lodash', to: null, status: 'skipped', detail: 'no fixed version' } satisfies AppliedUpgrade,
      reason: 'no fixed version',
    },
    {
      name: 'a failed install',
      upgrade: planned(),
      result: { package: 'lodash', to: '4.17.21', status: 'failed', detail: 'exit 1' } satisfies AppliedUpgrade,
      reason: 'upgrade install failed',
    },
  ])('does not mark the advisory resolved when the upgrade is blocked by $name', async ({ upgrade, result, reason }) => {
    applyPlan.mockReturnValue([result]);
    vi.stubGlobal('fetch', vi.fn(async () => fakeResponse(response(upgrade))));

    await fixCommand.parseAsync([dir, '--yes'], { from: 'user' });

    const text = output();
    expect(text).not.toMatch(/Advisories resolved:/);
    expect(text).toContain(`Advisory GHSA-lodash stayed open — ${reason}`);
  });

  it('does not mark the advisory resolved when a peer conflict blocks apply before the package manager runs', async () => {
    const upgrade = planned();
    const body = response(upgrade);
    body.plans[0].conflicts = [{ packages: ['lodash', 'react'], reason: 'peer dependency', severity: 'blocking' }];
    vi.stubGlobal('fetch', vi.fn(async () => fakeResponse(body)));

    await fixCommand.parseAsync([dir, '--yes'], { from: 'user' });

    expect(applyPlan).not.toHaveBeenCalled();
    const text = output();
    expect(text).not.toMatch(/Advisories resolved:/);
    expect(text).toContain('Advisory GHSA-lodash stayed open — upgrade blocked by a peer conflict');
    expect(process.exitCode).toBe(2);
  });

  it('keeps the advisory open when the planner has no target version', async () => {
    const upgrade = planned({ to: null, advisories: [{ id: 'GHSA-lodash', fixedVersion: null }] });
    applyPlan.mockReturnValue([{ package: 'lodash', to: null, status: 'skipped', detail: 'no target version' }]);
    vi.stubGlobal('fetch', vi.fn(async () => fakeResponse(response(upgrade))));

    await fixCommand.parseAsync([dir, '--yes'], { from: 'user' });

    const text = output();
    expect(text).not.toMatch(/Advisories resolved:/);
    expect(text).toContain('Advisory GHSA-lodash stayed open — no fixed version');
  });

  it('marks the advisory resolved only after the install lands on the fixed version', async () => {
    applyPlan.mockReturnValue([{ package: 'lodash', to: '4.17.21', status: 'applied' }]);
    vi.stubGlobal('fetch', vi.fn(async () => fakeResponse(response(planned()))));

    await fixCommand.parseAsync([dir, '--yes'], { from: 'user' });

    expect(output()).toContain('Advisories resolved: GHSA-lodash');
  });
});

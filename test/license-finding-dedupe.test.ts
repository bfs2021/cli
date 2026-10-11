import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { generateFindings } from '../src/core-open/scoring/drift-score.js';
import { formatSarif } from '../src/core-open/formatters/sarif.js';
import { formatText as formatScanText } from '../src/core-open/formatters/text.js';
import { formatText as formatReportText } from '../src/reporting/formatters/text.js';
import { LICENSE_PARSE_FAILED } from '../src/core-open/licenses/diagnostic.js';
import {
  dedupeLicenseFindings,
  licenseComponentKey,
  licenseFindingId,
  licenseFindingSourcePath,
} from '../src/core-open/licenses/dedupe.js';
import type { DependencyRow, Finding, ProjectScan, ScanArtifact } from '../src/core-open/types.js';

interface FixtureDep {
  package: string;
  raw: string;
  sourcePath?: string;
  section?: DependencyRow['section'];
}

interface FixtureProject {
  name: string;
  path: string;
  dependencies: FixtureDep[];
}

const FIXTURE = fileURLToPath(new URL('./fixtures/license-findings/duplicate-rows.json', import.meta.url));

function projectsFromFixture(): ProjectScan[] {
  const parsed = JSON.parse(fs.readFileSync(FIXTURE, 'utf8')) as { projects: FixtureProject[] };
  return parsed.projects.map((project) => {
    const dependencies: DependencyRow[] = project.dependencies.map((dep) => ({
      package: dep.package,
      section: dep.section ?? 'dependencies',
      currentSpec: '1.0.0',
      resolvedVersion: '1.0.0',
      latestStable: '1.0.0',
      majorsBehind: 0,
      drift: 'current',
      license: {
        raw: dep.raw,
        spdxId: null,
        source: 'registry',
        confidence: 0,
        ...(dep.sourcePath !== undefined ? { sourcePath: dep.sourcePath } : {}),
      },
    }));
    return {
      type: 'node',
      path: project.path,
      name: project.name,
      runtimeMajorsBehind: 0,
      frameworks: [],
      dependencies,
      dependencyAgeBuckets: { current: dependencies.length, oneBehind: 0, twoPlusBehind: 0, unknown: 0 },
    };
  });
}

function artifact(projects: ProjectScan[]): ScanArtifact {
  const findings = generateFindings(projects);
  return {
    schemaVersion: '1.0',
    timestamp: '2026-10-11T00:00:00.000Z',
    vibgrateVersion: '0.0.0-test',
    rootPath: '.',
    projects,
    drift: {
      score: 0,
      riskLevel: 'low',
      components: { runtimeScore: 0, frameworkScore: 0, dependencyScore: 0, eolScore: 0 },
      measured: [],
    },
    findings,
  };
}

function licenseRows(findings: Finding[]): Array<{ component: string; licenseId: string; path: string }> {
  return findings
    .filter((f) => f.ruleId === LICENSE_PARSE_FAILED)
    .map((f) => ({
      component: licenseComponentKey(f),
      licenseId: licenseFindingId(typeof f.details?.raw === 'string' ? f.details.raw : ''),
      path: licenseFindingSourcePath(f),
    }));
}

const EXPECTED_ROWS = [
  { component: 'left-pad', licenseId: 'NotAReal-A', path: 'apps/web/LICENSE' },
  { component: 'left-pad', licenseId: 'NotAReal-A', path: 'apps/web/package.json' },
  { component: 'left-pad', licenseId: 'NotAReal-A OR NotAReal-C', path: 'apps/web/package.json' },
  { component: 'left-pad', licenseId: 'NotAReal-B', path: 'apps/web/package.json' },
  { component: 'right-pad', licenseId: 'NotAReal-A', path: 'apps/web/package.json' },
  { component: 'left-pad', licenseId: 'NotAReal-A', path: 'apps/api' },
  { component: 'left-pad', licenseId: 'Not-A-LicenseRef', path: 'apps/extra/package.json' },
];

function stripAnsi(value: string): string {
  return value.replace(/\x1b\[[0-9;]*m/g, '');
}

function countOccurrences(haystack: string, needle: string): number {
  if (!needle) return 0;
  let count = 0;
  let from = 0;
  while (from <= haystack.length) {
    const at = haystack.indexOf(needle, from);
    if (at === -1) break;
    count += 1;
    from = at + needle.length;
  }
  return count;
}

function licenseFinding(pkg: string, raw: string, path: string, sourcePath?: string): Finding {
  return {
    ruleId: LICENSE_PARSE_FAILED,
    level: 'warning',
    message:
      `Could not resolve SPDX license "${raw}" for ${pkg} at ${path}. ` +
      'Replace it with a canonical SPDX id or expression, or NOASSERTION if the license is intentionally unknown.',
    location: path,
    details:
      sourcePath === undefined
        ? { raw, warnCode: 'VG_WARN_LICENSE_UNPARSEABLE' }
        : { raw, sourcePath, warnCode: 'VG_WARN_LICENSE_UNPARSEABLE' },
  };
}

describe('license finding equality', () => {
  it('treats SPDX aliases and LicenseRefs as ids, and keeps a different id or path', () => {
    expect(licenseFindingId('mit')).toBe('MIT');
    expect(licenseFindingId('Apache2')).toBe('Apache-2.0');
    expect(licenseFindingId('LicenseRef-Acme-1.0')).toBe('LicenseRef-Acme-1.0');
    expect(licenseFindingId('MIT OR LicenseRef-Acme-1.0')).toBe('MIT OR LicenseRef-Acme-1.0');
    expect(licenseFindingId('NotAReal-A')).toBe('NotAReal-A');
    expect(licenseFindingId('NotAReal-A')).not.toBe(licenseFindingId('NotAReal-B'));

    const other = {
      ruleId: 'vibgrate/runtime-eol',
      level: 'error' as const,
      message: 'runtime is behind',
      location: 'apps/web',
    };
    const rows = dedupeLicenseFindings([
      other,
      licenseFinding('left-pad', 'MIT', 'package.json'),
      licenseFinding('left-pad', 'mit', 'package.json'),
      licenseFinding('left-pad', 'Apache2', 'package.json'),
      licenseFinding('left-pad', 'Apache-2.0', 'package.json'),
      licenseFinding('left-pad', 'MIT', 'LICENSE'),
      licenseFinding('right-pad', 'MIT', 'package.json'),
      licenseFinding('left-pad', 'LicenseRef-Acme-1.0', 'package.json'),
      licenseFinding('left-pad', 'LicenseRef-Acme-1.0', 'package.json'),
      licenseFinding('left-pad', 'LicenseRef-Other-1.0', 'package.json'),
      licenseFinding('left-pad', 'NotAReal-A', 'package.json', '.\\package.json'),
      licenseFinding('left-pad', 'NotAReal-A', 'package.json', 'package.json'),
    ]);

    expect(rows[0]).toBe(other);
    expect(licenseRows(rows)).toEqual([
      { component: 'left-pad', licenseId: 'MIT', path: 'package.json' },
      { component: 'left-pad', licenseId: 'Apache-2.0', path: 'package.json' },
      { component: 'left-pad', licenseId: 'MIT', path: 'LICENSE' },
      { component: 'right-pad', licenseId: 'MIT', path: 'package.json' },
      { component: 'left-pad', licenseId: 'LicenseRef-Acme-1.0', path: 'package.json' },
      { component: 'left-pad', licenseId: 'LicenseRef-Other-1.0', path: 'package.json' },
      { component: 'left-pad', licenseId: 'NotAReal-A', path: 'package.json' },
    ]);
  });
});

describe('duplicate license findings', () => {
  it('emits one row for the same component, license id, and path, in a stable order', () => {
    const projects = projectsFromFixture();
    const failingInputs = projects.reduce(
      (count, project) => count + project.dependencies.filter((dep) => dep.license?.raw !== 'MIT').length,
      0,
    );
    expect(failingInputs).toBeGreaterThan(EXPECTED_ROWS.length);

    const scan = artifact(projects);
    const again = artifact(projects);
    const reversed = artifact(
      projects.map((project) => ({ ...project, dependencies: [...project.dependencies].reverse() })),
    );

    expect(licenseRows(scan.findings)).toEqual(EXPECTED_ROWS);
    expect(licenseRows(again.findings)).toEqual(EXPECTED_ROWS);
    expect(licenseRows(reversed.findings)).toEqual(EXPECTED_ROWS);
    expect(scan.findings).toEqual(again.findings);
    expect(scan.findings).toEqual(reversed.findings);

    const duplicate = scan.findings.find(
      (f) =>
        f.ruleId === LICENSE_PARSE_FAILED &&
        f.details?.raw === 'NotAReal-A' &&
        f.location === 'apps/web/package.json',
    );
    expect(duplicate?.message).toContain('for left-pad at apps/web/package.json');
    expect(scan.findings.filter((f) => f.message === duplicate?.message)).toHaveLength(1);
    expect(scan.findings.some((f) => f.details?.raw === 'MIT')).toBe(false);

    const missingPath = scan.findings.find((f) => f.location === 'apps/api');
    expect(missingPath?.details).toEqual({ raw: 'NotAReal-A', warnCode: 'VG_WARN_LICENSE_UNPARSEABLE' });

    const json = JSON.stringify(scan.findings);
    const jsonAgain = JSON.stringify(again.findings);
    expect(json).toBe(jsonAgain);
    const parsed = JSON.parse(json) as Finding[];
    expect(parsed.filter((f) => f.message === duplicate!.message)).toHaveLength(1);

    const human = stripAnsi(formatScanText(scan));
    const humanAgain = stripAnsi(formatScanText(again));
    const report = stripAnsi(formatReportText(scan));
    expect(human).toBe(humanAgain);
    expect(countOccurrences(human, duplicate!.message)).toBe(1);
    expect(countOccurrences(report, duplicate!.message)).toBe(1);

    const sarif = formatSarif(scan) as {
      runs: Array<{ results: Array<{ ruleId: string; message: { text: string } }> }>;
    };
    const sarifAgain = formatSarif(again);
    expect(sarif).toEqual(sarifAgain);
    const results = sarif.runs[0]!.results.filter((r) => r.ruleId === LICENSE_PARSE_FAILED);
    expect(results).toHaveLength(EXPECTED_ROWS.length);
    expect(results.filter((r) => r.message.text === duplicate!.message)).toHaveLength(1);
    expect(results.map((r) => r.message.text)).toEqual(
      scan.findings.filter((f) => f.ruleId === LICENSE_PARSE_FAILED).map((f) => f.message),
    );
  });
});

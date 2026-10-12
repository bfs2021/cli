import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { generateFindings } from '../src/core-open/scoring/drift-score.js';
import { formatSarif } from '../src/core-open/formatters/sarif.js';
import { formatText } from '../src/core-open/formatters/text.js';
import { LICENSE_PARSE_FAILED, licenseParseDiagnostic } from '../src/core-open/licenses/diagnostic.js';
import {
  dedupeLicenseFindings,
  licenseFindingEqualityKey,
  licenseIdForEquality,
  setLicenseFindingKey,
} from '../src/core-open/licenses/dedupe-findings.js';
import type { DependencyRow, Finding, ProjectScan, ScanArtifact } from '../src/core-open/types.js';

interface FixtureDep {
  package: string;
  raw: string;
  sourcePath?: string;
  section?: DependencyRow['section'];
  version?: string | null;
}

interface FixtureProject {
  name: string;
  path: string;
  type?: ProjectScan['type'];
  dependencies: FixtureDep[];
}

const FIXTURE = fileURLToPath(new URL('./fixtures/license-findings/duplicates.json', import.meta.url));

function projectsFromFixture(): ProjectScan[] {
  const parsed = JSON.parse(fs.readFileSync(FIXTURE, 'utf8')) as { projects: FixtureProject[] };
  return parsed.projects.map((project) => {
    const dependencies: DependencyRow[] = project.dependencies.map((dep) => ({
      package: dep.package,
      section: dep.section ?? 'dependencies',
      currentSpec: '1.0.0',
      resolvedVersion: dep.version === undefined ? '1.0.0' : dep.version,
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
      type: project.type ?? 'node',
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
    findings: generateFindings(projects),
  };
}

function packageNamed(message: string): string {
  const forAt = message.match(/ for (.+) at /);
  return forAt?.[1] ?? '';
}

function licenseRows(scan: ScanArtifact): Array<{ package: string; raw: string; location: string; sourcePath: string | null }> {
  return scan.findings
    .filter((f) => f.ruleId === LICENSE_PARSE_FAILED)
    .map((f) => ({
      package: packageNamed(f.message),
      raw: String(f.details?.raw ?? ''),
      location: f.location,
      sourcePath: typeof f.details?.sourcePath === 'string' ? f.details.sourcePath : null,
    }));
}

function reversedDeps(projects: ProjectScan[]): ProjectScan[] {
  return projects.map((project) => ({ ...project, dependencies: [...project.dependencies].reverse() }));
}

function finding(packageName: string, raw: string, location: string, sourcePath?: string): Finding {
  const diag = licenseParseDiagnostic(raw, location, packageName);
  if (!diag) throw new Error(`expected a license finding for ${raw}`);
  return {
    ruleId: diag.code,
    level: 'warning',
    message: diag.message,
    location,
    details: sourcePath
      ? { raw: diag.raw, sourcePath, warnCode: diag.warnCode }
      : { raw: diag.raw, warnCode: diag.warnCode },
  };
}

describe('license finding equality', () => {
  it('uses the SPDX id or LicenseRef, and keeps an unresolved declaration whole', () => {
    expect(licenseIdForEquality('expat')).toBe('MIT');
    expect(licenseIdForEquality('MIT')).toBe('MIT');
    expect(licenseIdForEquality('LicenseRef-Acme-1.0')).toBe('LicenseRef-Acme-1.0');
    expect(licenseIdForEquality('LicenseRef-OR-1.0')).toBe('LicenseRef-OR-1.0');
    expect(licenseIdForEquality('NotARealLicense-9')).toBe('NotARealLicense-9');
    expect(licenseIdForEquality('MIT OR NotARealLicense-9')).toBe('MIT OR NotARealLicense-9');
    expect(licenseIdForEquality('  NotARealLicense-9  ')).toBe('NotARealLicense-9');
  });

  it('changes when the component, the license id, or the path changes', () => {
    const base = {
      projectType: 'node',
      packageName: 'alpha-bad',
      resolvedVersion: '1.0.0',
      licenseRaw: 'NotARealLicense-9',
      sourcePath: 'apps/web/package.json',
    };
    const key = licenseFindingEqualityKey(base);
    expect(licenseFindingEqualityKey(base)).toBe(key);
    expect(licenseFindingEqualityKey({ ...base, resolvedVersion: null })).not.toBe(key);
    expect(licenseFindingEqualityKey({ ...base, resolvedVersion: '2.0.0' })).not.toBe(key);
    expect(licenseFindingEqualityKey({ ...base, projectType: 'python' })).not.toBe(key);
    expect(licenseFindingEqualityKey({ ...base, packageName: 'other-bad' })).not.toBe(key);
    expect(licenseFindingEqualityKey({ ...base, licenseRaw: 'Also-Not-SPDX' })).not.toBe(key);
    expect(licenseFindingEqualityKey({ ...base, licenseRaw: 'LicenseRef-Acme-1.0' })).not.toBe(key);
    expect(licenseFindingEqualityKey({ ...base, licenseRaw: 'expat' })).not.toBe(
      licenseFindingEqualityKey({ ...base, licenseRaw: 'NotARealLicense-9' }),
    );
    expect(licenseFindingEqualityKey({ ...base, licenseRaw: 'expat' })).toBe(
      licenseFindingEqualityKey({ ...base, licenseRaw: 'MIT' }),
    );
    expect(licenseFindingEqualityKey({ ...base, sourcePath: 'apps/web/LICENSE' })).not.toBe(key);
    expect(licenseFindingEqualityKey({ ...base, resolvedVersion: undefined })).toBe(
      licenseFindingEqualityKey({ ...base, resolvedVersion: null }),
    );
  });

  it('keeps the first row, leaves other findings in place, and does not reorder', () => {
    const dup = finding('alpha-bad', 'NotARealLicense-9', 'apps/web/package.json', 'apps/web/package.json');
    const otherId = finding('alpha-bad', 'Also-Not-SPDX', 'apps/web/package.json', 'apps/web/package.json');
    const otherPath = finding('alpha-bad', 'NotARealLicense-9', 'apps/web/LICENSE', 'apps/web/LICENSE');
    const otherPkg = finding('other-bad', 'NotARealLicense-9', 'apps/web/package.json', 'apps/web/package.json');
    const runtime: Finding = {
      ruleId: 'vibgrate/runtime-lag',
      level: 'warning',
      message: 'Node.js runtime "18" is 2 major versions behind (latest: 22).',
      location: 'apps/web',
    };
    const once = dedupeLicenseFindings([dup, runtime, { ...dup }, otherId, otherPath, otherPkg, { ...otherId }]);
    expect(once).toEqual([dup, runtime, otherId, otherPath, otherPkg]);
    expect(dedupeLicenseFindings([otherPath, dup])).toEqual([otherPath, dup]);
    expect(dedupeLicenseFindings(once)).toEqual(once);
  });

  it('keeps two resolved versions when the findings were tagged with component identity', () => {
    const older = finding('alpha-bad', 'NotARealLicense-9', 'apps/web/package.json', 'apps/web/package.json');
    const newer = finding('alpha-bad', 'NotARealLicense-9', 'apps/web/package.json', 'apps/web/package.json');
    setLicenseFindingKey(older, licenseFindingEqualityKey({
      projectType: 'node',
      packageName: 'alpha-bad',
      resolvedVersion: '1.0.0',
      licenseRaw: 'NotARealLicense-9',
      sourcePath: 'apps/web/package.json',
    }));
    setLicenseFindingKey(newer, licenseFindingEqualityKey({
      projectType: 'node',
      packageName: 'alpha-bad',
      resolvedVersion: '2.0.0',
      licenseRaw: 'NotARealLicense-9',
      sourcePath: 'apps/web/package.json',
    }));
    expect(dedupeLicenseFindings([older, newer, older])).toEqual([older, newer]);
  });
});

describe('license findings before text, JSON, and SARIF', () => {
  // expr-ref is listed twice: resolved versions 1.0.0 and 3.0.0 are different
  // components, and the finding text does not include the version.
  // other-bad shares raw and path with alpha-bad; the message names the package.
  const expected = [
    { package: 'alpha-bad', raw: 'Also-Not-SPDX', location: 'apps/web/package.json', sourcePath: 'apps/web/package.json' },
    { package: 'alpha-bad', raw: 'MIT OR NotARealLicense-9', location: 'apps/web/package.json', sourcePath: 'apps/web/package.json' },
    { package: 'alpha-bad', raw: 'NotARealLicense-9', location: 'apps/web/package.json', sourcePath: 'apps/web/package.json' },
    { package: 'alpha-bad', raw: 'NotARealLicense-9', location: 'apps/web/LICENSE', sourcePath: 'apps/web/LICENSE' },
    { package: 'expr-ref', raw: 'LicenseRef-Acme-1.0 OR NotARealLicense-9', location: 'apps/web/package.json', sourcePath: 'apps/web/package.json' },
    { package: 'expr-ref', raw: 'LicenseRef-Acme-1.0 OR NotARealLicense-9', location: 'apps/web/package.json', sourcePath: 'apps/web/package.json' },
    { package: 'other-bad', raw: 'NotARealLicense-9', location: 'apps/web/package.json', sourcePath: 'apps/web/package.json' },
    { package: 'gamma-bad', raw: 'Third-Not-SPDX', location: 'apps/api/package.json', sourcePath: 'apps/api/package.json' },
    { package: 'gamma-bad', raw: 'Third-Not-SPDX', location: 'apps/api', sourcePath: null },
  ];

  it('lists each duplicate once, keeps distinct ids and paths, and stays stable across two runs', () => {
    const first = artifact(projectsFromFixture());
    const second = artifact(projectsFromFixture());
    const reversed = artifact(reversedDeps(projectsFromFixture()));

    expect(first.findings.every((f) => f.ruleId === LICENSE_PARSE_FAILED)).toBe(true);
    expect(licenseRows(first)).toEqual(expected);
    expect(licenseRows(second)).toEqual(licenseRows(first));
    expect(licenseRows(reversed)).toEqual(licenseRows(first));

    const alphaAtManifest = first.findings.filter(
      (f) => f.details?.raw === 'NotARealLicense-9' && f.location === 'apps/web/package.json' && f.message.includes('for alpha-bad at'),
    );
    expect(alphaAtManifest).toHaveLength(1);
    expect(first.findings.some((f) => f.details?.raw === 'MIT')).toBe(false);
    expect(first.findings.some((f) => f.details?.raw === 'LicenseRef-Acme-1.0')).toBe(false);

    const json = JSON.stringify(first, null, 2);
    const findingsJson = JSON.stringify(first.findings, null, 2);
    const text = formatText(first);
    const sarif = JSON.stringify(formatSarif(first), null, 2);
    expect(json).toBe(JSON.stringify(second, null, 2));
    expect(text).toBe(formatText(second));
    expect(sarif).toBe(JSON.stringify(formatSarif(second), null, 2));
    // Dependency row order is input. Findings, the text report, and SARIF are not.
    expect(findingsJson).toBe(JSON.stringify(reversed.findings, null, 2));
    expect(text).toBe(formatText(reversed));
    expect(sarif).toBe(JSON.stringify(formatSarif(reversed), null, 2));

    const alphaMessage = 'Could not resolve SPDX license "NotARealLicense-9" for alpha-bad at apps/web/package.json.';
    expect(text.split(alphaMessage)).toHaveLength(2);
    const sarifDoc = JSON.parse(sarif) as {
      runs: Array<{ results: Array<{ ruleId: string; message: { text: string } }> }>;
    };
    expect(sarifDoc.runs[0]!.results.filter((r) => r.message.text.startsWith(alphaMessage))).toHaveLength(1);
    expect(json).toContain('"raw": "Also-Not-SPDX"');
    expect(json).toContain('"raw": "LicenseRef-Acme-1.0 OR NotARealLicense-9"');
    expect(json).toContain('"location": "apps/web/LICENSE"');
    expect(json).toContain('"location": "apps/api"');
  });

  it('keeps a second resolved version of the same package, license, and path', () => {
    const [web] = projectsFromFixture();
    if (!web) throw new Error('fixture missing web');
    const again: ProjectScan = {
      ...web,
      dependencies: [
        ...web.dependencies,
        {
          package: 'alpha-bad',
          section: 'dependencies',
          currentSpec: '2.0.0',
          resolvedVersion: '2.0.0',
          latestStable: '2.0.0',
          majorsBehind: 0,
          drift: 'current',
          license: {
            raw: 'NotARealLicense-9',
            spdxId: null,
            source: 'registry',
            confidence: 0,
            sourcePath: 'apps/web/package.json',
          },
        },
      ],
    };
    const once = generateFindings([web]);
    const twice = generateFindings([again]);
    const alpha = (findings: Finding[]) => findings.filter(
      (f) => f.details?.raw === 'NotARealLicense-9' && f.message.includes('for alpha-bad at apps/web/package.json'),
    );
    expect(alpha(once)).toHaveLength(1);
    expect(alpha(twice)).toHaveLength(2);
    expect(alpha(twice)[0]).toEqual(alpha(twice)[1]);
    expect(generateFindings([again])).toEqual(twice);
  });
});

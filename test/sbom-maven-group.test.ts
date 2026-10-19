/**
 * A Maven coordinate with no groupId still gets a purl, and the export says so.
 * The fixture is a scan artifact: `gson` has no `:`, and the grouped coordinate
 * beside it must stay quiet. `mixed.cdx.json` and `mixed.spdx.json` are not inputs here.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { WARNING_CODES } from '../src/core-open/warnings.js';
import {
  collectMavenGroupWarnings,
  collectPurlWarnings,
  describeMissingMavenGroup,
  purlFor,
  sbomCommand,
  toCycloneDx,
  toSpdx,
} from '../src/reporting/commands/sbom.js';
import type { DependencyRow, ProjectScan, ScanArtifact } from '../src/reporting/types.js';

const fixtureDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures/sbom');
const fixturePath = path.join(fixtureDir, 'maven-no-group.json');

const MISSING_NAME = 'gson';
const MISSING_PURL = 'pkg:maven/gson@2.11.0';
const GROUPED_NAME = 'com.google.code.gson:gson';
const GROUPED_PURL = 'pkg:maven/com.google.code.gson/gson@2.11.0';
const MISSING_WARNING = describeMissingMavenGroup(MISSING_NAME, MISSING_PURL);

function loadFixture(): ScanArtifact {
  return JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as ScanArtifact;
}

function prop(properties: Array<{ name: string; value: string }>, name: string): string | undefined {
  return properties.find((property) => property.name === name)?.value;
}

describe('maven component with no groupId', () => {
  const dirs: string[] = [];
  afterEach(() => {
    while (dirs.length) fs.rmSync(dirs.pop()!, { recursive: true, force: true });
  });

  it('emits a namespace-less purl and VG_WARN_MAVEN_GROUP_MISSING, and leaves a grouped coordinate quiet', () => {
    const artifact = loadFixture();
    const reversed = loadFixture();
    reversed.projects[0]!.dependencies.reverse();

    const cyclone = toCycloneDx(artifact) as {
      components: Array<{
        name: string;
        version: string;
        purl?: string;
        'bom-ref': string;
        properties: Array<{ name: string; value: string }>;
      }>;
    };
    expect(JSON.stringify(toCycloneDx(reversed))).toBe(JSON.stringify(cyclone));
    expect(cyclone.components.map((component) => component.name)).toEqual([GROUPED_NAME, MISSING_NAME]);

    const grouped = cyclone.components[0]!;
    expect(grouped.purl).toBe(GROUPED_PURL);
    expect(grouped['bom-ref']).toBe(GROUPED_PURL);
    expect(prop(grouped.properties, 'vibgrate:mavenWarning')).toBeUndefined();
    expect(grouped.properties.some((property) => property.value === WARNING_CODES.MAVEN_GROUP_MISSING)).toBe(false);

    const missing = cyclone.components[1]!;
    expect(missing.version).toBe('2.11.0');
    expect(missing.purl).toBe(MISSING_PURL);
    expect(missing['bom-ref']).toBe(MISSING_PURL);
    expect(prop(missing.properties, 'vibgrate:purlStatus')).toBeUndefined();
    expect(prop(missing.properties, 'vibgrate:mavenWarning')).toBe(MISSING_WARNING);
    expect(prop(missing.properties, 'vibgrate:warningCode')).toBe(WARNING_CODES.MAVEN_GROUP_MISSING);
    expect(MISSING_WARNING).not.toContain(artifact.rootPath);

    const spdx = toSpdx(artifact) as {
      packages: Array<{
        name: string;
        externalRefs?: Array<{ referenceType: string; referenceLocator: string }>;
        annotations: Array<{ comment: string }>;
      }>;
    };
    expect(JSON.stringify(toSpdx(reversed))).toBe(JSON.stringify(spdx));
    const groupedPkg = spdx.packages.find((pkg) => pkg.name === GROUPED_NAME)!;
    expect(groupedPkg.externalRefs?.[0]?.referenceLocator).toBe(GROUPED_PURL);
    expect(groupedPkg.annotations.map((annotation) => annotation.comment).join('\n')).not.toContain('Maven group missing');

    const missingPkg = spdx.packages.find((pkg) => pkg.name === MISSING_NAME)!;
    expect(missingPkg.externalRefs).toEqual([
      { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: MISSING_PURL },
    ]);
    expect(missingPkg.annotations.map((annotation) => annotation.comment)).toEqual([
      'project=app; projects=app; drift=current; majorsBehind=0; scope=direct',
      MISSING_WARNING,
      `warningCode=${WARNING_CODES.MAVEN_GROUP_MISSING}`,
    ]);

    expect(collectMavenGroupWarnings(artifact)).toEqual([MISSING_WARNING]);
    expect(collectPurlWarnings(artifact)).toEqual([]);
  });

  it('treats an empty group segment like a missing group, and does not warn when the purl is omitted', () => {
    expect(purlFor('java', ':gson', '2.11.0')).toBe(MISSING_PURL);
    expect(describeMissingMavenGroup(':gson', MISSING_PURL)).toContain('":gson"');

    const artifact = loadFixture();
    const row = artifact.projects[0]!.dependencies[0]!;
    artifact.projects[0]!.dependencies = [
      { ...row, package: ':gson' },
      { ...row, package: 'gson bar', currentSpec: '1.0.0', resolvedVersion: '1.0.0' },
    ];
    artifact.projects.push({
      ...artifact.projects[0]!,
      type: 'node',
      name: 'web',
      dependencies: [{ ...row, package: 'left-pad' }],
    } as ProjectScan);

    const warnings = collectMavenGroupWarnings(artifact);
    expect(warnings).toEqual([describeMissingMavenGroup(':gson', MISSING_PURL)]);
    expect(collectPurlWarnings(artifact).some((warning) => warning.includes('gson bar'))).toBe(true);
    expect(warnings.join('\n')).not.toContain('gson bar');
    expect(warnings.join('\n')).not.toContain('left-pad');

    const unknown = loadFixture();
    const bare = unknown.projects[0]!.dependencies[0]!;
    bare.resolvedVersion = null;
    bare.currentSpec = 'latest';
    unknown.projects[0]!.dependencies = [bare];
    expect(collectMavenGroupWarnings(unknown)).toEqual([describeMissingMavenGroup(MISSING_NAME, 'pkg:maven/gson')]);
  });

  it('prints the coded warning on stderr and writes the same document twice', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-sbom-maven-group-'));
    dirs.push(root);
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'app', version: '1.0.0' }));
    const stderr: string[] = [];
    const stdout: string[] = [];
    const errSpy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      stderr.push(args.map(String).join(' '));
    });
    const logSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      stdout.push(args.map(String).join(' '));
    });
    try {
      const args = ['export', '--in', fixturePath, '--root', root, '--format', 'cyclonedx', '--no-transitive'];
      await sbomCommand.parseAsync(args, { from: 'user' });
      await sbomCommand.parseAsync(args, { from: 'user' });
    } finally {
      errSpy.mockRestore();
      logSpy.mockRestore();
    }
    expect(stdout).toHaveLength(2);
    expect(stdout[0]).toBe(stdout[1]);
    expect(stdout[0]).toContain(MISSING_PURL);
    expect(stdout[0]).toContain(GROUPED_PURL);
    expect(stdout[0]).toContain(WARNING_CODES.MAVEN_GROUP_MISSING);
    expect(stderr.join('\n')).toContain(`warning [${WARNING_CODES.MAVEN_GROUP_MISSING}]: ${MISSING_WARNING}`);
    expect(stderr.join('\n')).not.toContain(GROUPED_NAME);
  });

  it('warns for a lockfile-only Maven row that has no group', () => {
    const artifact = loadFixture();
    artifact.projects[0]!.dependencies = [] as DependencyRow[];
    const graph = {
      components: [{ package: MISSING_NAME, version: '2.11.0' }],
      edges: undefined,
      rootDependsOn: [],
      ecosystem: 'java' as const,
    };
    expect(collectMavenGroupWarnings(artifact, graph)).toEqual([MISSING_WARNING]);
    const cyclone = toCycloneDx(artifact, graph) as {
      components: Array<{ purl: string; properties: Array<{ name: string; value: string }> }>;
    };
    expect(cyclone.components).toHaveLength(1);
    expect(cyclone.components[0]!.purl).toBe(MISSING_PURL);
    expect(prop(cyclone.components[0]!.properties, 'vibgrate:warningCode')).toBe(WARNING_CODES.MAVEN_GROUP_MISSING);
  });
});

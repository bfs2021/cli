/**
 * Gradle test configurations are dev manifest rows. `implementation`, `api`,
 * `compileOnly`, `runtimeOnly`, and `platform` stay production. A coordinate
 * declared in both a production configuration and a test configuration stays
 * production, whichever line comes first. The stored configuration is the
 * bare name in Groovy and in Kotlin DSL.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MavenCache } from '../src/core-open/scanners/maven-cache.js';
import { parseGradleBuild, scanJavaProjects } from '../src/core-open/scanners/java-scanner.js';
import { Semaphore } from '../src/core-open/utils/semaphore.js';
import { collectLockfileGraph, toCycloneDx, toSpdx } from '../src/reporting/commands/sbom.js';
import type { ProjectScan, ScanArtifact } from '../src/reporting/types.js';

const GROOVY = fileURLToPath(new URL('./fixtures/gradle-scopes/groovy/build.gradle', import.meta.url));
const KOTLIN = fileURLToPath(new URL('./fixtures/gradle-scopes/kotlin/build.gradle.kts', import.meta.url));

/** package → section. Order is the scanner's code-unit sort (all drift unknown). */
const SECTIONS: Array<[string, string]> = [
  ['com.example:api-lib', 'dependencies'],
  ['com.example:both', 'dependencies'],
  ['com.example:compile-lib', 'dependencies'],
  ['com.example:impl-lib', 'dependencies'],
  ['com.example:runtime-lib', 'dependencies'],
  ['com.example:test-compile', 'devDependencies'],
  ['com.example:test-runtime', 'devDependencies'],
  ['junit:junit', 'devDependencies'],
  ['org.mockito:mockito-core', 'devDependencies'],
  ['org.springframework.boot:spring-boot-dependencies', 'dependencies'],
];

const PRODUCTION = [
  'com.example:api-lib',
  'com.example:both',
  'com.example:compile-lib',
  'com.example:impl-lib',
  'com.example:runtime-lib',
  'org.springframework.boot:spring-boot-dependencies',
] as const;

const DEVELOPMENT = [
  'com.example:test-compile',
  'com.example:test-runtime',
  'junit:junit',
  'org.mockito:mockito-core',
] as const;

function artifact(projects: ProjectScan[], rootPath: string): ScanArtifact {
  return {
    schemaVersion: '1.0',
    timestamp: '2026-02-19T00:00:00.000Z',
    vibgrateVersion: '0.0.1',
    rootPath,
    drift: {
      score: 0,
      riskLevel: 'low',
      components: { runtimeScore: 0, frameworkScore: 0, dependencyScore: 0, eolScore: 0 },
    },
    findings: [],
    projects,
  };
}

function offlineMavenCache(): MavenCache {
  const cache = new MavenCache(new Semaphore(1));
  vi.spyOn(cache, 'get').mockImplementation(async () => ({
    latest: null,
    stableVersions: [],
    latestStableOverall: null,
  }));
  return cache;
}

describe('sbom export: Gradle test configurations', () => {
  const roots: string[] = [];

  afterEach(() => {
    vi.restoreAllMocks();
    for (const dir of roots) fs.rmSync(dir, { recursive: true, force: true });
    roots.length = 0;
  });

  it('stores the bare configuration name for Groovy and Kotlin DSL', () => {
    const groovy = parseGradleBuild(fs.readFileSync(GROOVY, 'utf8'), GROOVY);
    const kotlin = parseGradleBuild(fs.readFileSync(KOTLIN, 'utf8'), KOTLIN);
    const configurations = (rows: typeof groovy.dependencies): string[] =>
      rows.map((dep) => `${dep.groupId}:${dep.artifactId} ${dep.configuration}`).sort();

    expect(configurations(groovy.dependencies)).toEqual([
      'com.example:api-lib api',
      'com.example:both implementation',
      'com.example:compile-lib compileOnly',
      'com.example:impl-lib implementation',
      'com.example:runtime-lib runtimeOnly',
      'com.example:test-compile testCompileOnly',
      'com.example:test-runtime testRuntimeOnly',
      'junit:junit testImplementation',
      'org.mockito:mockito-core testImplementation',
      'org.springframework.boot:spring-boot-dependencies platform',
    ]);
    expect(configurations(kotlin.dependencies)).toEqual(configurations(groovy.dependencies));

    const both = groovy.dependencies.find((dep) => dep.artifactId === 'both');
    expect(both?.version).toBe('1.5.0');
    expect(both?.configuration).toBe('implementation');
    const kotlinBoth = kotlin.dependencies.find((dep) => dep.artifactId === 'both');
    expect(kotlinBoth?.version).toBe('1.5.0');
    expect(kotlinBoth?.configuration).toBe('implementation');
  });

  it.each([
    ['build.gradle', GROOVY],
    ['build.gradle.kts', KOTLIN],
  ] as const)('marks %s test rows in the scan and in CycloneDX and SPDX', async (fileName, fixture) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-gradle-scope-'));
    roots.push(root);
    fs.copyFileSync(fixture, path.join(root, fileName));

    const projects = await scanJavaProjects(root, offlineMavenCache());
    expect(projects).toHaveLength(1);
    const project = projects[0]!;
    expect(project.dependencies.map((dep) => [dep.package, dep.section])).toEqual(SECTIONS);

    const both = project.dependencies.find((dep) => dep.package === 'com.example:both');
    expect(both?.currentSpec).toBe('1.5.0');
    expect(both?.section).toBe('dependencies');

    const scanArtifact = artifact(projects, fileName);
    const graph = collectLockfileGraph(scanArtifact, root);
    const cdx = toCycloneDx(scanArtifact, graph) as {
      components: Array<{ name: string; scope?: string; properties: Array<{ name: string; value: string }> }>;
      dependencies?: unknown;
    };
    const byName = new Map(cdx.components.map((component) => [component.name, component]));
    const vibScope = (name: string): string | undefined =>
      byName.get(name)?.properties.find((property) => property.name === 'vibgrate:scope')?.value;

    expect(cdx.components.map((component) => component.name)).toEqual(SECTIONS.map(([name]) => name));
    for (const [name] of SECTIONS) expect(vibScope(name)).toBe('direct');
    expect(cdx.dependencies).toBeUndefined();

    const scopeOf = (name: string): string | undefined => byName.get(name)?.scope;
    for (const name of PRODUCTION) expect(scopeOf(name)).toBeUndefined();
    for (const name of DEVELOPMENT) expect(scopeOf(name)).toBe('excluded');

    const spdx = toSpdx(scanArtifact, graph) as {
      packages: Array<{ name: string; annotations: Array<{ comment: string }> }>;
      relationships: Array<{ spdxElementId: string; relatedSpdxElementId: string; relationshipType: string }>;
    };
    const id = (name: string): string => `SPDXRef-Package-${spdx.packages.findIndex((pkg) => pkg.name === name) + 1}`;
    const rel = (name: string): { relationshipType: string; relatedSpdxElementId: string } | undefined => {
      const element = id(name);
      const found = spdx.relationships.find((row) => row.spdxElementId === element);
      return found
        ? { relationshipType: found.relationshipType, relatedSpdxElementId: found.relatedSpdxElementId }
        : undefined;
    };

    for (const pkg of spdx.packages) {
      expect(pkg.annotations.some((note) => note.comment.includes('scope=direct'))).toBe(true);
    }
    for (const name of DEVELOPMENT) {
      expect(rel(name)).toEqual({ relationshipType: 'DEV_DEPENDENCY_OF', relatedSpdxElementId: 'SPDXRef-DOCUMENT' });
    }
    for (const name of PRODUCTION) expect(rel(name)).toBeUndefined();
    expect(spdx.relationships.some((row) => row.relationshipType === 'DEPENDS_ON')).toBe(false);
  });
});

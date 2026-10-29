/**
 * Gradle test configurations are dev manifest rows. `testImplementation`,
 * `testRuntimeOnly`, and `testCompileOnly` export as development dependencies
 * in Groovy and Kotlin DSL. `implementation`, `api`, `compileOnly`,
 * `runtimeOnly`, and `platform` stay production. A coordinate declared on
 * both `implementation` and `testImplementation` stays production, and the
 * production declaration supplies the version. The stored configuration is
 * the bare name in both syntaxes.
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

const FIXTURE_DIR = fileURLToPath(new URL('./fixtures/gradle-scopes/', import.meta.url));

/** package → section. Order is the scanner's code-unit sort (all drift unknown). */
const SECTIONS: Array<[string, string]> = [
  ['com.example:api-lib', 'dependencies'],
  ['com.example:both-lib', 'dependencies'],
  ['com.example:compile-only-lib', 'dependencies'],
  ['com.example:impl-lib', 'dependencies'],
  ['com.example:platform-lib', 'dependencies'],
  ['com.example:runtime-only-lib', 'dependencies'],
  ['com.example:test-compile-lib', 'devDependencies'],
  ['com.example:test-runtime-lib', 'devDependencies'],
  ['junit:junit', 'devDependencies'],
];

const DEV = new Set(['com.example:test-compile-lib', 'com.example:test-runtime-lib', 'junit:junit']);

const CONFIGURATIONS: Record<string, string> = {
  'com.example:api-lib': 'api',
  'com.example:both-lib': 'implementation',
  'com.example:compile-only-lib': 'compileOnly',
  'com.example:impl-lib': 'implementation',
  'com.example:platform-lib': 'platform',
  'com.example:runtime-only-lib': 'runtimeOnly',
  'com.example:test-compile-lib': 'testCompileOnly',
  'com.example:test-runtime-lib': 'testRuntimeOnly',
  'junit:junit': 'testImplementation',
};

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
  let root: string;

  afterEach(() => {
    vi.restoreAllMocks();
    if (root) fs.rmSync(root, { recursive: true, force: true });
  });

  it.each([
    ['build.gradle', 'gradle-scopes'],
    ['build.gradle.kts', 'gradle-scopes-kts'],
  ])('marks test rows in %s and keeps the bare configuration name', async (fileName, rootPath) => {
    const source = fs.readFileSync(path.join(FIXTURE_DIR, fileName), 'utf8');
    const parsed = parseGradleBuild(source, path.join('proj', fileName));
    const stored = new Map(parsed.dependencies.map((dep) => [`${dep.groupId}:${dep.artifactId}`, dep]));
    expect([...stored.keys()].sort()).toEqual(SECTIONS.map(([name]) => name).sort());
    for (const [name, configuration] of Object.entries(CONFIGURATIONS)) {
      expect(stored.get(name)?.configuration).toBe(configuration);
      expect(stored.get(name)?.configuration).toMatch(/^[A-Za-z]+$/);
    }
    expect(stored.get('com.example:both-lib')?.version).toBe('1.2.3');

    root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-gradle-scope-'));
    fs.writeFileSync(path.join(root, fileName), source);

    const projects = await scanJavaProjects(root, offlineMavenCache());
    expect(projects).toHaveLength(1);
    const project = projects[0]!;
    expect(project.dependencies.map((dep) => [dep.package, dep.section])).toEqual(SECTIONS);

    const both = project.dependencies.find((dep) => dep.package === 'com.example:both-lib');
    expect(both?.currentSpec).toBe('1.2.3');
    expect(both?.section).toBe('dependencies');

    const scanArtifact = artifact(projects, rootPath);
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

    for (const [name] of SECTIONS) {
      expect(byName.get(name)?.scope).toBe(DEV.has(name) ? 'excluded' : undefined);
    }

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
    for (const [name] of SECTIONS) {
      expect(rel(name)).toEqual(
        DEV.has(name)
          ? { relationshipType: 'DEV_DEPENDENCY_OF', relatedSpdxElementId: 'SPDXRef-DOCUMENT' }
          : undefined,
      );
    }
    expect(spdx.relationships.some((row) => row.relationshipType === 'DEPENDS_ON')).toBe(false);
  });
});

/**
 * Maven `<scope>test</scope>` is a development row. A direct
 * `<optional>true</optional>` is an optional row. Test wins when both are set.
 * `compile` / `runtime` / `provided` / `system` / a missing scope and
 * `<optional>false</optional>` stay production. A `<dependencyManagement>`
 * `<optional>` stays production; a managed test scope is still development.
 */
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { scanJavaProjects } from '../src/core-open/scanners/java-scanner.js';
import { MavenCache } from '../src/core-open/scanners/maven-cache.js';
import { Semaphore } from '../src/core-open/utils/semaphore.js';
import { collectLockfileGraph, toCycloneDx, toSpdx } from '../src/reporting/commands/sbom.js';
import type { ProjectScan, ScanArtifact } from '../src/reporting/types.js';

const fixtureDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures/maven-sbom-scope');

function artifact(projects: ProjectScan[]): ScanArtifact {
  return {
    schemaVersion: '1.0',
    timestamp: '2026-02-19T00:00:00.000Z',
    vibgrateVersion: '0.0.1',
    rootPath: 'maven-sbom-scope',
    drift: {
      score: 0,
      riskLevel: 'low',
      components: { runtimeScore: 0, frameworkScore: 0, dependencyScore: 0, eolScore: 0 },
    },
    findings: [],
    projects,
  };
}

describe('sbom export: Maven test scope and optional dependencies', () => {
  it('marks test and optional rows and leaves production scopes unmarked', async () => {
    const projects = await scanJavaProjects(fixtureDir, new MavenCache(new Semaphore(1), undefined, true));
    expect(projects).toHaveLength(1);
    expect(projects[0]!.dependencies.map((dep) => [dep.package, dep.section])).toEqual([
      ['com.example:compile-lib', 'dependencies'],
      ['com.example:managed-optional-lib', 'dependencies'],
      ['com.example:managed-test-lib', 'devDependencies'],
      ['com.example:optional-false-lib', 'dependencies'],
      ['com.example:optional-lib', 'optionalDependencies'],
      ['com.example:provided-lib', 'dependencies'],
      ['com.example:runtime-lib', 'dependencies'],
      ['com.example:system-lib', 'dependencies'],
      ['com.example:test-lib', 'devDependencies'],
      ['com.example:test-optional-lib', 'devDependencies'],
      ['com.example:unscoped-lib', 'dependencies'],
    ]);

    const scanArtifact = artifact(projects);
    const graph = collectLockfileGraph(scanArtifact, fixtureDir);
    const cdx = toCycloneDx(scanArtifact, graph) as {
      components: Array<{ name: string; scope?: string; properties: Array<{ name: string; value: string }> }>;
      dependencies?: unknown;
    };
    const byName = new Map(cdx.components.map((component) => [component.name, component]));
    const vibScope = (name: string): string | undefined =>
      byName.get(name)?.properties.find((property) => property.name === 'vibgrate:scope')?.value;

    expect(byName.get('com.example:test-lib')?.scope).toBe('excluded');
    expect(byName.get('com.example:test-optional-lib')?.scope).toBe('excluded');
    expect(byName.get('com.example:managed-test-lib')?.scope).toBe('excluded');
    expect(byName.get('com.example:optional-lib')?.scope).toBe('optional');
    expect(byName.get('com.example:compile-lib')?.scope).toBeUndefined();
    expect(byName.get('com.example:runtime-lib')?.scope).toBeUndefined();
    expect(byName.get('com.example:provided-lib')?.scope).toBeUndefined();
    expect(byName.get('com.example:system-lib')?.scope).toBeUndefined();
    expect(byName.get('com.example:unscoped-lib')?.scope).toBeUndefined();
    expect(byName.get('com.example:optional-false-lib')?.scope).toBeUndefined();
    expect(byName.get('com.example:managed-optional-lib')?.scope).toBeUndefined();
    for (const component of cdx.components) expect(vibScope(component.name)).toBe('direct');
    expect(cdx.dependencies).toBeUndefined();

    const spdx = toSpdx(scanArtifact, graph) as {
      packages: Array<{ name: string }>;
      relationships: Array<{ spdxElementId: string; relatedSpdxElementId: string; relationshipType: string }>;
    };
    const id = (name: string): string => `SPDXRef-Package-${spdx.packages.findIndex((pkg) => pkg.name === name) + 1}`;
    const marked = (name: string, relationshipType: string) => ({
      spdxElementId: id(name),
      relatedSpdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType,
    });
    expect(spdx.relationships).toEqual([
      marked('com.example:managed-test-lib', 'DEV_DEPENDENCY_OF'),
      marked('com.example:optional-lib', 'OPTIONAL_DEPENDENCY_OF'),
      marked('com.example:test-lib', 'DEV_DEPENDENCY_OF'),
      marked('com.example:test-optional-lib', 'DEV_DEPENDENCY_OF'),
    ]);
  });
});
/**
 * Maven `<scope>test</scope>` is a dev manifest row. `<optional>true</optional>`
 * is an optional row. Test scope wins when the same dependency is also optional.
 * compile, runtime, provided, system, import, a missing scope, and
 * `<optional>false</optional>` stay production.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MavenCache } from '../src/core-open/scanners/maven-cache.js';
import { scanJavaProjects } from '../src/core-open/scanners/java-scanner.js';
import { Semaphore } from '../src/core-open/utils/semaphore.js';
import { collectLockfileGraph, toCycloneDx, toSpdx } from '../src/reporting/commands/sbom.js';
import type { ProjectScan, ScanArtifact } from '../src/reporting/types.js';

const FIXTURE = fileURLToPath(new URL('./fixtures/maven-scopes/pom.xml', import.meta.url));

/** package → section. Order is the scanner's code-unit sort (all drift unknown). */
const SECTIONS: Array<[string, string]> = [
  ['com.example:bom-import', 'dependencies'],
  ['com.example:compile-lib', 'dependencies'],
  ['com.example:managed-optional-lib', 'optionalDependencies'],
  ['com.example:managed-test-lib', 'devDependencies'],
  ['com.example:optional-false-lib', 'dependencies'],
  ['com.example:optional-lib', 'optionalDependencies'],
  ['com.example:optional-text-lib', 'optionalDependencies'],
  ['com.example:provided-lib', 'dependencies'],
  ['com.example:runtime-lib', 'dependencies'],
  ['com.example:system-lib', 'dependencies'],
  ['com.example:test-case-lib', 'devDependencies'],
  ['com.example:unscoped-lib', 'dependencies'],
  ['junit:junit', 'devDependencies'],
  ['org.mockito:mockito-core', 'devDependencies'],
];

function artifact(projects: ProjectScan[]): ScanArtifact {
  return {
    schemaVersion: '1.0',
    timestamp: '2026-02-19T00:00:00.000Z',
    vibgrateVersion: '0.0.1',
    rootPath: 'maven-scopes',
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

describe('sbom export: Maven test scope and optional dependencies', () => {
  let root: string;

  afterEach(() => {
    vi.restoreAllMocks();
    if (root) fs.rmSync(root, { recursive: true, force: true });
  });

  it('marks test and optional rows in the scan and in CycloneDX and SPDX', async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-maven-scope-'));
    fs.copyFileSync(FIXTURE, path.join(root, 'pom.xml'));

    const projects = await scanJavaProjects(root, offlineMavenCache());
    expect(projects).toHaveLength(1);
    const project = projects[0]!;
    expect(project.dependencies.map((dep) => [dep.package, dep.section])).toEqual(SECTIONS);

    const compile = project.dependencies.find((dep) => dep.package === 'com.example:compile-lib');
    expect(compile?.currentSpec).toBe('1.2.3');
    expect(compile?.section).toBe('dependencies');

    const scanArtifact = artifact(projects);
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
    expect(scopeOf('com.example:compile-lib')).toBeUndefined();
    expect(scopeOf('com.example:runtime-lib')).toBeUndefined();
    expect(scopeOf('com.example:provided-lib')).toBeUndefined();
    expect(scopeOf('com.example:system-lib')).toBeUndefined();
    expect(scopeOf('com.example:unscoped-lib')).toBeUndefined();
    expect(scopeOf('com.example:optional-false-lib')).toBeUndefined();
    expect(scopeOf('com.example:bom-import')).toBeUndefined();
    expect(scopeOf('junit:junit')).toBe('excluded');
    expect(scopeOf('com.example:test-case-lib')).toBe('excluded');
    expect(scopeOf('org.mockito:mockito-core')).toBe('excluded');
    expect(scopeOf('com.example:managed-test-lib')).toBe('excluded');
    expect(scopeOf('com.example:optional-lib')).toBe('optional');
    expect(scopeOf('com.example:optional-text-lib')).toBe('optional');
    expect(scopeOf('com.example:managed-optional-lib')).toBe('optional');

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
    expect(rel('junit:junit')).toEqual({ relationshipType: 'DEV_DEPENDENCY_OF', relatedSpdxElementId: 'SPDXRef-DOCUMENT' });
    expect(rel('com.example:test-case-lib')).toEqual({ relationshipType: 'DEV_DEPENDENCY_OF', relatedSpdxElementId: 'SPDXRef-DOCUMENT' });
    expect(rel('org.mockito:mockito-core')).toEqual({ relationshipType: 'DEV_DEPENDENCY_OF', relatedSpdxElementId: 'SPDXRef-DOCUMENT' });
    expect(rel('com.example:managed-test-lib')).toEqual({ relationshipType: 'DEV_DEPENDENCY_OF', relatedSpdxElementId: 'SPDXRef-DOCUMENT' });
    expect(rel('com.example:optional-lib')).toEqual({ relationshipType: 'OPTIONAL_DEPENDENCY_OF', relatedSpdxElementId: 'SPDXRef-DOCUMENT' });
    expect(rel('com.example:optional-text-lib')).toEqual({ relationshipType: 'OPTIONAL_DEPENDENCY_OF', relatedSpdxElementId: 'SPDXRef-DOCUMENT' });
    expect(rel('com.example:managed-optional-lib')).toEqual({ relationshipType: 'OPTIONAL_DEPENDENCY_OF', relatedSpdxElementId: 'SPDXRef-DOCUMENT' });
    expect(rel('com.example:compile-lib')).toBeUndefined();
    expect(rel('com.example:optional-false-lib')).toBeUndefined();
    expect(rel('com.example:runtime-lib')).toBeUndefined();
    expect(rel('com.example:provided-lib')).toBeUndefined();
    expect(rel('com.example:system-lib')).toBeUndefined();
    expect(rel('com.example:unscoped-lib')).toBeUndefined();
    expect(rel('com.example:bom-import')).toBeUndefined();
    expect(spdx.relationships.some((row) => row.relationshipType === 'DEPENDS_ON')).toBe(false);
  });
});

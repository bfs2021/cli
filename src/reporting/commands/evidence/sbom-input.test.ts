import { readFileSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { buildRelease } from './release.js';
import { pushRelease } from './push-payload.js';
import { readCycloneDxInput, readSpdxInput, SBOM_INPUT_MAX_COMPONENTS, SBOM_INPUT_MAX_DEPTH } from './sbom-input.js';
import type { Release } from './types.js';

const fixtureDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../../../test/fixtures/sbom');

function load(name: string): unknown {
  return JSON.parse(readFileSync(path.join(fixtureDir, name), 'utf8'));
}

describe('CycloneDX input with no package URL and no CPE', () => {
  const doc = load('mixed.cdx.json');

  it('keeps named components, nests, and a CPE, and skips the rest once', () => {
    const read = readCycloneDxInput(doc, 'mixed.cdx.json');
    expect(read.components).toEqual([
      { name: 'bootloader', version: '1.4.2', type: 'firmware' },
      { name: 'both', version: '1.0.0', purl: 'pkg:npm/both@1.0.0', ecosystem: 'npm' },
      { name: 'dup', version: '1.0.0', type: 'file' },
      { name: 'dup', version: '1.0.0', type: 'library' },
      { name: 'left-pad', version: '1.3.0', purl: 'pkg:npm/left-pad@1.3.0', ecosystem: 'npm' },
      { name: 'nested-only', version: '0.1.0', purl: 'pkg:npm/nested-only@0.1.0', ecosystem: 'npm' },
      { name: 'openssl', version: '3.0.13', cpe: 'cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*', type: 'library' },
      { name: 'resnet50', version: '2.1.0', type: 'machine-learning-model' },
      { name: 'vendor-libfoo', version: '1.0.0', type: 'library' },
      { name: 'vendor/openssl/crypto/aes.c', version: '3.0.13', type: 'file' },
      { name: 'vendored-openssl', version: '3.0.13', type: 'library' },
    ]);
    expect(read.components.some((c) => c.name === 'device-firmware')).toBe(false);
    expect(read.warning).toBe('mixed.cdx.json: skipped 3 components with no package URL, no CPE, and no name and version');
    expect(readCycloneDxInput(doc, 'mixed.cdx.json')).toEqual(read);
  });
});

describe('SPDX input with no package URL and no CPE', () => {
  const doc = load('mixed.spdx.json');

  it('keeps named packages and files, ignores a relationship cycle, and warns once', () => {
    const started = performance.now();
    const read = readSpdxInput(doc, 'mixed.spdx.json');
    expect(performance.now() - started).toBeLessThan(1000);
    expect(read.components).toEqual([
      { name: 'bootloader', version: '1.4.2', type: 'firmware' },
      { name: 'both', version: '1.0.0', purl: 'pkg:npm/both@1.0.0', ecosystem: 'npm' },
      { name: 'dup', version: '1.0.0', type: 'file' },
      { name: 'dup', version: '1.0.0', type: 'library' },
      { name: 'left-pad', version: '1.3.0', purl: 'pkg:npm/left-pad@1.3.0', ecosystem: 'npm' },
      { name: 'loose', version: '1.0.0', type: 'package' },
      { name: 'openssl', version: '3.0.13', cpe: 'cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*', type: 'library' },
      { name: 'resnet50', version: '2.1.0', type: 'machine-learning-model' },
      { name: 'vendor/openssl/crypto/aes.c', version: '3.0.13', type: 'file' },
      { name: 'vendored-openssl', version: '3.0.13', type: 'source' },
    ]);
    expect(read.components.some((c) => c.name === 'device-firmware')).toBe(false);
    expect(read.warning).toBe('mixed.spdx.json: skipped 3 components with no package URL, no CPE, and no name and version');
    expect(readSpdxInput(doc, 'mixed.spdx.json')).toEqual(read);
  });
});

describe('large nested SBOM fixtures', () => {
  it('reads a CycloneDX tree in bounded time and keeps identifier-less rows', () => {
    const doc = load('nested.cdx.json');
    const started = performance.now();
    const read = readCycloneDxInput(doc, 'nested.cdx.json');
    expect(performance.now() - started).toBeLessThan(1000);
    expect(read.components).toHaveLength(345);
    expect(read.components.find((c) => c.name === 'left-pad')).toEqual({ name: 'left-pad', version: '1.3.0', purl: 'pkg:npm/left-pad@1.3.0', ecosystem: 'npm' });
    expect(read.components.find((c) => c.name === 't.0.0.0.0')).toEqual({ name: 't.0.0.0.0', version: '1.0.0', type: 'library' });
    expect(read.components.find((c) => c.name === 'bootloader')).toEqual({ name: 'bootloader', version: '1.4.2', type: 'firmware' });
    expect(read.components.find((c) => c.name === 'resnet50')?.type).toBe('machine-learning-model');
    expect(read.components.find((c) => c.name === 'openssl')?.cpe).toBe('cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*');
    expect(read.warning).toBe('nested.cdx.json: skipped 1 component with no package URL, no CPE, and no name and version');
    expect(readCycloneDxInput(doc, 'nested.cdx.json')).toEqual(read);
  });

  it('reads an SPDX tree and a relationship cycle without looping', () => {
    const doc = load('nested.spdx.json');
    const started = performance.now();
    const read = readSpdxInput(doc, 'nested.spdx.json');
    expect(performance.now() - started).toBeLessThan(1000);
    expect(read.components).toHaveLength(346);
    expect(read.components.some((c) => c.name === 'nested-tree')).toBe(false);
    expect(read.components.find((c) => c.name === 't.0.0.0.0')).toEqual({ name: 't.0.0.0.0', version: '1.0.0', type: 'library' });
    expect(read.components.find((c) => c.name === 'vendor/openssl/crypto/aes.c')).toEqual({ name: 'vendor/openssl/crypto/aes.c', version: '3.0.13', type: 'file' });
    expect(read.warning).toBe('nested.spdx.json: skipped 2 components with no package URL, no CPE, and no name and version');
    expect(readSpdxInput(doc, 'nested.spdx.json')).toEqual(read);
  });
});

describe('bounds', () => {
  it('stops a wide document at the component cap', () => {
    const components = Array.from({ length: SBOM_INPUT_MAX_COMPONENTS + 1 }, (_, i) => ({ type: 'library', name: `p${i}`, version: '1' }));
    const started = performance.now();
    const read = readCycloneDxInput({ bomFormat: 'CycloneDX', components }, 'wide.cdx.json');
    expect(performance.now() - started).toBeLessThan(3000);
    expect(read.components).toHaveLength(SBOM_INPUT_MAX_COMPONENTS);
    expect(read.components.some((c) => c.name === `p${SBOM_INPUT_MAX_COMPONENTS}`)).toBe(false);
    expect(read.warning).toBe(`wide.cdx.json: stopped after ${SBOM_INPUT_MAX_COMPONENTS} components; the rest of the document was not read`);
  });

  it('does not walk a cycle or a chain past the depth cap', () => {
    const a: Record<string, unknown> = { type: 'library', name: 'a', version: '1', components: [] };
    const b: Record<string, unknown> = { type: 'file', name: 'b', version: '1', components: [a] };
    (a.components as unknown[]).push(b);
    const started = performance.now();
    const cycled = readCycloneDxInput({ bomFormat: 'CycloneDX', components: [a] }, 'cycle.cdx.json');
    expect(performance.now() - started).toBeLessThan(1000);
    expect(cycled.components.map((c) => c.name).sort()).toEqual(['a', 'b']);
    expect(cycled.warning).toBeUndefined();

    let cursor: Record<string, unknown> = { type: 'file', name: 'd0', version: '1' };
    const root = cursor;
    for (let i = 1; i <= SBOM_INPUT_MAX_DEPTH + 8; i++) {
      const child: Record<string, unknown> = { type: 'file', name: `d${i}`, version: '1' };
      cursor.components = [child];
      cursor = child;
    }
    const deep = readCycloneDxInput({ bomFormat: 'CycloneDX', components: [root] }, 'deep.cdx.json');
    expect(deep.components).toHaveLength(SBOM_INPUT_MAX_DEPTH + 1);
    expect(deep.components.some((c) => c.name === `d${SBOM_INPUT_MAX_DEPTH}`)).toBe(true);
    expect(deep.components.some((c) => c.name === `d${SBOM_INPUT_MAX_DEPTH + 1}`)).toBe(false);
    expect(deep.warning).toBe(`deep.cdx.json: did not read components nested deeper than ${SBOM_INPUT_MAX_DEPTH}`);
  });

  it('does not throw on a broken document', () => {
    expect(readCycloneDxInput(null, 'empty.json')).toEqual({ components: [] });
    expect(readSpdxInput({ spdxVersion: 'SPDX-2.3' }, 'empty.spdx.json')).toEqual({ components: [] });
    expect(readCycloneDxInput({ components: 'nope' }, 'bad.json').components).toEqual([]);
    const odd = readCycloneDxInput(
      { components: [{ name: 'x', version: '1', purl: 12, type: 'library' }, { name: 'y', version: '1', purl: 'not a purl', cpe: 'cpe:/a:acme:y:1.0' }] },
      'odd.json',
    );
    expect(odd.components).toEqual([
      { name: 'x', version: '1', type: 'library' },
      { name: 'y', version: '1', cpe: 'cpe:/a:acme:y:1.0', type: 'unknown' },
    ]);
    expect(odd.warning).toBeUndefined();
  });
});

describe('release freeze', () => {
  it('prints one warning and keeps the identifier-less components', async () => {
    const dir = path.join(os.tmpdir(), `vg-sbom-input-${process.pid}`);
    const { mkdirSync, writeFileSync } = await import('node:fs');
    mkdirSync(dir, { recursive: true });
    const from = path.join(dir, 'mixed.cdx.json');
    // The reader fixture includes a nameless component and a null entry so a
    // direct read can skip them. `vg evidence release` rejects those before
    // the read (a missing name fails the document). This freeze uses the same
    // inventory with those rows removed and a document version added, and
    // still skips the named file that has no version.
    const doc = JSON.parse(readFileSync(path.join(fixtureDir, 'mixed.cdx.json'), 'utf8')) as {
      version?: number;
      components?: unknown[];
    };
    doc.version = 1;
    doc.components = (doc.components ?? []).filter(
      (component) =>
        component !== null &&
        typeof component === 'object' &&
        typeof (component as { name?: unknown }).name === 'string',
    );
    writeFileSync(from, JSON.stringify(doc));
    const warnings: string[] = [];
    const release = await buildRelease({
      productId: 'device',
      version: '1.0.0',
      from,
      fromExplicit: true,
      distribution: [],
      frozenAt: '2026-10-10T00:00:00.000Z',
      onWarning: (message) => warnings.push(message),
    });
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('skipped 1 component');
    expect(release.components.find((c) => c.name === 'resnet50')?.type).toBe('machine-learning-model');
    expect(release.components.find((c) => c.name === 'left-pad')?.purl).toBe('pkg:npm/left-pad@1.3.0');
    expect(release.components.some((c) => c.name === 'README')).toBe(false);

    const pushed = pushRelease({ ...release, manifestFormat: 'vibgrate-frozen-1' } as Release);
    const model = pushed.components.find((c) => c.name === 'resnet50');
    expect(model).toEqual({ name: 'resnet50', version: '2.1.0', ecosystem: undefined, purl: undefined, type: 'machine-learning-model' });
    const openssl = pushed.components.find((c) => c.name === 'openssl');
    expect(openssl?.cpe).toBe('cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*');
  });
});

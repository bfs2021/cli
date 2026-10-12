// Reading a CycloneDX or SPDX document as an input to a frozen release.
//
// Some components are not registry packages. Vendored source, a file, firmware,
// and a machine-learning model often have a name and a version and neither a
// package URL nor a CPE. Those are kept. The identity is name + version + type.
// A component that cannot form that identity, and has no package URL and no
// CPE, is counted and skipped. One file produces at most one warning.
//
// The walk is iterative, deduped by object identity, and capped, so a nested
// document or a cycle cannot loop or grow without bound. No network.

import type { FrozenComponent } from './types.js';

/** Components visited in one document. Past this the rest is not read. */
export const SBOM_INPUT_MAX_COMPONENTS = 50_000;
/** Nesting depth of `components` / `packages`. Deeper lists are not read. */
export const SBOM_INPUT_MAX_DEPTH = 32;

const MAX_NAME = 512;
const MAX_PURL = 1024;
const MAX_CPE = 512;
const MAX_REFS = 32;
const MAX_LABEL = 240;

const PURL_ECOSYSTEM: Record<string, string> = {
  npm: 'npm',
  pypi: 'PyPI',
  maven: 'Maven',
  nuget: 'NuGet',
  golang: 'Go',
  cargo: 'crates.io',
  gem: 'RubyGems',
  composer: 'Packagist',
  pub: 'Pub',
  hex: 'Hex',
  deb: 'Debian',
  apk: 'Alpine',
  rpm: 'RPM',
};

export interface InputSbomRead {
  components: FrozenComponent[];
  /** One coalesced warning for this file, or absent when nothing was skipped. */
  warning?: string;
}

interface WalkFrame {
  list: unknown[];
  index: number;
  depth: number;
  kind: 'cdx' | 'spdx-package' | 'spdx-file';
}

interface Described {
  name?: string;
  version?: string;
  purl?: string;
  cpe?: string;
  type: string;
  /** The document subject (the image itself), not a component of the release. */
  subject: boolean;
}

function ecosystemForPurl(purl: string): string | undefined {
  const m = /^pkg:([^/]+)\//.exec(purl);
  if (!m) return undefined;
  return PURL_ECOSYSTEM[m[1].toLowerCase()];
}

function boundedText(value: unknown, max: number): string | undefined {
  if (typeof value !== 'string') return undefined;
  const text = value.trim();
  if (!text || text.length > max) return undefined;
  if (/[\r\n\u0000]/u.test(text)) return undefined;
  return text;
}

function asPurl(value: unknown): string | undefined {
  const purl = boundedText(value, MAX_PURL);
  if (!purl || !purl.startsWith('pkg:') || /\s/u.test(purl)) return undefined;
  return purl;
}

function asCpe(value: unknown): string | undefined {
  const cpe = boundedText(value, MAX_CPE);
  if (!cpe || !/^cpe:(?:2\.2:|2\.3:|\/)/.test(cpe) || /\s/u.test(cpe)) return undefined;
  return cpe;
}

/** Stable type token. Omitted or unusable values become `fallback`. */
export function componentTypeToken(value: unknown, fallback: string): string {
  if (typeof value !== 'string') return fallback;
  const token = value.trim().toLowerCase().replace(/_/g, '-');
  if (!token || token.length > 64) return fallback;
  if (!/^[a-z0-9][a-z0-9.+-]*$/.test(token)) return fallback;
  return token;
}

function warningLabel(label: string): string {
  const clean = label.replace(/[\r\n\t]/g, ' ').trim();
  const text = clean.length > 0 ? clean : 'SBOM';
  return text.length > MAX_LABEL ? `${text.slice(0, MAX_LABEL - 3)}...` : text;
}

function formatWarning(label: string, unidentified: number, capped: boolean, tooDeep: boolean): string | undefined {
  const parts: string[] = [];
  if (unidentified > 0) {
    const noun = unidentified === 1 ? 'component' : 'components';
    parts.push(`skipped ${unidentified} ${noun} with no package URL, no CPE, and no name and version`);
  }
  if (capped) {
    parts.push(`stopped after ${SBOM_INPUT_MAX_COMPONENTS} components; the rest of the document was not read`);
  }
  if (tooDeep) {
    parts.push(`did not read components nested deeper than ${SBOM_INPUT_MAX_DEPTH}`);
  }
  if (parts.length === 0) return undefined;
  return `${warningLabel(label)}: ${parts.join('; ')}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function refList(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) return [];
  const out: Record<string, unknown>[] = [];
  const n = Math.min(value.length, MAX_REFS);
  for (let i = 0; i < n; i++) {
    if (isRecord(value[i])) out.push(value[i] as Record<string, unknown>);
  }
  return out;
}

function purlFromRefs(refs: unknown): string | undefined {
  for (const ref of refList(refs)) {
    const type = typeof ref.referenceType === 'string' ? ref.referenceType.toLowerCase() : '';
    if (type === 'purl') {
      const purl = asPurl(ref.referenceLocator);
      if (purl) return purl;
    }
  }
  return undefined;
}

function cpeFromRefs(refs: unknown): string | undefined {
  for (const ref of refList(refs)) {
    const type = typeof ref.referenceType === 'string' ? ref.referenceType.toLowerCase() : '';
    if (type === 'cpe22type' || type === 'cpe23type' || type === 'cpe22' || type === 'cpe23') {
      const cpe = asCpe(ref.referenceLocator);
      if (cpe) return cpe;
    }
  }
  return undefined;
}

function describeCdx(node: Record<string, unknown>): Described {
  return {
    name: boundedText(node.name, MAX_NAME),
    version: boundedText(node.version, MAX_NAME),
    purl: asPurl(node.purl),
    cpe: asCpe(node.cpe),
    type: componentTypeToken(node.type, 'unknown'),
    subject: false,
  };
}

function describeSpdxPackage(node: Record<string, unknown>): Described {
  const purl = purlFromRefs(node.externalRefs);
  const type = componentTypeToken(node.primaryPackagePurpose, 'package');
  return {
    name: boundedText(node.name, MAX_NAME),
    version: boundedText(node.versionInfo, MAX_NAME),
    purl,
    cpe: cpeFromRefs(node.externalRefs),
    type,
    subject: type === 'container' || Boolean(purl?.startsWith('pkg:oci/')),
  };
}

function describeSpdxFile(node: Record<string, unknown>): Described {
  return {
    name: boundedText(node.fileName, MAX_NAME) ?? boundedText(node.name, MAX_NAME),
    version: boundedText(node.versionInfo, MAX_NAME),
    purl: purlFromRefs(node.externalRefs),
    cpe: cpeFromRefs(node.externalRefs),
    type: 'file',
    subject: false,
  };
}

function describe(node: Record<string, unknown>, kind: WalkFrame['kind']): Described {
  if (kind === 'cdx') return describeCdx(node);
  if (kind === 'spdx-file') return describeSpdxFile(node);
  return describeSpdxPackage(node);
}

function childLists(node: Record<string, unknown>, kind: WalkFrame['kind']): Array<{ list: unknown; kind: WalkFrame['kind'] }> {
  if (kind === 'cdx') return [{ list: node.components, kind: 'cdx' }];
  if (kind === 'spdx-package') {
    return [
      { list: node.packages, kind: 'spdx-package' },
      { list: node.files, kind: 'spdx-file' },
    ];
  }
  return [];
}

function cmp(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function identityKey(component: FrozenComponent): string {
  if (component.purl) return `purl\0${component.purl}`;
  if (component.cpe) return `cpe\0${component.cpe}`;
  return `id\0${component.type ?? ''}\0${component.name}\0${component.version}`;
}

/**
 * Walk component lists. Object identity breaks cycles. A count cap and a depth
 * cap stop a wide or deep document. The same identity is one component; the
 * first one in document order is kept.
 */
function readComponents(roots: WalkFrame[], label: string): InputSbomRead {
  // Stack: the last frame is next. Push roots in reverse so the first root is read first.
  const frames: WalkFrame[] = [];
  for (let i = roots.length - 1; i >= 0; i--) {
    const root = roots[i];
    if (root && root.list.length > 0) frames.push(root);
  }
  const seen = new WeakSet<object>();
  const byKey = new Map<string, FrozenComponent>();
  let unidentified = 0;
  let visited = 0;
  let capped = false;
  let tooDeep = false;

  while (frames.length > 0) {
    const frame = frames[frames.length - 1]!;
    if (frame.index >= frame.list.length) {
      frames.pop();
      continue;
    }
    if (frame.depth > SBOM_INPUT_MAX_DEPTH) {
      tooDeep = true;
      frame.index = frame.list.length;
      continue;
    }
    if (visited >= SBOM_INPUT_MAX_COMPONENTS) {
      capped = true;
      break;
    }
    const node = frame.list[frame.index];
    frame.index += 1;
    visited += 1;
    if (!isRecord(node)) {
      unidentified += 1;
      continue;
    }
    if (seen.has(node)) continue;
    seen.add(node);

    const hit = describe(node, frame.kind);
    if (!hit.subject) {
      const component = toComponent(hit);
      if (!component) unidentified += 1;
      else if (!byKey.has(identityKey(component))) byKey.set(identityKey(component), component);
    }

    const depth = frame.depth + 1;
    if (depth > SBOM_INPUT_MAX_DEPTH) {
      const nested = childLists(node, frame.kind).some((child) => Array.isArray(child.list) && child.list.length > 0);
      if (nested) tooDeep = true;
      continue;
    }
    const children = childLists(node, frame.kind);
    for (let i = children.length - 1; i >= 0; i--) {
      const child = children[i]!;
      if (Array.isArray(child.list) && child.list.length > 0) {
        frames.push({ list: child.list, index: 0, depth, kind: child.kind });
      }
    }
  }

  const components = [...byKey.values()].sort(
    (a, b) => cmp(a.name, b.name) || cmp(a.version, b.version) || cmp(a.type ?? '', b.type ?? '') || cmp(a.purl ?? '', b.purl ?? '') || cmp(a.cpe ?? '', b.cpe ?? ''),
  );
  const warning = formatWarning(label, unidentified, capped, tooDeep);
  return warning ? { components, warning } : { components };
}

function toComponent(hit: Described): FrozenComponent | undefined {
  if (!hit.name || !hit.version) return undefined;
  if (hit.purl) {
    const ecosystem = ecosystemForPurl(hit.purl);
    return ecosystem ? { name: hit.name, version: hit.version, purl: hit.purl, ecosystem } : { name: hit.name, version: hit.version, purl: hit.purl };
  }
  if (hit.cpe) return { name: hit.name, version: hit.version, cpe: hit.cpe, type: hit.type };
  return { name: hit.name, version: hit.version, type: hit.type };
}

function rootList(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/** CycloneDX components, including nested `components` and metadata children. The metadata component itself is the document root and is not a row. */
export function readCycloneDxInput(doc: unknown, label: string): InputSbomRead {
  const root = isRecord(doc) ? doc : {};
  const metadata = isRecord(root.metadata) ? root.metadata : undefined;
  const metaComponent = metadata && isRecord(metadata.component) ? metadata.component : undefined;
  return readComponents(
    [
      { list: rootList(root.components), index: 0, depth: 0, kind: 'cdx' },
      { list: rootList(metaComponent?.components), index: 0, depth: 0, kind: 'cdx' },
    ],
    label,
  );
}

/**
 * SPDX 2.x packages and files, including a nested `packages` list. Relationship
 * edges are not a second inventory and are not followed. A package whose
 * purpose is `CONTAINER`, or whose package URL is `pkg:oci/`, is the image
 * itself and is not a component.
 */
export function readSpdxInput(doc: unknown, label: string): InputSbomRead {
  const root = isRecord(doc) ? doc : {};
  return readComponents(
    [
      { list: rootList(root.packages), index: 0, depth: 0, kind: 'spdx-package' },
      { list: rootList(root.files), index: 0, depth: 0, kind: 'spdx-file' },
    ],
    label,
  );
}

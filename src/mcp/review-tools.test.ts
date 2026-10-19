import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { VgGraph } from '../schema.js';
import { COMPRESS_TOOLS } from './compress-tools.js';
import { REVIEW_TOOLS } from './review-tools.js';
import { advertisedAnnotations, extraToolsFor } from './server.js';
import { HOT_TOOLS, TOOLS } from './tools.js';

/**
 * `review_doc`: listed only on request, honest about what it writes, and a
 * thin adapter over the saved-document store — driven here the way an agent
 * drives it, against a real git repository.
 */

const names = (opts: Parameters<typeof extraToolsFor>[0]) => extraToolsFor(opts, '/repo').map((t) => t.name);
const tool = REVIEW_TOOLS[0];
const call = (root: string, args: Record<string, unknown>) =>
  Promise.resolve(tool.handler({} as VgGraph, args, { root })) as Promise<Record<string, unknown>>;

describe('what `vg serve` advertises', () => {
  it('a default `vg serve` lists no review tool; `--review` adds exactly one', () => {
    expect(names({})).toEqual([]);
    expect(names({ compressTools: true, memory: true })).not.toContain('review_doc');
    expect(names({ review: true })).toEqual(['review_doc']);
  });

  it('stays out of the hot core and never shadows a code-map tool', () => {
    expect(HOT_TOOLS).not.toContain('review_doc' as never);
    expect(TOOLS.map((t) => t.name)).not.toContain('review_doc');
  });

  it('declares that it writes, that what it writes is never destroyed, and that comments reach Cloud', () => {
    expect(tool.annotations).toEqual({ readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true });
    expect(advertisedAnnotations(tool)).toEqual(tool.annotations);
    expect(tool.description).toMatch(/op "reply" answers a thread/);
    expect(tool.graphless).toBe(true);
    expect(tool.description).toMatch(/write what and why first/);
    expect(tool.description).toMatch(/recorded as origin "agent"/);
  });

  it('keeps write tools off unless that mode is requested, and keeps read-only annotations on the rest', () => {
    expect(extraToolsFor({}, '/repo')).toEqual([]);
    expect(extraToolsFor({ compressTools: true, memory: true }, '/repo').map((t) => t.name)).not.toContain('review_doc');
    expect(TOOLS.map((t) => t.name)).not.toContain('review_doc');
    for (const listed of TOOLS) {
      const annotations = advertisedAnnotations(listed);
      expect(annotations.readOnlyHint, listed.name).toBe(true);
      expect(annotations.destructiveHint, listed.name).not.toBe(true);
    }
    const review = extraToolsFor({ review: true }, '/repo');
    expect(review.map((t) => t.name)).toEqual(['review_doc']);
    expect(advertisedAnnotations(review[0]!)).toEqual({
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    });
    // Compression and memory writes stay unlisted on a review-only server.
    const reviewNames = new Set(review.map((t) => t.name));
    for (const write of ['compress_content', 'memory_save']) {
      expect(reviewNames.has(write)).toBe(false);
    }
    const compressWrite = COMPRESS_TOOLS.find((t) => t.name === 'compress_content');
    expect(advertisedAnnotations(compressWrite!)).toMatchObject({
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
    });
  });
});

describe('review_doc, as an agent uses it', () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const r of roots.splice(0)) fs.rmSync(r, { recursive: true, force: true });
  });
  const git = (cwd: string, ...args: string[]) => {
    const res = spawnSync('git', args, { cwd, encoding: 'utf8' });
    if (res.status !== 0) throw new Error(`git ${args.join(' ')}: ${res.stderr}`);
  };
  function repo(parentDir?: string): string {
    const root = fs.realpathSync(fs.mkdtempSync(path.join(parentDir ?? os.tmpdir(), 'vg-review-tool-')));
    roots.push(root);
    git(root, 'init', '-q', '-b', 'main');
    git(root, 'config', 'user.email', 'test@example.com');
    git(root, 'config', 'user.name', 'Test');
    fs.mkdirSync(path.join(root, 'src'));
    fs.writeFileSync(path.join(root, '.gitignore'), '.vibgrate/\n');
    fs.writeFileSync(path.join(root, 'src/a.ts'), 'export const a = 1;\nexport const b = 2;\n');
    git(root, 'add', '-A');
    git(root, 'commit', '-q', '-m', 'base');
    fs.writeFileSync(path.join(root, 'src/a.ts'), 'export const a = 1;\nexport const b = validate(2);\n');
    return root;
  }

  it('reads the comments on the pushed copy and answers one, with the DSN, naming the same change', async () => {
    const root = repo();
    const opened = await call(root, { op: 'open' });
    const id = opened.doc_id as string;
    const sent: { url: string; body: Record<string, unknown> }[] = [];
    vi.stubEnv('VIBGRATE_DSN', 'vibgrate+https://key_1:s3cret@us.ingest.vibgrate.com/ws_1');
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      sent.push({ url, body });
      if (url.endsWith('/comments')) {
        return new Response(
          JSON.stringify({
            status: 'ok',
            title: 'Review',
            comments: [
              { id: 'rdc_1', blockId: 'blk_1', blockTitle: 'Design', parentId: null, authorKind: 'person', authorName: 'Ada', body: 'Why?', createdAt: 't', resolvedAt: null },
              { id: 'rdc_2', blockId: 'blk_2', blockTitle: null, parentId: null, authorKind: 'person', authorName: 'Bo', body: 'Done', createdAt: 't', resolvedAt: 't' },
            ],
          }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({ status: 'ok', comment: { id: 'rdc_3', parentId: body.parent_id, authorKind: 'agent', authorName: 'Agent (review_doc)', body: body.body } }), { status: 201 });
    });
    try {
      const listed = await call(root, { op: 'comments', doc_id: id });
      expect(listed).toMatchObject({ doc_id: id, resolved: 1, open: [{ id: 'rdc_1', comments: [{ authorName: 'Ada', body: 'Why?' }] }] });
      const replied = await call(root, { op: 'reply', doc_id: id, comment_id: 'rdc_1', text: 'Because the base side was not built.' });
      expect(replied).toMatchObject({ replied: true, comment: { authorKind: 'agent' } });
      expect(sent.map((s) => s.url)).toEqual([
        'https://us.ingest.vibgrate.com/v1/ingest/review-doc/comments',
        'https://us.ingest.vibgrate.com/v1/ingest/review-doc/reply',
      ]);
      const doc = (opened.doc ?? {}) as { target: { repo_key: string; head_sha: string; base_sha: string } };
      expect(sent[1].body).toMatchObject({ repo_key: doc.target.repo_key, head_sha: doc.target.head_sha, base_sha: doc.target.base_sha, parent_id: 'rdc_1' });
      expect(await call(root, { op: 'reply', doc_id: id, comment_id: 'rdc_1' })).toMatchObject({ error: 'bad_request' });
    } finally {
      vi.unstubAllGlobals();
      vi.unstubAllEnvs();
    }
  });

  it('open → write what and why → check → history → restore', async () => {
    const root = repo();
    const opened = await call(root, { op: 'open' });
    expect(opened).toMatchObject({ version: 1, built: true });
    const id = opened.doc_id as string;
    const outline = opened.outline as { sections: { kind: string; blocks: { id: string }[] }[] };
    const first = outline.sections[0].blocks[0].id;

    const patched = await call(root, {
      op: 'patch',
      doc_id: id,
      version: 1,
      ops: [{ op: 'set_text', block: first, text: 'Validates `b` before export — [the change](head:src/a.ts#L2).' }],
    });
    expect(patched).toMatchObject({ saved: true, version: 2 });

    const block = await call(root, { op: 'get', doc_id: id, block: first });
    expect(block).toMatchObject({ section: 'what_why', block: { origin: 'agent' } });

    expect(await call(root, { op: 'check', doc_id: id })).toEqual({ doc_id: id, version: 2, valid: true, issues: [] });
    const history = (await call(root, { op: 'history', doc_id: id })) as { versions: { version: number; by: string }[] };
    expect(history.versions.map((v) => [v.version, v.by])).toEqual([[2, 'agent'], [1, 'vg']]);
    expect(await call(root, { op: 'restore', doc_id: id, version: 1 })).toMatchObject({ saved: true, version: 3 });
  });

  it('says what is wrong instead of saving a bad patch', async () => {
    const root = repo();
    const { doc_id } = await call(root, { op: 'open' });
    expect(await call(root, { op: 'patch', doc_id, ops: [] })).toEqual({ error: 'bad_request', message: 'patch needs version: the version you read' });
    const stale = await call(root, { op: 'patch', doc_id, version: 7, ops: [{ op: 'set_title', title: 'x' }] });
    expect(stale).toMatchObject({ saved: false, conflict: true, version: 1 });
    expect(await call(root, { op: 'rewrite', doc_id })).toMatchObject({ error: 'bad_request' });
    expect(await call(root, { op: 'get' })).toMatchObject({ error: 'bad_request', message: 'op "get" needs doc_id — call op "open" first' });
    expect(await call(root, { op: 'get', doc_id: 'rd_000000000000' })).toMatchObject({ error: 'review_doc_failed' });
  });

  it('rejects a document id or pin that leaves the repository, and a text over the size limit', async () => {
    // The parent of a repo in os.tmpdir() is the shared temp dir. Other tests
    // create and delete entries there, so the "nothing escaped" listing has to
    // use a private parent.
    const sandbox = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-review-confine-')));
    roots.push(sandbox);
    const root = repo(sandbox);
    const parent = path.dirname(root);
    const before = fs.readdirSync(parent).sort();
    const outside = path.join(parent, 'outside.json');

    const badId = await call(root, {
      op: 'patch',
      doc_id: '../outside',
      version: 1,
      ops: [{ op: 'set_title', title: 'escaped' }],
    });
    expect(badId).toMatchObject({ error: 'review_doc_failed' });
    expect(String(badId.message)).toMatch(/not a review document id/);
    expect(fs.existsSync(outside)).toBe(false);

    const opened = await call(root, { op: 'open' });
    const id = opened.doc_id as string;
    const outline = opened.outline as { sections: { blocks: { id: string }[] }[] };
    const blockId = outline.sections[0]?.blocks[0]?.id;
    expect(blockId).toBeTruthy();
    expect(id).toMatch(/^rd_[0-9a-f]{12}$/);
    const store = path.join(root, '.vibgrate', 'review-docs', id);
    expect(fs.existsSync(store)).toBe(true);

    for (const pinPath of ['../secret.txt', '../../etc/passwd', '/etc/passwd', 'C:/secret.txt']) {
      const escaped = await call(root, {
        op: 'patch',
        doc_id: id,
        version: 1,
        ops: [{
          op: 'insert',
          section: 'design',
          at: 'start',
          block: { type: 'code_peek', pin: { side: 'head', path: pinPath, start: 1, end: 1 } },
        }],
      });
      expect(escaped, pinPath).toMatchObject({ saved: false });
      expect(JSON.stringify(escaped), pinPath).toMatch(/repository-relative/);
    }

    const huge = await call(root, {
      op: 'patch',
      doc_id: id,
      version: 1,
      ops: [{ op: 'set_text', block: blockId, text: 'x'.repeat(20_001) }],
    });
    expect(huge).toMatchObject({ saved: false });
    expect(JSON.stringify(huge)).toMatch(/exceeds 20000 characters/);

    const names = fs.readdirSync(path.join(root, '.vibgrate', 'review-docs')).sort();
    expect(names.every((name) => name === 'scratchpad.json' || /^rd_[0-9a-f]{12}$/.test(name))).toBe(true);
    expect(fs.readdirSync(parent).sort()).toEqual(before);
    expect(fs.existsSync(outside)).toBe(false);
  });

  it('works outside a git repository only to say so', async () => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-review-tool-nogit-')));
    roots.push(dir);
    const res = await call(dir, { op: 'open' });
    expect(res).toMatchObject({ error: 'review_doc_failed' });
    expect(String(res.message)).toMatch(/needs a git repository/);
  });
});

describe('review_doc op "explain"', () => {
  let root: string;
  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));
  const fnNode = (id: string, file: string, start: number, end: number) => ({
    id, kind: 'function', name: id, qualifiedName: id, file, span: { start, end }, lang: 'ts', importance: 0.1,
    centrality: { degree: 0, pagerank: 0, betweenness: 0, eigenvector: 0 }, area: 0, isHub: false,
  });
  const graph = {
    schemaVersion: 'vg-graph/1.1',
    nodes: [fnNode('main', 'src/app.ts', 1, 3), fnNode('save', 'src/store.ts', 2, 4)],
    edges: [{ id: 'call:main>save', kind: 'call', src: 'main', dst: 'save', resolution: 'tsc', confidence: 1, sites: [2] }],
    areas: [{ id: 0, label: 'app' }],
  } as unknown as VgGraph;
  const explain = (args: Record<string, unknown>, g: VgGraph = graph) =>
    Promise.resolve(tool.handler(g, { op: 'explain', ...args }, { root })) as Promise<Record<string, unknown>>;

  function setup(): void {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-review-explain-')));
    fs.mkdirSync(path.join(root, 'src'));
    fs.writeFileSync(path.join(root, 'src/app.ts'), 'a\nb\nc\n');
    fs.writeFileSync(path.join(root, 'src/store.ts'), 'a\nb\nc\nd\n');
  }

  it('returns the call path between two symbols, read-only and unsaved', async () => {
    setup();
    const res = await explain({ symbol: 'main', to: 'save' });
    expect(res).toMatchObject({ doc_id: null, version: null, saved: false });
    expect((res.doc as { kind: string; title: string }).title).toBe('Path: main → save');
    expect(fs.existsSync(path.join(root, '.vibgrate', 'review-docs'))).toBe(false);
  });

  it('keeps an explanation on the scratchpad, which the agent then reads and patches by id', async () => {
    setup();
    const kept = await explain({ symbol: 'main', to: 'save', keep: true });
    expect(kept).toMatchObject({ doc_id: 'scratchpad', version: 1, saved: true, kept: 'Path: main → save' });
    const call2 = (args: Record<string, unknown>) => Promise.resolve(tool.handler(graph, args, { root })) as Promise<Record<string, unknown>>;
    const got = await call2({ op: 'get', doc_id: 'scratchpad' });
    const blocks = (got.doc as { sections: { blocks: { id: string; type: string; text?: string }[] }[] }).sections[0]!.blocks;
    expect(blocks[0]!.text).toBe('#### Path: main → save');
    const res = await call2({ op: 'patch', doc_id: 'scratchpad', version: 1, ops: [{ op: 'set_text', block: blocks[0]!.id, text: '#### How main saves' }] });
    expect(res).toMatchObject({ saved: true, version: 2 });
    expect(await call2({ op: 'history', doc_id: 'scratchpad' })).toMatchObject({ error: 'bad_request' });
    expect(await call2({ op: 'clear', doc_id: 'scratchpad' })).toEqual({ cleared: true, was_version: 2 });
  });

  it('says what is missing: a code map, a symbol, or a path', async () => {
    setup();
    expect(await explain({ symbol: 'main' }, { ...graph, nodes: [] } as VgGraph)).toMatchObject({ error: 'no_code_map' });
    expect(await explain({})).toMatchObject({ error: 'bad_request' });
    expect(await explain({ symbol: 'nope' })).toMatchObject({ error: 'not_found' });
    expect(await explain({ symbol: 'save', to: 'main' })).toMatchObject({ doc: expect.objectContaining({ title: 'Path: main → save' }) });
  });
});

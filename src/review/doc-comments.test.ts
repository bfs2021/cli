import { describe, expect, it } from 'vitest';
import { CliError, ExitCode } from '../util/exit.js';
import { fetchComments, formatThreads, refuseReviewDocCloudWhenOffline, threadsOf, type DocComment } from './doc-comments.js';
import type { ParsedDsn } from './push.js';

const c = (over: Partial<DocComment>): DocComment => ({
  id: 'rdc_1', blockId: 'blk_1', blockTitle: 'What save does', parentId: null, authorKind: 'person',
  authorName: 'Ada', body: 'Why?', createdAt: '2026-10-02T10:00:00Z', resolvedAt: null, ...over,
});

describe('cloud flags under --offline', () => {
  it('refuses --push, --comments, and --reply before any request', () => {
    expect(() => refuseReviewDocCloudWhenOffline('--push', false)).not.toThrow();
    expect(() => refuseReviewDocCloudWhenOffline('--comments', undefined)).not.toThrow();
    const cases = [
      ['--push', 'upload the review document'],
      ['--comments', 'read comments'],
      ['--reply', 'post the reply'],
    ] as const;
    for (const [flag, verb] of cases) {
      const message = `\`${flag}\` needs the network — drop \`--offline\` (or \`--local\`) to ${verb}, or drop \`${flag}\` to stay on this machine`;
      expect(() => refuseReviewDocCloudWhenOffline(flag, true)).toThrow(message);
      try {
        refuseReviewDocCloudWhenOffline(flag, true);
      } catch (err) {
        expect((err as CliError).code).toBe(ExitCode.USAGE_ERROR);
      }
    }
  });
});

describe('threads', () => {
  it('groups replies under their thread and lists open threads first', () => {
    const threads = threadsOf([
      c({ id: 'rdc_1', resolvedAt: 't' }),
      c({ id: 'rdc_2', blockTitle: null, blockId: 'blk_9', body: 'And this?' }),
      c({ id: 'rdc_3', parentId: 'rdc_2', authorKind: 'agent', authorName: 'Agent (review_doc)', body: 'Because…\nsee L3' }),
    ]);
    expect(threads.map((t) => [t.id, t.comments.length, t.resolved])).toEqual([
      ['rdc_1', 1, true],
      ['rdc_2', 2, false],
    ]);
    expect(formatThreads(threads)).toEqual([
      'rdc_2  on blk_9',
      '  Bo: And this?'.replace('Bo', 'Ada'),
      '  Agent (review_doc) [agent]: Because…\n    see L3',
      'rdc_1  (resolved) on What save does',
      '  Ada: Why?',
    ]);
  });

  it('says so when there are none', () => {
    expect(formatThreads([])).toEqual(['no comments on this document yet']);
  });
});

describe('fetchComments', () => {
  const dsn: ParsedDsn = { keyId: 'k', secret: 's', host: 'h.test', workspaceId: 'ws', scheme: 'https' };
  const target = { repo_key: `sha256:${'a'.repeat(64)}`, head_sha: 'b'.repeat(40), base_sha: 'c'.repeat(40) };

  it('explains a document that was never pushed, and a workspace that has not opted in', async () => {
    const answer = (code: string, status: number) => (async () => new Response(JSON.stringify({ status: 'error', code, error: 'x' }), { status })) as unknown as typeof fetch;
    await expect(fetchComments(dsn, target, answer('review_doc_not_found', 404))).rejects.toThrow(/vg review doc --base <ref> --push/);
    await expect(fetchComments(dsn, target, answer('review_doc_upload_disabled', 403))).rejects.toThrow(/workspace admin/);
  });
});

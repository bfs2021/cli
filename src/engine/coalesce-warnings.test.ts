import { describe, expect, it, vi } from 'vitest';
import { formatSarif } from '../core-open/formatters/sarif.js';
import { sortCodedWarnings, stampWarning, WARNING_CODES, type CodedWarning } from '../core-open/warnings.js';
import type { ScanArtifact } from '../core-open/types.js';
import { assembleEngineWarnings } from './warning-codes.js';
import {
  coalesceHumanWarnings,
  coalescePlainWarnings,
  HUMAN_WARNING_SAMPLE_CAP,
  isFailedParseWarning,
  stampedParseFailure,
  withCoalescedWarningStderr,
} from './coalesce-warnings.js';

const PARSE_REASON = 'parse failed: scanner error';
const PARSE_PATHS = ['z/b.ts', 'a/a.ts', 'm/c.ts', 'b/d.ts', 'a/e.ts', 'z/a.ts', 'q/f.ts'];

function row(code: CodedWarning['code'], message: string): CodedWarning {
  return { code, message };
}

/** Repeated identical degrade events, in an order that is not the output order. */
function degradeFixture(): CodedWarning[] {
  const events: CodedWarning[] = [
    row(WARNING_CODES.YAML_PARSE_FAILED, 'z/chart.yaml: YAML parse failed (duplicate key)'),
    row(WARNING_CODES.TSC_RESOLVER_SKIPPED, 'typescript resolver skipped — 12000 TS/JS files exceed the 8000-file limit'),
    row(WARNING_CODES.SCAN_FILE_OVERSIZE, 'z/blob.bin skipped — larger than 5 MB'),
    row(WARNING_CODES.BUILD_FILE_OVERSIZE, 'zzz.ts: skipped — 9 KiB exceeds the 1 KiB per-file limit'),
    row(WARNING_CODES.HCL_PARTIAL, 'infra/main.tf: HCL parse recovered from a syntax error — extraction may be partial'),
    row(WARNING_CODES.PARSE_FAILED, 'n/other.ts: parse failed: other reason'),
    row(
      WARNING_CODES.ROOT_PACKAGE_IDENTITY,
      'Root package.json has no version. The root component version is omitted. Dependencies are still resolved.',
    ),
    row(WARNING_CODES.YAML_PARSE_FAILED, 'a/chart.yaml: YAML parse failed (duplicate key)'),
    row(WARNING_CODES.SCAN_FILE_OVERSIZE, 'a/blob.bin skipped — larger than 5 MB'),
    row(WARNING_CODES.BUILD_FILE_OVERSIZE, 'aaa.ts: skipped — 9 KiB exceeds the 1 KiB per-file limit'),
    row(WARNING_CODES.SCAN_FILE_OVERSIZE, 'm/blob.bin skipped — larger than 5 MB'),
  ];
  for (const rel of PARSE_PATHS) events.push(row(WARNING_CODES.PARSE_FAILED, `${rel}: ${PARSE_REASON}`));
  return events;
}

const COALESCED = [
  'warning [VG_WARN_BUILD_FILE_OVERSIZE]: skipped — 9 KiB exceeds the 1 KiB per-file limit — 2 files; samples: aaa.ts, zzz.ts',
  'warning [VG_WARN_HCL_PARTIAL]: infra/main.tf: HCL parse recovered from a syntax error — extraction may be partial',
  'warning [VG_WARN_PARSE_FAILED]: n/other.ts: parse failed: other reason',
  `warning [VG_WARN_PARSE_FAILED]: ${PARSE_REASON} — ${PARSE_PATHS.length} files; samples: a/a.ts, a/e.ts, b/d.ts, m/c.ts, q/f.ts (+2 more)`,
  'warning [VG_WARN_ROOT_PACKAGE_IDENTITY]: Root package.json has no version. The root component version is omitted. Dependencies are still resolved.',
  'warning [VG_WARN_SCAN_FILE_OVERSIZE]: skipped — larger than 5 MB — 3 files; samples: a/blob.bin, m/blob.bin, z/blob.bin',
  'warning [VG_WARN_TSC_RESOLVER_SKIPPED]: typescript resolver skipped — 12000 TS/JS files exceed the 8000-file limit',
  'warning [VG_WARN_YAML_PARSE_FAILED]: YAML parse failed (duplicate key) — 2 files; samples: a/chart.yaml, z/chart.yaml',
];

describe('coalesceHumanWarnings', () => {
  it('coalesces identical degrade events into stable text', () => {
    expect(HUMAN_WARNING_SAMPLE_CAP).toBe(5);
    const events = degradeFixture();
    const text = coalesceHumanWarnings(events);
    expect(text).toEqual(COALESCED);
    expect(coalesceHumanWarnings([...events].reverse())).toEqual(text);
    expect(coalesceHumanWarnings(events.slice(3).concat(events.slice(0, 3)))).toEqual(text);
    expect(text.join('\n')).not.toContain('z/a.ts');
    expect(text.join('\n')).not.toContain('z/b.ts');
    expect(text.join('\n')).toContain('a/a.ts');
    expect(text.length).toBeLessThan(events.length);
  });

  it('keeps JSON and SARIF rows complete and ordered', () => {
    const events = degradeFixture();
    const stored = events.map((warning) => stampWarning(warning.code, warning.message));
    const first = assembleEngineWarnings(stored);
    const second = assembleEngineWarnings([...stored].reverse());
    expect(first).toEqual(second);
    expect(first.codedWarnings).toHaveLength(events.length);
    expect(first.warnings).toHaveLength(events.length);
    const messages = new Set(first.codedWarnings.map((warning) => warning.message));
    for (const event of events) expect(messages.has(event.message)).toBe(true);

    const sorted = sortCodedWarnings(events);
    const artifact = {
      schemaVersion: '1.0',
      timestamp: '2020-01-01T00:00:00.000Z',
      vibgrateVersion: 'test',
      rootPath: 'repo',
      projects: [],
      findings: [],
      degradations: sorted,
    } as unknown as ScanArtifact;
    const sarif = formatSarif(artifact) as {
      runs: Array<{ invocations: Array<{ toolExecutionNotifications?: Array<{ message: { text: string }; descriptor: { id: string } }> }> }>;
    };
    const again = formatSarif(artifact);
    expect(JSON.stringify(sarif)).toBe(JSON.stringify(again));
    const notes = sarif.runs[0]!.invocations[0]!.toolExecutionNotifications ?? [];
    expect(notes).toHaveLength(events.length);
    expect(notes.map((note) => note.message.text)).toEqual(sorted.map((warning) => warning.message));
    expect(notes.map((note) => note.descriptor.id)).toEqual(sorted.map((warning) => warning.code));
    expect(notes.length).toBeGreaterThan(coalesceHumanWarnings(events).length);
  });

  it('does not print a home directory or a credential', () => {
    const secret = 'Bearer not-a-real-token';
    const events = [
      row(WARNING_CODES.PARSE_FAILED, `/home/alice/proj/src/a.ts: parse failed: boom ${secret}`),
      row(WARNING_CODES.PARSE_FAILED, `/home/bob/proj/src/b.ts: parse failed: boom ${secret}`),
      row(WARNING_CODES.PARSE_FAILED, `../outside.ts: parse failed: boom ${secret}`),
    ];
    const text = coalesceHumanWarnings(events).join('\n');
    expect(text).toContain('3 files');
    expect(text).toContain('[REDACTED]');
    expect(text).not.toContain('/home/alice');
    expect(text).not.toContain('/home/bob');
    expect(text).not.toContain('not-a-real-token');
    expect(text).not.toContain('..');
    expect(text).not.toContain('outside.ts');
  });

  it('stamps a repo-relative parse failure and still recognises it', () => {
    const stamped = stampedParseFailure(
      'src/a.ts',
      new Error('boom at /home/alice/proj/src/a.ts Bearer not-a-real-token'),
    );
    expect(stamped.startsWith('src/a.ts: parse failed:')).toBe(true);
    expect(stamped.endsWith(' [VG_WARN_PARSE_FAILED]')).toBe(true);
    expect(stamped).not.toContain('/home/alice');
    expect(stamped).not.toContain('not-a-real-token');
    expect(stamped).toContain('[REDACTED]');
    expect(isFailedParseWarning(stamped)).toBe(true);
    expect(isFailedParseWarning('parse failed: legacy [VG_WARN_PARSE_FAILED]')).toBe(true);
    expect(isFailedParseWarning('chart.yaml: YAML parse failed (bad indent) [VG_WARN_YAML_PARSE_FAILED]')).toBe(false);
  });
});

describe('withCoalescedWarningStderr', () => {
  it('coalesces repeated warning lines and leaves other stderr in place', async () => {
    const chunks: string[] = [];
    const spy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      chunks.push(args.map((part) => String(part)).join(' '));
    });
    try {
      await withCoalescedWarningStderr(async () => {
        console.error('warning [VG_WARN_PARSE_FAILED]: z/b.ts: parse failed: scanner error');
        console.error('error: disk full');
        console.error('warning [VG_WARN_PARSE_FAILED]: a/a.ts: parse failed: scanner error');
      });
    } finally {
      spy.mockRestore();
    }
    const text = chunks.join('\n').replace(/\u001b\[[0-9;]*m/g, '');
    expect(text).toContain('error: disk full');
    expect(text).toContain('parse failed: scanner error — 2 files; samples: a/a.ts, z/b.ts');
    expect(text).not.toContain('warning [VG_WARN_PARSE_FAILED]: z/b.ts:');
    expect(text).not.toContain('warning [VG_WARN_PARSE_FAILED]: a/a.ts:');
  });

  it('prints the coalesced line before the report that follows it', async () => {
    const order: string[] = [];
    const err = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      order.push(args.map((part) => String(part)).join(' '));
    });
    const log = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      order.push(args.map((part) => String(part)).join(' '));
    });
    try {
      await withCoalescedWarningStderr(async () => {
        console.log('before');
        console.error('warning [VG_WARN_PARSE_FAILED]: b.ts: parse failed: scanner error');
        console.error('warning [VG_WARN_PARSE_FAILED]: a.ts: parse failed: scanner error');
        console.log('REPORT');
      });
    } finally {
      err.mockRestore();
      log.mockRestore();
    }
    const text = order.join('\n').replace(/\u001b\[[0-9;]*m/g, '');
    expect(text.indexOf('before')).toBeLessThan(text.indexOf('2 files'));
    expect(text.indexOf('2 files')).toBeLessThan(text.indexOf('REPORT'));
  });
});

describe('coalescePlainWarnings', () => {
  it('counts identical uncoded lines and keeps a single line as written', () => {
    expect(coalescePlainWarnings(['parse failed: scanner error', 'other', 'parse failed: scanner error'])).toEqual([
      'warning: other',
      'warning: parse failed: scanner error — 2 files',
    ]);
  });
});

import { afterEach, describe, expect, it } from 'vitest';
import { buildGraph } from '../src/engine/build.js';
import {
  codedWarning,
  formatCoalescedPlainLines,
  formatCoalescedWarningLines,
  formatDegradationLines,
  formatWarningLine,
  parseFailedWarning,
  sortCodedWarnings,
  WARNING_CODES,
  WARNING_SAMPLE_CAP,
  warningErrorDetail,
  type CodedWarning,
} from '../src/core-open/warnings.js';
import { cleanup, makeProject } from './helpers.js';

const PIN = '2020-01-01T00:00:00.000Z';
const dirs: string[] = [];

afterEach(() => {
  while (dirs.length) cleanup(dirs.pop()!);
});

function parseFailed(rel: string): CodedWarning {
  return codedWarning(WARNING_CODES.PARSE_FAILED, `${rel}: parse failed: unexpected token`);
}

describe('coalesced human warnings', () => {
  it('collapses identical parse failures to a stable count and sample paths', () => {
    const paths = ['src/g.ts', 'src/a.ts', 'src/c.ts', 'src/b.ts', 'src/e.ts', 'src/d.ts', 'src/f.ts'];
    const warnings = paths.map(parseFailed);
    const shuffled = [warnings[3]!, warnings[0]!, warnings[6]!, warnings[1]!, warnings[4]!, warnings[2]!, warnings[5]!];
    const line =
      'warning [VG_WARN_PARSE_FAILED]: parse failed: unexpected token ' +
      '(7 files: src/a.ts, src/b.ts, src/c.ts, src/d.ts, src/e.ts, +2 more)';

    expect(WARNING_SAMPLE_CAP).toBe(5);
    expect(formatCoalescedWarningLines(shuffled)).toEqual([line]);
    expect(formatCoalescedWarningLines(warnings)).toEqual(formatCoalescedWarningLines(shuffled));
    expect(formatDegradationLines(shuffled)).toEqual([line]);

    const orderBefore = shuffled.map((warning) => warning.message);
    const machine = sortCodedWarnings(shuffled);
    expect(machine).toHaveLength(7);
    expect(machine.map((warning) => warning.message)).toEqual([
      'src/a.ts: parse failed: unexpected token',
      'src/b.ts: parse failed: unexpected token',
      'src/c.ts: parse failed: unexpected token',
      'src/d.ts: parse failed: unexpected token',
      'src/e.ts: parse failed: unexpected token',
      'src/f.ts: parse failed: unexpected token',
      'src/g.ts: parse failed: unexpected token',
    ]);
    expect(shuffled.map((warning) => warning.message)).toEqual(orderBefore);
  });

  it('keeps a different reason or a different code on its own line', () => {
    const unexpected = parseFailed('src/a.ts');
    const invalid = codedWarning(WARNING_CODES.PARSE_FAILED, 'src/b.ts: parse failed: invalid character');
    const yaml = codedWarning(WARNING_CODES.YAML_PARSE_FAILED, 'k8s/a.yaml: YAML parse failed (bad indent)');
    expect(formatCoalescedWarningLines([yaml, invalid, unexpected])).toEqual([
      formatWarningLine(unexpected),
      formatWarningLine(invalid),
      formatWarningLine(yaml),
    ]);
  });

  it('leaves a single warning unchanged', () => {
    const one = codedWarning(
      WARNING_CODES.ROOT_PACKAGE_IDENTITY,
      'Root package.json has no version. The root component version is omitted. Dependencies are still resolved.',
    );
    expect(formatCoalescedWarningLines([one])).toEqual([formatWarningLine(one)]);
    expect(formatCoalescedPlainLines(['only once'])).toEqual(['warning: only once']);
  });

  it('treats differing byte sizes as one reason and keeps the shared limit', () => {
    const over = [
      codedWarning(
        WARNING_CODES.BUILD_FILE_OVERSIZE,
        'vendor/z.ts: skipped — 2.0 KiB exceeds the 256 B per-file limit (set VG_MAX_FILE_BYTES to raise it, 0 to disable)',
      ),
      codedWarning(
        WARNING_CODES.BUILD_FILE_OVERSIZE,
        'vendor/a.ts: skipped — 400 B exceeds the 256 B per-file limit (set VG_MAX_FILE_BYTES to raise it, 0 to disable)',
      ),
    ];
    expect(formatCoalescedWarningLines(over)).toEqual([
      'warning [VG_WARN_BUILD_FILE_OVERSIZE]: skipped — # exceeds the 256 B per-file limit ' +
        '(set VG_MAX_FILE_BYTES to raise it, 0 to disable) (2 files: vendor/a.ts, vendor/z.ts)',
    ]);
    expect(sortCodedWarnings(over)).toHaveLength(2);
  });

  it('samples basenames and drops home directories and secrets', () => {
    const abs = [
      codedWarning(
        WARNING_CODES.PARSE_FAILED,
        '/home/alice/secret/proj/src/a.ts: parse failed: boom at /home/alice/secret/proj/src/a.ts',
      ),
      codedWarning(
        WARNING_CODES.PARSE_FAILED,
        '/home/bob/secret/proj/src/b.ts: parse failed: boom at /home/bob/secret/proj/src/b.ts',
      ),
    ];
    const text = formatCoalescedWarningLines(abs).join('\n');
    expect(text).toBe('warning [VG_WARN_PARSE_FAILED]: parse failed: boom at a file (2 files: a.ts, b.ts)');
    expect(text).not.toContain('/home/');
    expect(text).not.toContain('alice');
    expect(text).not.toContain('bob');

    const detail = warningErrorDetail(new Error('boom ghp_1234567890abcdef at /home/alice/x.ts'));
    expect(detail).not.toContain('ghp_');
    expect(detail).not.toContain('/home/');
    expect(detail).toContain('[REDACTED]');

    const stored = parseFailedWarning('/home/alice/proj/src/a.ts', new Error('nope at /home/alice/proj/src/a.ts'));
    expect(stored).toBe('a.ts: parse failed: nope at a file [VG_WARN_PARSE_FAILED]');
    expect(stored).not.toContain('/home/');
  });

  it('coalesces scan timeout sentences and plain duplicates', () => {
    const scan = [
      codedWarning(WARNING_CODES.SCAN_PATH_SKIPPED, 'svc/b timed out (>30s) and was skipped'),
      codedWarning(WARNING_CODES.SCAN_PATH_SKIPPED, 'svc/a timed out (>30s) and was skipped'),
    ];
    expect(formatCoalescedWarningLines(scan)).toEqual([
      'warning [VG_WARN_SCAN_PATH_SKIPPED]: timed out (>30s) and was skipped (2 files: svc/a, svc/b)',
    ]);
    expect(formatCoalescedPlainLines(['src/b.ts: boom', 'src/a.ts: boom'])).toEqual([
      'warning: boom (2 files: src/a.ts, src/b.ts)',
    ]);
  });
});

describe('build parse-degrade warnings', () => {
  it('keeps one machine row per file and one stable human line', async () => {
    const broken = 'apiVersion: v1\nkind: [unclosed\n';
    const names = ['a.yaml', 'b.yaml', 'c.yaml', 'd.yaml', 'e.yaml', 'f.yaml', 'g.yaml'];
    const files: Record<string, string> = { 'src/ok.ts': 'export const a = 1;\n' };
    for (const name of names) files[`k8s/${name}`] = broken;
    const root = makeProject(files);
    dirs.push(root);

    const build = () => buildGraph({ root, generatedAt: PIN, inline: true, noCache: true });
    const first = await build();
    const again = await build();

    const yaml = first.codedWarnings.filter((warning) => warning.code === 'VG_WARN_YAML_DOCUMENT_SKIPPED');
    expect(yaml.map((warning) => warning.message)).toEqual(
      names.map((name) => `k8s/${name}: YAML document 1 has errors — skipped`),
    );
    expect(again.codedWarnings).toEqual(first.codedWarnings);

    const human = formatCoalescedWarningLines(first.codedWarnings).filter((line) =>
      line.includes('VG_WARN_YAML_DOCUMENT_SKIPPED'),
    );
    const againHuman = formatCoalescedWarningLines(again.codedWarnings).filter((line) =>
      line.includes('VG_WARN_YAML_DOCUMENT_SKIPPED'),
    );
    expect(human).toEqual([
      'warning [VG_WARN_YAML_DOCUMENT_SKIPPED]: YAML document 1 has errors — skipped ' +
        '(7 files: k8s/a.yaml, k8s/b.yaml, k8s/c.yaml, k8s/d.yaml, k8s/e.yaml, +2 more)',
    ]);
    expect(againHuman).toEqual(human);
    expect(human.join('\n')).not.toContain(root);
    expect(JSON.stringify(first.codedWarnings)).not.toContain(root);
  });
});

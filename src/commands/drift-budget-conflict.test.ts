import { afterEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { main } from '../cli.js';
import { configNotes } from './doctor.js';
import {
  DRIFT_BUDGET_CONFLICT_CODE,
  driftBudgetConflictNote,
  formatDriftBudgetConflictWarning,
} from './drift-budget-conflict.js';

const TOKEN = 'sk-exampleplaceholder1234567890';

const roots: string[] = [];
function project(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-budget-conflict-'));
  roots.push(root);
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), text);
  }
  return root;
}

afterEach(() => {
  for (const r of roots.splice(0)) fs.rmSync(r, { recursive: true, force: true });
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

const YML_40 = `driftBudget:\n  maxScore: 40\n`;
const JSON_40 = `{"driftBudget":{"mode":"warn","maxScore":40}}\n`;
const JSON_80 = `{"note":"${TOKEN}","driftBudget":{"maxScore":80,"mode":"enforce"}}\n`;

describe('driftBudget conflict across config files', () => {
  it('is quiet for one file, and for YAML and JSON that set the same budget', () => {
    expect(driftBudgetConflictNote(project({ '.vibgrate/config.yml': YML_40 }))).toBeNull();
    expect(driftBudgetConflictNote(project({}))).toBeNull();
    const same = project({
      '.vibgrate/config.yml': 'driftBudget:\n  mode: warn\n  maxScore: 40\n',
      'vibgrate.config.json': JSON_40,
    });
    expect(driftBudgetConflictNote(same)).toBeNull();
    expect(configNotes(same)).toEqual([
      'vibgrate.config.json is ignored: .vibgrate/config.yml is the config in use',
    ]);
  });

  it('names the winning file and both budgets when the values differ', () => {
    const root = project({
      '.vibgrate/config.yml': `# ${TOKEN}\ndriftBudget:\n  maxScore: 40\n`,
      'vibgrate.config.json': JSON_80,
    });
    const note =
      'driftBudget disagrees across config files. .vibgrate/config.yml wins (mode warn, maxScore 40). vibgrate.config.json is ignored (mode enforce, maxScore 80).';
    expect(driftBudgetConflictNote(root)).toBe(note);
    expect(note).not.toContain(TOKEN);
    expect(formatDriftBudgetConflictWarning(note)).toBe(`warning [${DRIFT_BUDGET_CONFLICT_CODE}]: ${note}`);
    expect(configNotes(root)).toEqual([
      'vibgrate.config.json is ignored: .vibgrate/config.yml is the config in use',
      note,
    ]);
  });

  it('warns when only the ignored file sets driftBudget', () => {
    const root = project({
      '.vibgrate/config.yml': 'exclude: []\n',
      'vibgrate.config.json': '{"driftBudget":{"maxScore":40,"maxWorseningPercent":5}}\n',
    });
    expect(driftBudgetConflictNote(root)).toBe(
      'driftBudget disagrees across config files. .vibgrate/config.yml wins and does not set driftBudget. vibgrate.config.json is ignored (mode warn, maxScore 40, maxWorseningPercent 5).',
    );
  });

  it('lists conflicting files in lookup order and skips a file that matches the winner', () => {
    const root = project({
      '.vibgrate/config.yml': YML_40,
      '.vibgrate/config.yaml': 'driftBudget:\n  maxScore: 20\n  agents:\n    maxWorseningPercent: 1\n',
      'vibgrate.config.json': JSON_40,
    });
    expect(driftBudgetConflictNote(root)).toBe(
      'driftBudget disagrees across config files. .vibgrate/config.yml wins (mode warn, maxScore 40). .vibgrate/config.yaml is ignored (mode warn, maxScore 20, agents.maxWorseningPercent 1).',
    );
    expect(driftBudgetConflictNote(root)).toBe(driftBudgetConflictNote(root));
  });

  it('names every ignored budget that differs, in lookup order', () => {
    const root = project({
      '.vibgrate/config.yml': YML_40,
      '.vibgrate/config.yaml': 'driftBudget:\n  maxRiskScore: 15\n',
      'vibgrate.config.json': JSON_80,
    });
    expect(driftBudgetConflictNote(root)).toBe(
      'driftBudget disagrees across config files. .vibgrate/config.yml wins (mode warn, maxScore 40). .vibgrate/config.yaml is ignored (mode warn, maxRiskScore 15). vibgrate.config.json is ignored (mode enforce, maxScore 80).',
    );
  });

  it('treats a code config as the winner and still reports the ignored JSON budget', () => {
    const root = project({
      'vibgrate.config.ts': 'export default { driftBudget: { maxScore: 10 } };\n',
      'vibgrate.config.json': '{"driftBudget":{"maxScore":80}}\n',
    });
    expect(driftBudgetConflictNote(root)).toBe(
      'driftBudget disagrees across config files. vibgrate.config.ts wins. vibgrate.config.json is ignored (mode warn, maxScore 80).',
    );
  });

  it('does not throw when an ignored file cannot be parsed', () => {
    const root = project({
      '.vibgrate/config.yml': YML_40,
      'vibgrate.config.json': '{"driftBudget":',
    });
    expect(driftBudgetConflictNote(root)).toBeNull();
  });
});

describe('vg scan warns on stderr when driftBudget disagrees', () => {
  async function runCli(args: string[]): Promise<{ code: number; stderr: string; stdout: string }> {
    vi.stubEnv('NO_COLOR', '1');
    vi.stubEnv('VIBGRATE_NO_KERNEL', '1');
    const stderr: string[] = [];
    const stdout: string[] = [];
    const write = (bucket: string[]) => (chunk: unknown, encodingOrCb?: unknown, cb?: unknown) => {
      bucket.push(String(chunk));
      const callback = typeof encodingOrCb === 'function' ? encodingOrCb : cb;
      if (typeof callback === 'function') callback();
      return true;
    };
    const errSpy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      stderr.push(args.map((part) => String(part)).join(' '));
    });
    const outSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      stdout.push(args.map((part) => String(part)).join(' '));
    });
    const errWrite = vi.spyOn(process.stderr, 'write').mockImplementation(write(stderr) as never);
    const outWrite = vi.spyOn(process.stdout, 'write').mockImplementation(write(stdout) as never);
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      throw new Error(`EXIT:${code ?? 0}`);
    }) as never);

    try {
      await main(['node', 'vg', ...args]);
      return { code: 0, stderr: stderr.join(''), stdout: stdout.join('') };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const match = /^EXIT:(\d+)$/.exec(message);
      if (!match) throw err;
      return { code: Number(match[1]), stderr: stderr.join(''), stdout: stdout.join('') };
    } finally {
      errSpy.mockRestore();
      outSpy.mockRestore();
      errWrite.mockRestore();
      outWrite.mockRestore();
      exitSpy.mockRestore();
    }
  }

  it('prints the coded warning once, keeps it off stdout, and still exits 0', async () => {
    const root = project({
      'package.json': '{"name":"budget-conflict","version":"1.0.0"}\n',
      '.vibgrate/config.yml': YML_40,
      'vibgrate.config.json': JSON_80,
    });
    const warning = formatDriftBudgetConflictWarning(driftBudgetConflictNote(root)!);
    const scan = await runCli(['scan', root, '--offline', '--no-graph', '--quiet', '--no-local-artifacts', '--format', 'json']);
    expect(scan.code).toBe(0);
    expect(scan.stderr.split(warning)).toHaveLength(2);
    expect(scan.stderr).toContain(DRIFT_BUDGET_CONFLICT_CODE);
    expect(scan.stderr).not.toContain(TOKEN);
    expect(scan.stdout).not.toContain(DRIFT_BUDGET_CONFLICT_CODE);
    expect(scan.stdout).not.toContain('maxScore 80');
  });
});

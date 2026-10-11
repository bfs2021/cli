import * as path from 'node:path';
import {
  parseDriftBudget,
  type DriftBudget,
  type DriftBudgetMode,
  type DriftBudgetRuleResult,
  type DriftBudgetVerdict,
} from '../core-open/index.js';
import type { ScanArtifact } from '../core-open/types.js';
import {
  compareDriftBudget,
  compareDriftWorsening,
  evaluateConfigDriftBudget,
  type DriftBudgetGateResult,
} from './drift-budget-gate.js';
import { ensureDir, writeJsonFile } from './utils/fs.js';

/**
 * The small, stable result of a scan that CI steps read (`vg scan --summary-out`).
 * Absent is `null`, never `0`: an unmeasured DriftScore must not read as perfect.
 *
 * `schemaVersion` stays `1` when a field is added. `driftBudget` is additive, so
 * a reader that only uses `driftScore` keeps working.
 */
export interface ScanSummary {
  schemaVersion: 1;
  /** 0-100, lower is better; `null` when drift could not be measured. */
  driftScore: number | null;
  riskLevel: ScanArtifact['drift']['riskLevel'];
  components: ScanArtifact['drift']['components'];
  /** Score change since `--baseline` (positive = worse); `null` without a comparison. */
  delta: number | null;
  /** The baseline's score; `null` without a comparison or when it was unmeasured. */
  baselineScore: number | null;
  /**
   * Budget verdict for this scan. `null` when no budget was applied: none is
   * configured, neither flag was passed, or the config block could not be parsed.
   */
  driftBudget: ScanSummaryDriftBudget | null;
}

/** Where the budget in the summary came from. Flags override project config. */
export type ScanSummaryBudgetSource =
  | 'config'
  | '--drift-budget'
  | '--drift-worsening'
  | '--drift-budget --drift-worsening';

export interface ScanSummaryBudgetRule {
  id: DriftBudgetRuleResult['id'];
  /** `not_evaluated` stays its own status. It is never reported as `pass`. */
  status: DriftBudgetRuleResult['status'];
  message: string;
}

/**
 * Same shape the config evaluator returns, plus `source`.
 *
 * `withinBudget` is true when no rule breached. A `not_evaluated` rule is not
 * a breach and is not a pass. `blocking` is true only for `enforce` (the flags
 * are always `enforce`) when a rule breached — that is when `vg scan` exits 2.
 */
export interface ScanSummaryDriftBudget {
  source: ScanSummaryBudgetSource;
  mode: DriftBudgetMode;
  withinBudget: boolean;
  blocking: boolean;
  /** Evaluator order: maxScore, worsening, agents, then RiskScore limits. */
  rules: ScanSummaryBudgetRule[];
}

export interface PreparedScanDriftBudget {
  /** Value for {@link ScanSummary.driftBudget}. */
  summary: ScanSummaryDriftBudget | null;
  /** Set when `--drift-budget` was passed. */
  flagBudget: { exitCode: 0 | 2; message: string | null } | null;
  /** Set when `--drift-worsening` was passed. */
  flagWorsening: { exitCode: 0 | 2; message: string | null } | null;
  /**
   * Config evaluation when neither flag was passed and a score was measured.
   * Null when flags were used, the score was absent, or the config was not loaded.
   */
  configGate: DriftBudgetGateResult | null;
  /**
   * A project `driftBudget` key is present and DriftScore was not measured.
   * The score is not compared and is not treated as 0.
   */
  configScoreAbsent: boolean;
}

const ABSENT_CONFIG_MESSAGE = 'DriftScore is absent; the project drift budget was not compared.';

export function buildScanSummary(
  artifact: ScanArtifact,
  driftBudget: ScanSummaryDriftBudget | null = null,
): ScanSummary {
  const score = artifact.drift.score;
  const delta = typeof artifact.delta === 'number' ? artifact.delta : null;
  return {
    schemaVersion: 1,
    driftScore: score,
    riskLevel: artifact.drift.riskLevel,
    components: artifact.drift.components,
    delta,
    baselineScore: score !== null && delta !== null ? score - delta : null,
    driftBudget,
  };
}

export async function writeScanSummary(
  file: string,
  artifact: ScanArtifact,
  driftBudget: ScanSummaryDriftBudget | null = null,
): Promise<void> {
  const target = path.resolve(file);
  await ensureDir(path.dirname(target));
  await writeJsonFile(target, buildScanSummary(artifact, driftBudget));
}

/**
 * Pure budget verdict for one finished scan.
 *
 * `--drift-budget` and `--drift-worsening` take precedence over project
 * config, matching the gate. An unmeasured score is never passed in as 0.
 */
export function prepareScanDriftBudget(input: {
  score: number | null;
  delta: number | undefined;
  driftBudget?: number;
  driftWorseningPercent?: number;
  /** Raw `driftBudget` from the project config. Ignored when either flag is set. */
  configRaw?: unknown;
  configFile?: string | null;
}): PreparedScanDriftBudget {
  const flags = input.driftBudget !== undefined || input.driftWorseningPercent !== undefined;
  if (flags) {
    return {
      summary: flagDriftBudgetSummary(input),
      flagBudget: input.driftBudget !== undefined ? compareDriftBudget(input.score, input.driftBudget) : null,
      flagWorsening: input.driftWorseningPercent !== undefined
        ? compareDriftWorsening(input.score, input.delta, input.driftWorseningPercent)
        : null,
      configGate: null,
      configScoreAbsent: false,
    };
  }

  const configPresent = input.configRaw !== undefined && input.configRaw !== null;
  if (input.score === null) {
    return {
      summary: configPresent ? absentConfigSummary(input.configRaw) : null,
      flagBudget: null,
      flagWorsening: null,
      configGate: null,
      configScoreAbsent: configPresent,
    };
  }

  const configGate = evaluateConfigDriftBudget({
    raw: input.configRaw,
    configFile: input.configFile ?? null,
    headScore: input.score,
    baseScore: input.delta === undefined ? null : input.score - input.delta,
  });
  return {
    summary: configGate.verdict ? verdictToSummary(configGate.verdict) : null,
    flagBudget: null,
    flagWorsening: null,
    configGate,
    configScoreAbsent: false,
  };
}

function verdictToSummary(verdict: DriftBudgetVerdict): ScanSummaryDriftBudget {
  return {
    source: 'config',
    mode: verdict.mode,
    withinBudget: verdict.withinBudget,
    blocking: verdict.blocking,
    rules: verdict.rules.map((rule) => ({ id: rule.id, status: rule.status, message: rule.message })),
  };
}

/** Configured limits, in evaluator order, when DriftScore itself was not measured. */
function absentRules(budget: DriftBudget): ScanSummaryBudgetRule[] {
  const rules: ScanSummaryBudgetRule[] = [];
  const row = (id: ScanSummaryBudgetRule['id']): ScanSummaryBudgetRule => ({
    id,
    status: 'not_evaluated',
    message: ABSENT_CONFIG_MESSAGE,
  });
  if (budget.maxScore !== null) rules.push(row('maxScore'));
  if (budget.maxWorseningPercent !== null) rules.push(row('maxWorseningPercent'));
  if (budget.agentMaxWorseningPercent !== null) rules.push(row('agents.maxWorseningPercent'));
  if (budget.maxRiskScore !== null) rules.push(row('maxRiskScore'));
  if (budget.maxRiskWorseningPercent !== null) rules.push(row('maxRiskWorseningPercent'));
  return rules;
}

function absentConfigSummary(raw: unknown): ScanSummaryDriftBudget | null {
  const parsed = parseDriftBudget(raw);
  if (!parsed?.ok) return null;
  return {
    source: 'config',
    mode: parsed.budget.mode,
    withinBudget: true,
    blocking: false,
    rules: absentRules(parsed.budget),
  };
}

function flagSource(hasBudget: boolean, hasWorsening: boolean): ScanSummaryBudgetSource {
  if (hasBudget && hasWorsening) return '--drift-budget --drift-worsening';
  if (hasBudget) return '--drift-budget';
  return '--drift-worsening';
}

function ruleFromCompare(
  id: 'maxScore' | 'maxWorseningPercent',
  result: { exitCode: 0 | 2; message: string | null },
  passMessage: string,
): ScanSummaryBudgetRule {
  if (result.message !== null && result.exitCode === 0) {
    return { id, status: 'not_evaluated', message: result.message };
  }
  if (result.exitCode === 2) {
    return { id, status: 'breach', message: result.message ?? passMessage };
  }
  return { id, status: 'pass', message: passMessage };
}

function worseningPassMessage(score: number, delta: number, limit: number): string {
  const baseline = score - delta;
  if (delta <= 0) return `Drift did not worsen (DriftScore ${baseline} → ${score}).`;
  const percent = (delta / Math.max(Math.abs(baseline), 0.0001)) * 100;
  return `Drift worsened by ${percent.toFixed(2)}% (limit ${limit}%); DriftScore ${baseline} → ${score}.`;
}

function flagDriftBudgetSummary(input: {
  score: number | null;
  delta: number | undefined;
  driftBudget?: number;
  driftWorseningPercent?: number;
}): ScanSummaryDriftBudget {
  const rules: ScanSummaryBudgetRule[] = [];
  if (input.driftBudget !== undefined) {
    const result = compareDriftBudget(input.score, input.driftBudget);
    const passMessage = input.score === null
      ? ''
      : `DriftScore ${input.score} is within the budget of ${input.driftBudget}.`;
    rules.push(ruleFromCompare('maxScore', result, passMessage));
  }
  if (input.driftWorseningPercent !== undefined) {
    const result = compareDriftWorsening(input.score, input.delta, input.driftWorseningPercent);
    const passMessage = input.score === null || input.delta === undefined
      ? ''
      : worseningPassMessage(input.score, input.delta, input.driftWorseningPercent);
    rules.push(ruleFromCompare('maxWorseningPercent', result, passMessage));
  }
  const breached = rules.some((rule) => rule.status === 'breach');
  return {
    source: flagSource(input.driftBudget !== undefined, input.driftWorseningPercent !== undefined),
    mode: 'enforce',
    withinBudget: !breached,
    blocking: breached,
    rules,
  };
}

import * as path from 'node:path';
import {
  evaluateDriftBudget,
  LOCAL_SCAN_RISK_NOTE,
  parseDriftBudget,
  worseningPercent,
  type DriftBudget,
  type DriftBudgetMode,
  type DriftBudgetRuleResult,
} from '../core-open/index.js';
import { ensureDir, writeJsonFile } from './utils/fs.js';
import type { ScanArtifact } from '../core-open/types.js';

/**
 * The small, stable result of a scan that CI steps read (`vg scan --summary-out`).
 * Absent is `null`, never `0`: an unmeasured DriftScore must not read as perfect.
 */
export interface ScanSummaryDriftBudget {
  /**
   * `flags` when `--drift-budget` or `--drift-worsening` supplied the limits.
   * Those flags replace the project config and block on a breach.
   */
  source: 'config' | 'flags';
  mode: DriftBudgetMode;
  /** No rule breached. A rule that was not evaluated is not a breach. */
  withinBudget: boolean;
  /** A breach that gates: `enforce` mode and at least one rule breached. */
  blocking: boolean;
  rules: DriftBudgetRuleResult[];
}

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
   * Verdict for the drift budget that applied to this scan.
   * `null` when no budget was set, or when the project budget could not be read.
   */
  driftBudget: ScanSummaryDriftBudget | null;
}

/** Limits to judge. The score and delta always come from the scan artifact. */
export interface DriftBudgetSummaryInput {
  /** `--drift-budget`. Replaces `configRaw` when set. */
  flagBudget?: number;
  /** `--drift-worsening`. Replaces `configRaw` when set. */
  flagWorseningPercent?: number;
  /** Unvalidated `driftBudget` from the project config. Ignored when a flag is set. */
  configRaw?: unknown;
}

const ABSENT_CONFIG = 'DriftScore is absent; the project drift budget was not compared.';
const FLAG_WORSENING_NEEDS_BASELINE =
  'Failing fitness function: --drift-worsening requires --baseline to compare against previous drift.';

function fromRules(
  source: ScanSummaryDriftBudget['source'],
  mode: DriftBudgetMode,
  rules: DriftBudgetRuleResult[],
): ScanSummaryDriftBudget {
  const withinBudget = rules.every((rule) => rule.status !== 'breach');
  return {
    source,
    mode,
    withinBudget,
    blocking: mode === 'enforce' && !withinBudget,
    rules,
  };
}

function absentConfigRules(budget: DriftBudget): DriftBudgetRuleResult[] {
  const rules: DriftBudgetRuleResult[] = [];
  if (budget.maxScore !== null) rules.push({ id: 'maxScore', status: 'not_evaluated', message: ABSENT_CONFIG });
  if (budget.maxWorseningPercent !== null) {
    rules.push({ id: 'maxWorseningPercent', status: 'not_evaluated', message: ABSENT_CONFIG });
  }
  if (budget.agentMaxWorseningPercent !== null) {
    rules.push({ id: 'agents.maxWorseningPercent', status: 'not_evaluated', message: ABSENT_CONFIG });
  }
  if (budget.maxRiskScore !== null) rules.push({ id: 'maxRiskScore', status: 'not_evaluated', message: ABSENT_CONFIG });
  if (budget.maxRiskWorseningPercent !== null) {
    rules.push({ id: 'maxRiskWorseningPercent', status: 'not_evaluated', message: ABSENT_CONFIG });
  }
  return rules;
}

/**
 * Judge a measured score with the pure budget evaluator.
 * `baseScore` is null when there is no baseline — never 0.
 */
function evaluateMeasured(
  score: number,
  delta: number | undefined,
  budget: DriftBudget,
): DriftBudgetRuleResult[] {
  const baseScore = delta === undefined ? null : score - delta;
  return evaluateDriftBudget({
    headScore: score,
    baseScore,
    budget,
    riskUnavailableReason: LOCAL_SCAN_RISK_NOTE,
  }).rules;
}

function flagRule(
  rule: DriftBudgetRuleResult,
  score: number,
  delta: number | undefined,
  flagBudget: number | undefined,
  flagWorseningPercent: number | undefined,
): DriftBudgetRuleResult {
  if (rule.id === 'maxScore' && flagBudget !== undefined) {
    return {
      id: 'maxScore',
      status: rule.status,
      message: rule.status === 'breach'
        ? `Failing fitness function: DriftScore ${score}/100 exceeds --drift-budget ${flagBudget}.`
        : `DriftScore ${score} is within --drift-budget ${flagBudget}.`,
    };
  }
  if (rule.id === 'maxWorseningPercent' && flagWorseningPercent !== undefined) {
    // The flag fails when a measured score has no baseline. The config key
    // does not: there the same gap is "not evaluated".
    if (delta === undefined) {
      return { id: 'maxWorseningPercent', status: 'breach', message: FLAG_WORSENING_NEEDS_BASELINE };
    }
    const actual = worseningPercent(score, score - delta);
    if (rule.status === 'breach') {
      return {
        id: 'maxWorseningPercent',
        status: 'breach',
        message: `Failing fitness function: drift worsened by ${actual.toFixed(2)}% (--drift-worsening ${flagWorseningPercent}%).`,
      };
    }
    return {
      id: 'maxWorseningPercent',
      status: 'pass',
      message: actual === 0
        ? `Drift did not worsen against --drift-worsening ${flagWorseningPercent}%.`
        : `Drift worsened by ${actual.toFixed(2)}%, within --drift-worsening ${flagWorseningPercent}%.`,
    };
  }
  return rule;
}

function summarizeFlags(
  score: number | null,
  delta: number | undefined,
  flagBudget: number | undefined,
  flagWorseningPercent: number | undefined,
): ScanSummaryDriftBudget {
  if (score === null) {
    const rules: DriftBudgetRuleResult[] = [];
    if (flagBudget !== undefined) {
      rules.push({
        id: 'maxScore',
        status: 'not_evaluated',
        message: `DriftScore is absent; --drift-budget ${flagBudget} was not compared.`,
      });
    }
    if (flagWorseningPercent !== undefined) {
      rules.push({
        id: 'maxWorseningPercent',
        status: 'not_evaluated',
        message: 'DriftScore is absent; --drift-worsening was not compared.',
      });
    }
    return fromRules('flags', 'enforce', rules);
  }

  const budget: DriftBudget = {
    mode: 'enforce',
    maxScore: flagBudget ?? null,
    maxWorseningPercent: flagWorseningPercent ?? null,
    agentMaxWorseningPercent: null,
    maxRiskScore: null,
    maxRiskWorseningPercent: null,
  };
  const rules = evaluateMeasured(score, delta, budget).map((rule) =>
    flagRule(rule, score, delta, flagBudget, flagWorseningPercent),
  );
  return fromRules('flags', 'enforce', rules);
}

function summarizeConfig(
  score: number | null,
  delta: number | undefined,
  configRaw: unknown,
): ScanSummaryDriftBudget | null {
  const parsed = parseDriftBudget(configRaw);
  if (!parsed?.ok) return null;
  if (score === null) return fromRules('config', parsed.budget.mode, absentConfigRules(parsed.budget));
  const rules = evaluateMeasured(score, delta, parsed.budget);
  return fromRules('config', parsed.budget.mode, rules);
}

/**
 * Drift-budget verdict for the scan summary.
 *
 * Calls the pure budget evaluator when a score was measured. An unmeasured
 * score is not passed in as 0. Flags replace the project config.
 * Returns null when no budget is set or the config budget does not parse.
 */
export function summarizeDriftBudget(
  score: number | null,
  delta: number | undefined,
  input: DriftBudgetSummaryInput = {},
): ScanSummaryDriftBudget | null {
  if (input.flagBudget !== undefined || input.flagWorseningPercent !== undefined) {
    return summarizeFlags(score, delta, input.flagBudget, input.flagWorseningPercent);
  }
  if (input.configRaw === undefined || input.configRaw === null) return null;
  return summarizeConfig(score, delta, input.configRaw);
}

export function buildScanSummary(artifact: ScanArtifact, budget?: DriftBudgetSummaryInput): ScanSummary {
  const score = artifact.drift.score;
  const delta = typeof artifact.delta === 'number' ? artifact.delta : null;
  return {
    schemaVersion: 1,
    driftScore: score,
    riskLevel: artifact.drift.riskLevel,
    components: artifact.drift.components,
    delta,
    baselineScore: score !== null && delta !== null ? score - delta : null,
    driftBudget: budget ? summarizeDriftBudget(score, artifact.delta, budget) : null,
  };
}

export async function writeScanSummary(
  file: string,
  artifact: ScanArtifact,
  budget?: DriftBudgetSummaryInput,
): Promise<void> {
  const target = path.resolve(file);
  await ensureDir(path.dirname(target));
  await writeJsonFile(target, buildScanSummary(artifact, budget));
}

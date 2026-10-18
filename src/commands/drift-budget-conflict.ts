import { existsSync, readFileSync } from 'node:fs';
import * as path from 'node:path';
import { CONFIG_FILES, isDataConfigFile, parseDataConfig, type ConfigFile } from '../core-open/config.js';
import { parseDriftBudget, type DriftBudget } from '../core-open/drift-budget.js';

/**
 * Coded warning printed by `vg scan` when YAML and JSON configs disagree on
 * `driftBudget`. This is a CLI notice about which file is read, not a scan
 * degradation, so it is not a core-open warning code.
 */
export const DRIFT_BUDGET_CONFLICT_CODE = 'VG_WARN_CONFIG_DRIFT_BUDGET';

type BudgetRead = { kind: 'value'; text: string } | { kind: 'absent' } | { kind: 'unreadable' } | { kind: 'code' };

/**
 * The limits `vg scan` would apply, in a fixed order. `mode` is always
 * included because an omitted mode is `warn`.
 */
export function formatDriftBudget(budget: DriftBudget): string {
  const parts = [`mode ${budget.mode}`];
  if (budget.maxScore !== null) parts.push(`maxScore ${budget.maxScore}`);
  if (budget.maxWorseningPercent !== null) parts.push(`maxWorseningPercent ${budget.maxWorseningPercent}`);
  if (budget.maxRiskScore !== null) parts.push(`maxRiskScore ${budget.maxRiskScore}`);
  if (budget.maxRiskWorseningPercent !== null) parts.push(`maxRiskWorseningPercent ${budget.maxRiskWorseningPercent}`);
  if (budget.agentMaxWorseningPercent !== null) parts.push(`agents.maxWorseningPercent ${budget.agentMaxWorseningPercent}`);
  return parts.join(', ');
}

function readBudget(root: string, file: ConfigFile): BudgetRead {
  if (!isDataConfigFile(file)) return { kind: 'code' };
  let parsed: Record<string, unknown>;
  try {
    parsed = parseDataConfig(readFileSync(path.join(root, file), 'utf8'), file);
  } catch {
    return { kind: 'unreadable' };
  }
  if (!Object.prototype.hasOwnProperty.call(parsed, 'driftBudget')) return { kind: 'absent' };
  const budget = parseDriftBudget(parsed.driftBudget);
  if (!budget?.ok) return { kind: 'unreadable' };
  return { kind: 'value', text: formatDriftBudget(budget.budget) };
}

/**
 * One sentence when more than one config file is present and a YAML or JSON
 * file sets a `driftBudget` that is not the budget in effect.
 *
 * The first present file in {@link CONFIG_FILES} wins. Files are never
 * merged. A later file that sets the same budget is quiet. A file that does
 * not parse is left to the config error path. The sentence names paths and
 * budget limits only.
 */
export function driftBudgetConflictNote(root: string): string | null {
  const present = CONFIG_FILES.filter((file) => existsSync(path.join(root, file)));
  if (present.length < 2) return null;
  const winner = present[0]!;
  const winnerBudget = readBudget(root, winner);
  if (winnerBudget.kind === 'unreadable') return null;

  const effective = winnerBudget.kind === 'value' ? winnerBudget.text : null;
  const conflicts: string[] = [];
  for (const file of present.slice(1)) {
    const read = readBudget(root, file);
    if (read.kind !== 'value' || read.text === effective) continue;
    conflicts.push(`${file} is ignored (${read.text})`);
  }
  if (conflicts.length === 0) return null;

  const winnerClause =
    winnerBudget.kind === 'value'
      ? `${winner} wins (${winnerBudget.text})`
      : winnerBudget.kind === 'absent'
        ? `${winner} wins and does not set driftBudget`
        : `${winner} wins`;
  return `driftBudget disagrees across config files. ${winnerClause}. ${conflicts.join('. ')}.`;
}

/** Stderr line for {@link driftBudgetConflictNote}. */
export function formatDriftBudgetConflictWarning(note: string): string {
  return `warning [${DRIFT_BUDGET_CONFLICT_CODE}]: ${note}`;
}

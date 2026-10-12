import * as path from 'node:path';
import { Command } from 'commander';
import chalk from 'chalk';
import { usageError } from '../../util/exit.js';
import { pathExists, readJsonFile } from '../utils/fs.js';
import { formatText } from '../formatters/text.js';
import { formatMarkdown } from '../formatters/markdown.js';
import { formatHtmlReport } from '../formatters/html.js';
import { portableValue } from '../../core-open/utils/portable-path.js';
import type { ScanArtifact } from '../types.js';

/** Formats `vg report` accepts. `text` is the default. */
export const REPORT_FORMATS = ['md', 'text', 'json', 'html'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

function isReportFormat(value: string): value is ReportFormat {
  return (REPORT_FORMATS as readonly string[]).includes(value);
}

export const reportCommand = new Command('report')
  .description('Generate a drift report from a scan artifact')
  .option('--in <file>', 'Input artifact file', '.vibgrate/scan_result.json')
  .option('--format <format>', 'Output format (md|text|json|html)', 'text')
  .action(async (opts: { in: string; format: string }) => {
    const format = opts.format;
    if (!isReportFormat(format)) {
      throw usageError(`unknown --format "${format}" (expected ${REPORT_FORMATS.join(', ')})`);
    }

    const artifactPath = path.resolve(opts.in);

    if (!(await pathExists(artifactPath))) {
      console.error(chalk.red(`Artifact not found: ${artifactPath}`));
      console.error(chalk.dim('Run "vibgrate scan" first to generate a scan artifact.'));
      process.exit(1);
    }

    const artifact = portableValue(await readJsonFile<ScanArtifact>(artifactPath));

    switch (format) {
      case 'md':
        console.log(formatMarkdown(artifact));
        break;
      case 'json':
        console.log(JSON.stringify(artifact, null, 2));
        break;
      case 'text':
        console.log(formatText(artifact));
        break;
      case 'html':
        console.log(formatHtmlReport(artifact));
        break;
    }
  });

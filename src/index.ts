import * as core from '@actions/core';
import * as github from '@actions/github';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { getConfig } from './config.js';
import { getPullRequestDiff, getLocalGitDiff } from './git.js';
import { SecurityScanner } from './engine/scanner.js';
import { RuleLoader } from './engine/loader.js';
import { RemediationEngine } from './remediation/engine.js';
import { PrCommenter, publishStepSummary } from './reporter/pr-commenter.js';
import { writeSarifReport } from './sarif.js';
import { SeverityLevel } from './types.js';

const SEVERITY_RANKS: Record<SeverityLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0
};

const REMEDIATION_CONCURRENCY = 4;

async function runWithConcurrency<T>(
  items: readonly T[],
  limit: number,
  worker: (item: T, index: number) => Promise<void>
): Promise<void> {
  if (items.length === 0) return;
  const workerCount = Math.min(Math.max(1, limit), items.length);
  let nextIndex = 0;
  await Promise.all(
    Array.from({ length: workerCount }, async () => {
      while (true) {
        const current = nextIndex++;
        if (current >= items.length) return;
        await worker(items[current], current);
      }
    })
  );
}

function readSurroundingContext(workspaceDir: string, relFile: string, lineNum: number, radius = 20): string {
  try {
    const content = readFileSync(resolve(workspaceDir, relFile), 'utf8');
    const lines = content.split(/\r?\n/);
    const start = Math.max(0, lineNum - 1 - radius);
    const end = Math.min(lines.length, lineNum + radius);
    return lines
      .slice(start, end)
      .map((l, idx) => `${start + idx + 1}: ${l}`)
      .join('\n');
  } catch {
    return '';
  }
}

export async function run(): Promise<void> {
  try {
    const config = getConfig();
    const { eventName, sha, ref, repo } = github.context;

    core.info('Wide Action initializing...');
    core.info(`Repository: ${repo.owner}/${repo.repo}`);
    core.info(`Trigger Event: ${eventName}`);
    core.info(`Git Reference: ${ref}`);
    core.info(`Commit SHA: ${sha}`);
    core.info(`Fail-On Threshold: ${config.failOn}`);
    core.info(`Only Diff: ${config.onlyDiff}`);
    core.info(`OSV SCA Scan: ${config.sca ? 'enabled' : 'disabled'}`);
    core.info(`SARIF Output: ${config.sarif ? config.outputPath : 'disabled'}`);
    core.info(`AI Remediation: ${config.aiRemediation ? `${config.provider}${config.model ? ` (${config.model})` : ''}` : 'disabled'}`);

    const prNumber = github.context.payload.pull_request?.number;
    const prHeadSha = github.context.payload.pull_request?.head?.sha || sha;
    const modifiedFilesMap = new Map<string, Set<number>>();
    const octokit = config.githubToken ? github.getOctokit(config.githubToken) : null;

    if (config.onlyDiff) {
      if (prNumber && octokit) {
        core.info(`Fetching diff for Pull Request #${prNumber}...`);
        const prDiffs = await getPullRequestDiff(octokit, repo.owner, repo.repo, prNumber);
        for (const file of prDiffs) {
          modifiedFilesMap.set(file.filename.replace(/\\/g, '/'), file.changedLines);
        }
        core.info(`Retrieved ${prDiffs.length} modified file(s) from Pull Request.`);
      } else {
        core.info('Detecting local git diff...');
        const localDiffs = await getLocalGitDiff();
        for (const file of localDiffs) {
          modifiedFilesMap.set(file.filename.replace(/\\/g, '/'), file.changedLines);
        }
        core.info(`Detected ${localDiffs.length} modified file(s) via git diff.`);
      }
    } else if (prNumber && octokit) {
      try {
        const prDiffs = await getPullRequestDiff(octokit, repo.owner, repo.repo, prNumber);
        for (const file of prDiffs) {
          modifiedFilesMap.set(file.filename.replace(/\\/g, '/'), file.changedLines);
        }
      } catch {}
    }

    core.info('Running Wide Security Scanner...');
    core.info(`Rules Source: ${config.rules}`);
    const rulesStart = Date.now();
    const activeRules = await RuleLoader.loadRules(config.rules, process.cwd());
    const agentRules = await RuleLoader.loadAgentRules(config.rules, process.cwd(), activeRules);
    const advisories = config.sca ? await RuleLoader.loadAdvisories(config.rules, process.cwd()) : undefined;
    core.debug(`Loaded ${activeRules.length} rules in ${Date.now() - rulesStart}ms.`);

    const scanStart = Date.now();
    const scanner = new SecurityScanner(process.cwd());
    const scanResult = await scanner.scan({
      onlyDiff: config.onlyDiff,
      modifiedFiles: modifiedFilesMap,
      rules: activeRules,
      sca: config.sca,
      advisories
    });
    core.debug(`Security scan completed in ${Date.now() - scanStart}ms.`);

    const scaCount = scanResult.findings.filter(f => f.source === 'sca').length;
    core.info(`Scanned ${scanResult.totalFilesScanned} file(s). Found ${scanResult.findings.length} issue(s) (SAST: ${scanResult.findings.length - scaCount}, SCA: ${scaCount}).`);
    core.info(`Severity Breakdown: [CRITICAL: ${scanResult.summary.critical}] [HIGH: ${scanResult.summary.high}] [MEDIUM: ${scanResult.summary.medium}] [LOW: ${scanResult.summary.low}]`);

    const sastFindingsForAi = scanResult.findings.filter(f => f.source !== 'sca');
    if (config.aiRemediation && sastFindingsForAi.length > 0) {
      core.info(`Running AI Remediation using provider '${config.provider}' (concurrency=${REMEDIATION_CONCURRENCY})...`);
      const remediationEngine = new RemediationEngine({
        provider: config.provider,
        model: config.model,
        apiKey: config.apiKey
      });

      await runWithConcurrency(sastFindingsForAi, REMEDIATION_CONCURRENCY, async finding => {
        try {
          const surrounding = readSurroundingContext(process.cwd(), finding.file, finding.line);
          const triage = await remediationEngine.analyzeAndRemediate(finding, surrounding, agentRules);
          if (triage.verdict) {
            finding.triageVerdict = triage.verdict;
            finding.triageReason = triage.reason;
          }
          if (triage.patch) {
            finding.suggestedPatch = triage.patch;
            core.info(`Generated AI fix for ${finding.file}:${finding.line} (${finding.ruleId})`);
          }
        } catch (err) {
          core.warning(`Failed to generate AI fix for ${finding.file}:${finding.line}: ${String(err)}`);
        }
      });
    }

    if (config.sarif) {
      writeSarifReport(config.outputPath, scanResult.findings, process.cwd(), activeRules);
      core.setOutput('sarif-path', config.outputPath);
    } else {
      core.setOutput('sarif-path', '');
    }

    core.setOutput('findings-count', scanResult.summary.total.toString());
    core.setOutput('critical-count', scanResult.summary.critical.toString());
    core.setOutput('high-count', scanResult.summary.high.toString());
    core.setOutput('medium-count', scanResult.summary.medium.toString());
    core.setOutput('low-count', scanResult.summary.low.toString());
    core.setOutput('sca-count', scaCount.toString());

    for (const finding of scanResult.findings) {
      const location = `${finding.file}:${finding.line}`;
      const msg = `[${finding.severity}] ${finding.title} (${finding.cwe || 'N/A'}): ${finding.description}`;
      const annotation = { file: finding.file, startLine: Math.max(1, finding.line) };
      if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') {
        core.error(`${location} - ${msg}`, annotation);
      } else if (finding.severity === 'MEDIUM') {
        core.warning(`${location} - ${msg}`, annotation);
      } else {
        core.notice(`${location} - ${msg}`, annotation);
      }
    }

    let isBlocked = false;
    if (config.failOn !== 'NEVER') {
      const thresholdRank = SEVERITY_RANKS[config.failOn as SeverityLevel] || 3;
      isBlocked = scanResult.findings.some(
        f => SEVERITY_RANKS[f.severity] >= thresholdRank
      );
    }

    await publishStepSummary(scanResult, config.failOn, isBlocked);

    const commenter = octokit
      ? new PrCommenter({
          octokit,
          owner: repo.owner,
          repo: repo.repo,
          pullNumber: prNumber || 0,
          commitSha: prHeadSha
        })
      : null;

    if (prNumber && commenter) {
      core.info('Publishing PR review and summary comments...');
      await commenter.postOrUpdateSummary(scanResult, config.failOn, isBlocked);
      await commenter.postInlineReviewComments(
        scanResult.findings,
        modifiedFilesMap.size > 0 ? modifiedFilesMap : undefined
      );
    }

    if (config.checkRun && commenter) {
      await commenter.publishCheckRun(scanResult, config.failOn, isBlocked);
    }

    if (isBlocked) {
      const thresholdRank = SEVERITY_RANKS[config.failOn as SeverityLevel] || 3;
      const blockingCount = scanResult.findings.filter(
        f => SEVERITY_RANKS[f.severity] >= thresholdRank
      ).length;
      core.setFailed(
        `Wide Security Gate: Found ${blockingCount} issue(s) at or above ${config.failOn} threshold.`
      );
      return;
    }

    core.info('Wide Security Gate: All checks passed.');
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed(String(error));
    }
  }
}

void run();

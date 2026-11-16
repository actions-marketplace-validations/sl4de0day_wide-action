import * as core from '@actions/core';
import type { getOctokit } from '@actions/github';
import { ScanResult, VulnerabilityFinding } from '../types.js';
import { formatSummaryComment, formatInlineComment } from './markdown.js';
import { withRetry } from '../retry.js';

export interface CommenterOptions {
  octokit: ReturnType<typeof getOctokit>;
  owner: string;
  repo: string;
  pullNumber: number;
  commitSha: string;
}

export class PrCommenter {
  private octokit: ReturnType<typeof getOctokit>;
  private owner: string;
  private repo: string;
  private pullNumber: number;
  private commitSha: string;

  constructor(options: CommenterOptions) {
    this.octokit = options.octokit;
    this.owner = options.owner;
    this.repo = options.repo;
    this.pullNumber = options.pullNumber;
    this.commitSha = options.commitSha;
  }

  public async postOrUpdateSummary(
    scanResult: ScanResult,
    failOn: string,
    isBlocked: boolean
  ): Promise<void> {
    try {
      const body = formatSummaryComment(scanResult, failOn, isBlocked);
      const comments = await withRetry(
        () => this.octokit.paginate(
          this.octokit.rest.issues.listComments,
          {
            owner: this.owner,
            repo: this.repo,
            issue_number: this.pullNumber,
            per_page: 100
          }
        ),
        {
          onRetry: (_err, attempt, delayMs) => core.debug(`Retrying listComments (attempt ${attempt}, delay ${delayMs}ms)`)
        }
      );

      const existingComment = comments.find(
        c => c.body && c.body.includes('data-wide-action="summary"')
      );

      if (existingComment) {
        core.info(`Updating existing PR summary comment (ID: ${existingComment.id})...`);
        await withRetry(() => this.octokit.rest.issues.updateComment({
          owner: this.owner,
          repo: this.repo,
          comment_id: existingComment.id,
          body
        }));
      } else {
        core.info('Posting new PR summary comment...');
        await withRetry(() => this.octokit.rest.issues.createComment({
          owner: this.owner,
          repo: this.repo,
          issue_number: this.pullNumber,
          body
        }));
      }
    } catch (error) {
      core.warning(`Failed to post or update PR summary comment: ${String(error)}`);
    }
  }

  public async postInlineReviewComments(
    findings: VulnerabilityFinding[],
    diffLinesMap?: Map<string, Set<number>>
  ): Promise<number> {
    if (findings.length === 0) return 0;

    try {
      const existingReviews = await withRetry(
        () => this.octokit.paginate(
          this.octokit.rest.pulls.listReviewComments,
          {
            owner: this.owner,
            repo: this.repo,
            pull_number: this.pullNumber,
            per_page: 100
          }
        ),
        {
          onRetry: (_err, attempt, delayMs) => core.debug(`Retrying listReviewComments (attempt ${attempt}, delay ${delayMs}ms)`)
        }
      );

      const existingKeys = new Set<string>();
      for (const review of existingReviews) {
        const match = review.body?.match(/data-rule-id="([^"]+)"/);
        const ruleId = match ? match[1] : '';
        const key = `${review.path}:${review.line || review.original_line || 0}:${ruleId}`;
        existingKeys.add(key);
      }

      const newComments: Array<{ path: string; line: number; side: 'RIGHT'; body: string }> = [];

      for (const finding of findings) {
        const normalizedPath = finding.file.replace(/\\/g, '/');
        if (diffLinesMap && diffLinesMap.size > 0) {
          const fileChanged = diffLinesMap.get(normalizedPath);
          if (!fileChanged || !fileChanged.has(finding.line)) {
            continue;
          }
        }
        const key = `${normalizedPath}:${finding.line}:${finding.ruleId}`;

        if (existingKeys.has(key)) {
          continue;
        }

        existingKeys.add(key);
        newComments.push({
          path: normalizedPath,
          line: finding.line,
          side: 'RIGHT',
          body: formatInlineComment(finding)
        });
      }

      if (newComments.length === 0) {
        core.info('No new inline review comments to post.');
        return 0;
      }

      core.info(`Submitting ${newComments.length} inline review comment(s)...`);

      const batchSize = 25;
      for (let i = 0; i < newComments.length; i += batchSize) {
        const batch = newComments.slice(i, i + batchSize);
        try {
          await withRetry(() => this.octokit.rest.pulls.createReview({
            owner: this.owner,
            repo: this.repo,
            pull_number: this.pullNumber,
            commit_id: this.commitSha,
            event: 'COMMENT',
            comments: batch
          }));
        } catch (batchError) {
          core.warning(`Batch inline review failed, trying individually: ${String(batchError)}`);
          for (const item of batch) {
            try {
              await withRetry(() => this.octokit.rest.pulls.createReviewComment({
                owner: this.owner,
                repo: this.repo,
                pull_number: this.pullNumber,
                commit_id: this.commitSha,
                path: item.path,
                line: item.line,
                side: 'RIGHT',
                body: item.body
              }));
            } catch (singleError) {
              core.warning(`Failed to comment on ${item.path}:${item.line} - ${String(singleError)}`);
            }
          }
        }
      }

      return newComments.length;
    } catch (error) {
      core.warning(`Failed to submit inline review comments: ${String(error)}`);
      return 0;
    }
  }

  public async publishCheckRun(
    scanResult: ScanResult,
    failOn: string,
    isBlocked: boolean
  ): Promise<boolean> {
    const checksApi = (this.octokit as any)?.rest?.checks;
    if (!checksApi || typeof checksApi.create !== 'function') {
      return false;
    }

    const annotations = scanResult.findings.slice(0, 50).map((f) => ({
      path: f.file.replace(/\\/g, '/'),
      start_line: Math.max(1, f.line),
      end_line: Math.max(1, f.endLine || f.line),
      annotation_level:
        f.severity === 'CRITICAL' || f.severity === 'HIGH'
          ? ('failure' as const)
          : f.severity === 'MEDIUM'
            ? ('warning' as const)
            : ('notice' as const),
      title: `[${f.severity}] ${f.title} (${f.ruleId})`,
      message: `${f.description}${f.remediation ? ` Remediation: ${f.remediation}` : ''}`
    }));

    try {
      await withRetry(() => checksApi.create({
        owner: this.owner,
        repo: this.repo,
        name: 'Wide Security Audit',
        head_sha: this.commitSha,
        status: 'completed',
        conclusion: isBlocked ? 'failure' : 'success',
        output: {
          title: isBlocked
            ? `Blocked: ${scanResult.summary.total} issue(s) at or above ${failOn}`
            : `Passed: ${scanResult.summary.total} issue(s) detected`,
          summary: formatSummaryComment(scanResult, failOn, isBlocked),
          annotations
        }
      }));
      return true;
    } catch (error: any) {
      const status = Number(error?.status || error?.statusCode || 0);
      if (status === 403 || status === 404) {
        core.info('Optional Check Run skipped: token does not have checks:write permission.');
      } else {
        core.warning(`Failed to publish GitHub Check Run: ${String(error)}`);
      }
      return false;
    }
  }
}

export async function publishStepSummary(
  scanResult: ScanResult,
  failOn: string,
  isBlocked: boolean
): Promise<boolean> {
  if (!process.env.GITHUB_STEP_SUMMARY) {
    return false;
  }
  try {
    await core.summary.addRaw(formatSummaryComment(scanResult, failOn, isBlocked)).write({ overwrite: true });
    return true;
  } catch (error) {
    core.debug(`Failed to write GitHub Step Summary: ${String(error)}`);
    return false;
  }
}

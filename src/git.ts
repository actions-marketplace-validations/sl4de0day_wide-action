import { execFile } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { promisify } from 'node:util';
import * as core from '@actions/core';
import type { getOctokit } from '@actions/github';
import { ModifiedFileDiff } from './types.js';
import { withRetry } from './retry.js';

const execFileAsync = promisify(execFile);
const GIT_MAX_BUFFER = 16 * 1024 * 1024;

const HUNK_REGEX = /^@@\s+-(?<oldStart>\d+)(?:,(?<oldLines>\d+))?\s+\+(?<newStart>\d+)(?:,(?<newLines>\d+))?\s+@@/;

export function parsePatch(patch: string): Set<number> {
  const changedLines = new Set<number>();
  if (!patch) return changedLines;

  const lines = patch.split('\n');
  let currentNewLine = 0;
  let inHunk = false;

  for (const line of lines) {
    if (line.startsWith('diff --git ')) {
      inHunk = false;
      continue;
    }
    const match = line.match(HUNK_REGEX);
    if (match && match.groups) {
      inHunk = true;
      currentNewLine = parseInt(match.groups.newStart, 10);
      continue;
    }

    if (!inHunk) continue;

    if (line.startsWith('+')) {
      changedLines.add(currentNewLine);
      currentNewLine++;
    } else if (line.startsWith('-')) {
      continue;
    } else if (line.startsWith(' ') || line === '') {
      currentNewLine++;
    }
  }

  return changedLines;
}

export function parseUnifiedDiff(rawDiff: string): ModifiedFileDiff[] {
  const result: ModifiedFileDiff[] = [];
  if (!rawDiff.trim()) return result;

  const fileChunks = rawDiff.split(/^diff --git\s+/m).filter(Boolean);

  for (const chunk of fileChunks) {
    const lines = chunk.split('\n');
    let filename = '';

    for (const line of lines) {
      if (line.startsWith('+++ b/')) {
        filename = line.slice(6).trim();
        break;
      }
    }

    if (!filename) {
      const match = lines[0].match(/a\/(.+?)\s+b\/(.+)/);
      if (match) {
        filename = match[2].trim();
      }
    }

    if (!filename || filename === '/dev/null') continue;

    const changedLines = parsePatch(chunk);
    let additions = 0;
    let deletions = 0;

    for (const line of lines) {
      if (line.startsWith('+') && !line.startsWith('+++')) additions++;
      if (line.startsWith('-') && !line.startsWith('---')) deletions++;
    }

    result.push({
      filename,
      status: deletions > 0 && additions === 0 ? 'removed' : additions > 0 && deletions === 0 ? 'added' : 'modified',
      additions,
      deletions,
      changedLines,
      patch: chunk
    });
  }

  return result;
}

export async function getPullRequestDiff(
  octokit: ReturnType<typeof getOctokit>,
  owner: string,
  repo: string,
  pullNumber: number
): Promise<ModifiedFileDiff[]> {
  try {
    const files = await withRetry(
      () => octokit.paginate(octokit.rest.pulls.listFiles, {
        owner,
        repo,
        pull_number: pullNumber,
        per_page: 100
      }),
      {
        onRetry: (_err, attempt, delayMs) => core.debug(`Retrying pulls.listFiles (attempt ${attempt}, delay ${delayMs}ms)`)
      }
    );

    return files.map(file => ({
      filename: file.filename,
      status: file.status,
      additions: file.additions,
      deletions: file.deletions,
      changedLines: parsePatch(file.patch || ''),
      patch: file.patch
    }));
  } catch (error) {
    core.warning(`Failed to fetch pull request files via GitHub API: ${String(error)}`);
    return getLocalGitDiff();
  }
}

function resolveFallbackBaseRef(explicitRef?: string): string {
  if (explicitRef) return explicitRef;
  const baseRef = process.env.GITHUB_BASE_REF?.trim();
  if (baseRef) return `origin/${baseRef}...HEAD`;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (eventPath && existsSync(eventPath)) {
    try {
      const payload = JSON.parse(readFileSync(eventPath, 'utf8'));
      const before = typeof payload?.before === 'string' ? payload.before.trim() : '';
      if (before && !/^0+$/.test(before)) {
        return `${before}..HEAD`;
      }
    } catch {}
  }
  return 'HEAD~1';
}

export async function getLocalGitDiff(baseRef?: string): Promise<ModifiedFileDiff[]> {
  try {
    const targetRef = resolveFallbackBaseRef(baseRef);
    const diffArgs = targetRef.includes('..')
      ? ['diff', '-U0', targetRef]
      : ['diff', '-U0', targetRef, 'HEAD'];
    const { stdout } = await execFileAsync('git', diffArgs, { maxBuffer: GIT_MAX_BUFFER });
    return parseUnifiedDiff(stdout);
  } catch {
    try {
      const { stdout } = await execFileAsync('git', ['diff', '-U0', 'HEAD~1', 'HEAD'], { maxBuffer: GIT_MAX_BUFFER });
      return parseUnifiedDiff(stdout);
    } catch {
      try {
        const { stdout } = await execFileAsync('git', ['diff', '-U0', 'HEAD'], { maxBuffer: GIT_MAX_BUFFER });
        return parseUnifiedDiff(stdout);
      } catch (err) {
        core.warning(`Failed to extract local git diff: ${String(err)}`);
        return [];
      }
    }
  }
}

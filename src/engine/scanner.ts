import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { resolve, relative, extname, join } from 'node:path';
import { SECURITY_RULES, SecurityRule } from './rules.js';
import {
  ScanResult,
  ScanOptions,
  SeverityLevel,
  ScanSummary,
  VulnerabilityFinding
} from '../types.js';

const MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024;
const MAX_LINE_LENGTH = 1500;

const EXTENSION_MAP: Record<string, string> = {
  '.js': 'js',
  '.jsx': 'js',
  '.mjs': 'js',
  '.cjs': 'js',
  '.ts': 'ts',
  '.tsx': 'ts',
  '.py': 'py',
  '.php': 'php',
  '.java': 'java',
  '.cs': 'cs',
  '.go': 'go',
  '.rb': 'rb',
  '.rs': 'rs',
  '.c': 'c',
  '.cpp': 'c',
  '.h': 'c'
};

const SEVERITY_RANKS: Record<SeverityLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0
};

const IGNORED_DIRECTORIES = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'vendor',
  '.next',
  'target',
  'coverage',
  '.gemini',
  '.vscode'
]);

export class SecurityScanner {
  private workspaceDir: string;

  constructor(workspaceDir = process.cwd()) {
    this.workspaceDir = resolve(workspaceDir);
  }

  public async scan(options: ScanOptions = {}): Promise<ScanResult> {
    const minSeverity = options.minSeverity || 'LOW';
    const minRank = minSeverity === 'ALL' ? 0 : SEVERITY_RANKS[minSeverity] || 1;
    const activeRules: readonly SecurityRule[] = (options.rules && options.rules.length > 0) ? options.rules : SECURITY_RULES;
    const findings: VulnerabilityFinding[] = [];
    const rulesByLang = new Map<string, SecurityRule[]>();
    let scannedFilesCount = 0;

    if (options.onlyDiff) {
      if (options.modifiedFiles) {
        for (const [rawFilePath, changedLines] of options.modifiedFiles.entries()) {
          if (!changedLines || changedLines.size === 0) continue;
          const normalizedRel = rawFilePath.replace(/\\/g, '/');
          if (!this.isScannableRelativePath(normalizedRel)) continue;

          const fullPath = resolve(this.workspaceDir, normalizedRel);
          if (this.scanSingleFile(fullPath, normalizedRel, changedLines, minRank, activeRules, rulesByLang, findings)) {
            scannedFilesCount++;
          }
        }
      }
    } else {
      const allFiles = this.collectWorkspaceFiles(this.workspaceDir);
      for (const fullPath of allFiles) {
        const relPath = relative(this.workspaceDir, fullPath).replace(/\\/g, '/');
        if (this.scanSingleFile(fullPath, relPath, undefined, minRank, activeRules, rulesByLang, findings)) {
          scannedFilesCount++;
        }
      }
    }

    const summary: ScanSummary = {
      total: findings.length,
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
      info: findings.filter(f => f.severity === 'INFO').length
    };

    return {
      totalFilesScanned: scannedFilesCount,
      findings,
      summary
    };
  }

  private isScannableRelativePath(relPath: string): boolean {
    const ext = extname(relPath).toLowerCase();
    if (!(ext in EXTENSION_MAP)) return false;
    const segments = relPath.split('/');
    for (let i = 0; i < segments.length - 1; i++) {
      if (IGNORED_DIRECTORIES.has(segments[i])) return false;
    }
    return true;
  }

  private getRulesForLanguage(
    lang: string,
    minRank: number,
    rules: readonly SecurityRule[],
    rulesByLang: Map<string, SecurityRule[]>
  ): SecurityRule[] {
    let cached = rulesByLang.get(lang);
    if (!cached) {
      cached = rules.filter(
        r => SEVERITY_RANKS[r.severity] >= minRank && (r.languages.includes('all') || r.languages.includes(lang))
      );
      rulesByLang.set(lang, cached);
    }
    return cached;
  }

  private scanSingleFile(
    fullPath: string,
    relPath: string,
    changedLines: Set<number> | undefined,
    minRank: number,
    rules: readonly SecurityRule[],
    rulesByLang: Map<string, SecurityRule[]>,
    findings: VulnerabilityFinding[]
  ): boolean {
    const ext = extname(fullPath).toLowerCase();
    const lang = EXTENSION_MAP[ext];
    if (!lang) return false;

    let raw: Buffer;
    try {
      const st = statSync(fullPath);
      if (!st.isFile() || st.size > MAX_SCAN_FILE_BYTES) return false;
      raw = readFileSync(fullPath);
    } catch {
      return false;
    }

    if (raw.subarray(0, Math.min(raw.length, 4096)).includes(0)) {
      return false;
    }

    const content = raw.toString('utf8');
    const lines = content.split('\n');
    const applicableRules = this.getRulesForLanguage(lang, minRank, rules, rulesByLang);

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;

      if (changedLines && !changedLines.has(lineNum)) {
        continue;
      }

      const lineText = lines[i];
      if (lineText.length > MAX_LINE_LENGTH) continue;

      for (const rule of applicableRules) {
        if (rule.pattern.test(lineText)) {
          if (rule.notMatch && rule.notMatch.test(lineText)) continue;
          let confirmed = true;
          if (rule.sourcePattern) {
            const windowStart = Math.max(0, i - 15);
            const windowText = lines.slice(windowStart, i + 1).join('\n');
            confirmed = rule.sourcePattern.test(windowText);
          }

          if (confirmed) {
            findings.push({
              id: `${rule.id}-${relPath}-${lineNum}`,
              ruleId: rule.id,
              cwe: rule.cwe,
              title: rule.category,
              description: rule.message,
              severity: rule.severity,
              file: relPath,
              line: lineNum,
              snippet: lineText.trim(),
              remediation: rule.remediation
            });
          }
        }
      }
    }
    return true;
  }

  private collectWorkspaceFiles(dir: string): string[] {
    const results: string[] = [];
    if (!existsSync(dir)) return results;

    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (IGNORED_DIRECTORIES.has(entry.name)) continue;

      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...this.collectWorkspaceFiles(fullPath));
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        if (ext in EXTENSION_MAP) {
          results.push(fullPath);
        }
      }
    }

    return results;
  }
}

import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { resolve, relative, extname, join, basename } from 'node:path';
import { SECURITY_RULES, SecurityRule } from './rules.js';
import { collectImportedPackagesFromContent, scanWorkspaceDependencies } from './sca.js';
import { analyzeProjectFlows, buildLogicalSpans } from './taint.js';
import { isLikelyRealSecret } from './secrets.js';
import {
  ScanResult,
  ScanOptions,
  SeverityLevel,
  ScanSummary,
  VulnerabilityFinding
} from '../types.js';

const MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024;
const MAX_LINE_LENGTH = 1500;

const AGENT_BEHAVIOR_ONLY_RULE_IDS = new Set([
  'wide/ai-no-emojis',
  'wide/ai-no-system-prompt-leak',
  'wide/ai-direct-file-edits',
  'wide/ai-native-tool-priority',
  'wide/ai-language-matching'
]);

const EXTENSION_LANGS: Record<string, readonly string[]> = {
  '.js': ['js'],
  '.jsx': ['jsx', 'js'],
  '.mjs': ['mjs', 'js'],
  '.cjs': ['cjs', 'js'],
  '.ts': ['ts'],
  '.tsx': ['tsx', 'ts'],
  '.mts': ['mts', 'ts'],
  '.cts': ['cts', 'ts'],
  '.vue': ['vue', 'html', 'js', 'ts'],
  '.svelte': ['svelte', 'html', 'js', 'ts'],
  '.html': ['html', 'htm', 'xhtml'],
  '.htm': ['htm', 'html', 'xhtml'],
  '.xhtml': ['xhtml', 'html', 'htm'],
  '.py': ['py'],
  '.pyi': ['pyi', 'py'],
  '.pyw': ['pyw', 'py'],
  '.php': ['php'],
  '.phtml': ['phtml', 'php'],
  '.php3': ['php3', 'php'],
  '.php4': ['php4', 'php'],
  '.php5': ['php5', 'php'],
  '.phps': ['phps', 'php'],
  '.java': ['java'],
  '.kt': ['kt', 'kotlin'],
  '.kts': ['kts', 'kt', 'kotlin'],
  '.scala': ['scala', 'sc'],
  '.sc': ['sc', 'scala'],
  '.cs': ['cs'],
  '.csx': ['csx', 'cs'],
  '.go': ['go'],
  '.rb': ['rb'],
  '.rs': ['rs'],
  '.c': ['c'],
  '.cc': ['cc', 'c'],
  '.cpp': ['cpp', 'c'],
  '.cxx': ['cxx', 'c'],
  '.h': ['h', 'c'],
  '.hh': ['hh', 'c'],
  '.hpp': ['hpp', 'c'],
  '.erl': ['erl'],
  '.hrl': ['hrl', 'erl'],
  '.ex': ['ex'],
  '.exs': ['exs', 'ex'],
  '.sql': ['sql'],
  '.json': ['json'],
  '.yaml': ['yaml', 'yml'],
  '.yml': ['yml', 'yaml'],
  '.tf': ['tf', 'hcl'],
  '.tfvars': ['tf', 'hcl']
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
  '.venv',
  'venv',
  '__pycache__',
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
    const rawRules: readonly SecurityRule[] = (options.rules && options.rules.length > 0) ? options.rules : SECURITY_RULES;
    const activeRules = rawRules.filter((r) => !AGENT_BEHAVIOR_ONLY_RULE_IDS.has(r.id));
    const findings: VulnerabilityFinding[] = [];
    const rulesByLangKey = new Map<string, SecurityRule[]>();
    const collectedSources: Array<{ file: string; lang: string; content: string }> = [];
    const importedPackages = new Set<string>();
    let scannedFilesCount = 0;

    if (options.onlyDiff) {
      if (options.modifiedFiles) {
        for (const [rawFilePath, changedLines] of options.modifiedFiles.entries()) {
          if (!changedLines || changedLines.size === 0) continue;
          const normalizedRel = rawFilePath.replace(/\\/g, '/');
          if (!this.isScannableRelativePath(normalizedRel)) continue;

          const fullPath = resolve(this.workspaceDir, normalizedRel);
          if (this.scanSingleFile(fullPath, normalizedRel, changedLines, minRank, activeRules, rulesByLangKey, findings, collectedSources, importedPackages)) {
            scannedFilesCount++;
          }
        }
      }
    } else {
      const allFiles = this.collectWorkspaceFiles(this.workspaceDir);
      for (const fullPath of allFiles) {
        const relPath = relative(this.workspaceDir, fullPath).replace(/\\/g, '/');
        if (this.scanSingleFile(fullPath, relPath, undefined, minRank, activeRules, rulesByLangKey, findings, collectedSources, importedPackages)) {
          scannedFilesCount++;
        }
      }
    }

    if (collectedSources.length > 0) {
      const flowFindings = analyzeProjectFlows(collectedSources);
      for (const flow of flowFindings) {
        if (SEVERITY_RANKS[flow.severity] < minRank) continue;
        if (options.onlyDiff && options.modifiedFiles) {
          const changed = options.modifiedFiles.get(flow.file);
          if (!changed) continue;
          const end = flow.endLine || flow.line;
          let touchesDiff = false;
          for (let ln = flow.line; ln <= end; ln++) {
            if (changed.has(ln)) {
              touchesDiff = true;
              break;
            }
          }
          if (!touchesDiff) continue;
        }
        findings.push(flow);
      }
    }

    const dedupedFindings = this.deduplicateFindings(findings);

    if (options.sca !== false && options.advisories) {
      const scaFindings = scanWorkspaceDependencies({
        workspaceDir: this.workspaceDir,
        advisories: options.advisories,
        onlyDiff: options.onlyDiff,
        modifiedFiles: options.modifiedFiles,
        minRank,
        severityRanks: SEVERITY_RANKS,
        importedPackages: !options.onlyDiff && importedPackages.size > 0 ? importedPackages : undefined
      });
      dedupedFindings.push(...scaFindings);
    }

    const summary: ScanSummary = {
      total: dedupedFindings.length,
      critical: dedupedFindings.filter(f => f.severity === 'CRITICAL').length,
      high: dedupedFindings.filter(f => f.severity === 'HIGH').length,
      medium: dedupedFindings.filter(f => f.severity === 'MEDIUM').length,
      low: dedupedFindings.filter(f => f.severity === 'LOW').length,
      info: dedupedFindings.filter(f => f.severity === 'INFO').length
    };

    return {
      totalFilesScanned: scannedFilesCount,
      findings: dedupedFindings,
      summary
    };
  }

  private deduplicateFindings(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
    const bySlot = new Map<string, VulnerabilityFinding>();
    const passthrough: VulnerabilityFinding[] = [];

    for (const f of findings) {
      const hasValidCwe = f.cwe && f.cwe !== 'N/A';
      if (!hasValidCwe) {
        passthrough.push(f);
        continue;
      }
      const key = `${f.file}:${f.line}:${f.cwe}`;
      const existing = bySlot.get(key);
      if (!existing || SEVERITY_RANKS[f.severity] > SEVERITY_RANKS[existing.severity]) {
        bySlot.set(key, f);
      }
    }

    return [...bySlot.values(), ...passthrough].sort((a, b) =>
      a.file.localeCompare(b.file) || a.line - b.line || a.ruleId.localeCompare(b.ruleId)
    );
  }

  private resolveLangTokens(filePath: string): readonly string[] | null {
    const ext = extname(filePath).toLowerCase();
    if (ext in EXTENSION_LANGS) {
      return EXTENSION_LANGS[ext];
    }
    const base = basename(filePath).toLowerCase();
    if (base === 'dockerfile' || base.startsWith('dockerfile.')) {
      return ['yaml', 'yml'];
    }
    return null;
  }

  private isScannableRelativePath(relPath: string): boolean {
    if (!this.resolveLangTokens(relPath)) return false;
    const segments = relPath.split('/');
    for (let i = 0; i < segments.length - 1; i++) {
      if (IGNORED_DIRECTORIES.has(segments[i])) return false;
    }
    return true;
  }

  private getRulesForLanguage(
    langTokens: readonly string[],
    minRank: number,
    rules: readonly SecurityRule[],
    rulesByLangKey: Map<string, SecurityRule[]>
  ): SecurityRule[] {
    const key = langTokens.join(',');
    let cached = rulesByLangKey.get(key);
    if (!cached) {
      const isDataConfigOnly = langTokens.every((t) => ['json', 'yaml', 'yml', 'tf', 'hcl'].includes(t));
      cached = rules.filter((r) => {
        if (SEVERITY_RANKS[r.severity] < minRank) return false;
        if (r.languages.includes('all')) {
          return !isDataConfigOnly;
        }
        return langTokens.some((t) => r.languages.includes(t));
      });
      rulesByLangKey.set(key, cached);
    }
    return cached;
  }

  private isCommentOnlyLine(lineText: string, langTokens: readonly string[]): boolean {
    const trimmed = lineText.trim();
    if (!trimmed) return true;
    const isJson = langTokens.length === 1 && langTokens[0] === 'json';
    if (isJson) return false;
    if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('* ') || trimmed === '*' || trimmed.startsWith('<!--')) {
      return true;
    }
    const usesHashComment = langTokens.some((t) => ['py', 'rb', 'yaml', 'yml', 'ex', 'exs', 'tf', 'hcl'].includes(t));
    if (usesHashComment && trimmed.startsWith('#')) {
      return true;
    }
    return false;
  }

  private scanSingleFile(
    fullPath: string,
    relPath: string,
    changedLines: Set<number> | undefined,
    minRank: number,
    rules: readonly SecurityRule[],
    rulesByLangKey: Map<string, SecurityRule[]>,
    findings: VulnerabilityFinding[],
    collectedSources?: Array<{ file: string; lang: string; content: string }>,
    importedPackages?: Set<string>
  ): boolean {
    const langTokens = this.resolveLangTokens(fullPath);
    if (!langTokens) return false;

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
    if (collectedSources && !['json', 'yaml', 'yml', 'tf', 'hcl', 'sql'].includes(langTokens[0])) {
      collectedSources.push({ file: relPath, lang: langTokens[0], content });
    }
    if (importedPackages) {
      collectImportedPackagesFromContent(content, importedPackages);
    }

    const lines = content.split(/\r?\n/);
    const fileHead = lines.slice(0, Math.min(lines.length, 15)).join('\n');
    const applicableRules = this.getRulesForLanguage(langTokens, minRank, rules, rulesByLangKey);
    const spans = buildLogicalSpans(lines);
    const seenLineRule = new Set<string>();

    const evaluateCandidate = (text: string, lineIdx: number, endLineNum: number) => {
      const lineNum = lineIdx + 1;
      const windowSlice = lines.slice(Math.max(0, lineIdx - 5), Math.min(lines.length, lineIdx + 6)).join('\n');
      for (const rule of applicableRules) {
        if (!rule.pattern.test(text)) continue;
        if (rule.notMatch) {
          if (rule.notMatch.test(text)) continue;
          if ((rule.id.startsWith('wide/xxe-') || rule.id.startsWith('wide/client-crypto-')) && (rule.notMatch.test(windowSlice) || rule.notMatch.test(fileHead))) {
            continue;
          }
        }
        if (rule.category === 'SECRETS' && !isLikelyRealSecret(text, relPath)) {
          continue;
        }
        if (rule.sourcePattern) {
          const windowStart = Math.max(0, lineIdx - 15);
          const windowText = lines.slice(windowStart, lineIdx + 1).join('\n');
          if (!rule.sourcePattern.test(windowText)) continue;
        }
        const key = `${lineNum}:${rule.id}`;
        if (seenLineRule.has(key)) continue;
        seenLineRule.add(key);

        findings.push({
          id: `${rule.id}-${relPath}-${lineNum}`,
          ruleId: rule.id,
          cwe: rule.cwe,
          title: rule.category,
          description: rule.message,
          severity: rule.severity,
          file: relPath,
          line: lineNum,
          ...(endLineNum > lineNum ? { endLine: endLineNum } : {}),
          snippet: lines[lineIdx].trim(),
          rawSnippet: endLineNum > lineNum ? lines.slice(lineIdx, endLineNum).join('\n') : lines[lineIdx],
          remediation: rule.remediation,
          source: 'sast'
        });
      }
    };

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      if (changedLines && !changedLines.has(lineNum)) continue;
      const lineText = lines[i];
      if (lineText.length > MAX_LINE_LENGTH) continue;
      if (/\bwide-ignore\b/i.test(lineText)) continue;
      if (i > 0 && /\bwide-ignore(-next-line)?\b/i.test(lines[i - 1])) continue;
      if (this.isCommentOnlyLine(lineText, langTokens)) continue;
      evaluateCandidate(lineText, i, lineNum);
    }

    for (const span of spans) {
      if (span.endLine <= span.startLine) continue;
      const startIdx = span.startLine - 1;
      if (/\bwide-ignore\b/i.test(lines[startIdx] || '')) continue;
      if (startIdx > 0 && /\bwide-ignore(-next-line)?\b/i.test(lines[startIdx - 1] || '')) continue;
      if (changedLines) {
        let touches = false;
        for (let ln = span.startLine; ln <= span.endLine; ln++) {
          if (changedLines.has(ln)) {
            touches = true;
            break;
          }
        }
        if (!touches) continue;
      }
      evaluateCandidate(span.text, startIdx, span.endLine);
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
        if (this.resolveLangTokens(fullPath)) {
          results.push(fullPath);
        }
      }
    }

    return results;
  }
}

import { SeverityLevel } from '../types.js';
import { CompactEmbeddedRule, EMBEDDED_RULES_DATA } from './embedded-bundle.js';

export interface SecurityRule {
  id: string;
  cwe: string;
  category: string;
  severity: SeverityLevel;
  languages: string[];
  pattern: RegExp;
  notMatch?: RegExp;
  sourcePattern?: RegExp;
  message: string;
  remediation: string;
  instruction?: string;
}

const VALID_SEVERITIES = new Set<SeverityLevel>(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

export function normalizeSeverity(raw: unknown): SeverityLevel {
  const upper = String(raw || 'MEDIUM').trim().toUpperCase() as SeverityLevel;
  return VALID_SEVERITIES.has(upper) ? upper : 'MEDIUM';
}

export function compileRulePattern(rawPattern: string, rawFlags?: string): RegExp {
  const cleaned = typeof rawFlags === 'string'
    ? rawFlags.replace(/[gy]/g, '')
    : (rawPattern.includes('\\uD800') ? '' : 'i');
  const needsUnicode = /\\(?:p\{|P\{|u\{)/.test(rawPattern);
  const flags = needsUnicode && !cleaned.includes('u') && !rawPattern.includes('\\uD800')
    ? `${cleaned}u`
    : cleaned;
  try {
    return new RegExp(rawPattern, flags);
  } catch {
    return new RegExp(rawPattern, flags.replace('u', ''));
  }
}

export function toSecurityRule(item: Partial<CompactEmbeddedRule> & Record<string, any>): SecurityRule | null {
  if (!item || typeof item.id !== 'string' || !item.id || typeof item.pattern !== 'string' || !item.pattern) {
    return null;
  }
  try {
    const notMatchRaw = item['not-match'] || item.notMatch;
    const sourceRaw = item['source-pattern'] || item.sourcePattern;
    return {
      id: item.id,
      cwe: typeof item.cwe === 'string' && item.cwe ? item.cwe : 'N/A',
      category: typeof item.category === 'string' && item.category ? item.category : 'General Security',
      severity: normalizeSeverity(item.severity),
      languages: Array.isArray(item.languages) && item.languages.length > 0 ? [...item.languages] : ['all'],
      pattern: compileRulePattern(item.pattern, item.flags),
      notMatch: typeof notMatchRaw === 'string' && notMatchRaw ? compileRulePattern(notMatchRaw, item.flags) : undefined,
      sourcePattern: typeof sourceRaw === 'string' && sourceRaw ? compileRulePattern(sourceRaw, item.flags) : undefined,
      message: typeof item.message === 'string' ? item.message : '',
      remediation: typeof item.remediation === 'string' ? item.remediation : '',
      instruction: typeof item.instruction === 'string' && item.instruction
        ? item.instruction
        : (typeof item.message === 'string' ? item.message : '')
    };
  } catch {
    return null;
  }
}

export const SECURITY_RULES: readonly SecurityRule[] = EMBEDDED_RULES_DATA
  .map((item) => toSecurityRule(item))
  .filter((r): r is SecurityRule => r !== null);

export const DEFAULT_AGENT_RULES: readonly SecurityRule[] = SECURITY_RULES.filter(
  (r) => r.category === 'AI_SECURITY' || r.id.includes('ai-')
);

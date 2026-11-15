import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import * as core from '@actions/core';
import { SECURITY_RULES, DEFAULT_AGENT_RULES, SecurityRule } from './rules.js';
import { fetchWithTimeout } from '../retry.js';

const REMOTE_RULES_URL = 'https://raw.githubusercontent.com/sl4de0day/wide-rules/main/dist/rules.json';
const REMOTE_OSV_URL = 'https://raw.githubusercontent.com/sl4de0day/wide-rules/main/dist/osv-bundle.json';
const REMOTE_CHECKSUMS_URL = 'https://raw.githubusercontent.com/sl4de0day/wide-rules/main/dist/SHA256SUMS';
const CHECKSUM_LINE_RE = /^([a-fA-F0-9]{64})\s+\*?(.+)$/;
const EMOJI_ZWJ_RE = /(?:\p{Extended_Pictographic}|\p{Emoji_Presentation}|[\u2600-\u27BF])(?:\uFE0F|\uFE0E|[\u{1F3FB}-\u{1F3FF}])?(?:\u200D(?:\p{Extended_Pictographic}|\p{Emoji_Presentation}|[\u2600-\u27BF])(?:\uFE0F|\uFE0E|[\u{1F3FB}-\u{1F3FF}])?)+/gu;
const EMOJI_KEYCAP_RE = /[0-9#*]\uFE0F?\u20E3/gu;
const EMOJI_MODIFIER_RE = /[\u{1F1E6}-\u{1F1FF}\u{1F3FB}-\u{1F3FF}\u{E0020}-\u{E007F}]/gu;
const EMOJI_PICTOGRAPHIC_RE = /\p{Extended_Pictographic}(?:\uFE0F|\uFE0E)?/gu;
const EMOJI_PRESENTATION_RE = /\p{Emoji_Presentation}(?:\uFE0F|\uFE0E)?/gu;
const EMOJI_BMP_RE = /[\u231A-\u23FF\u2600-\u27BF\u2B05-\u2B55][\uFE0E\uFE0F]?|[\u2139\u2194-\u21AA\u24C2\u25AA-\u25FE\u2934-\u2935\u3030\u303D\u3297\u3299]\uFE0F|[\uFE0E\uFE0F\u20E3]/gu;
const EMOJI_SURROGATE_RE = new RegExp('[\\uD800-\\uDFFF]', 'g');
const SANITIZER_REGEX_CACHE = new Map<string, RegExp>();

function parseChecksums(raw: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of String(raw || '').split(/\r?\n/)) {
    const m = CHECKSUM_LINE_RE.exec(line.trim());
    if (m) out.set(m[2].trim(), m[1].toLowerCase());
  }
  return out;
}

async function fetchRemoteChecksums(): Promise<Map<string, string>> {
  const sumRes = await fetchWithTimeout(REMOTE_CHECKSUMS_URL, {}, 15000);
  if (!sumRes.ok) {
    throw new Error(`Failed to fetch SHA256SUMS: HTTP ${sumRes.status} ${sumRes.statusText}`);
  }
  return parseChecksums(await sumRes.text());
}

function verifyChecksum(raw: string, checksums: Map<string, string>, assetName: string): void {
  const expectedSha = checksums.get(assetName);
  if (!expectedSha) {
    throw new Error(`Missing SHA-256 checksum for ${assetName} in SHA256SUMS`);
  }
  const actualSha = createHash('sha256').update(raw).digest('hex');
  if (actualSha !== expectedSha) {
    throw new Error(`SHA-256 mismatch while downloading ${assetName}`);
  }
}

export class RuleLoader {
  public static async loadRules(
    source = 'embedded',
    workspaceDir = process.cwd()
  ): Promise<SecurityRule[]> {
    const trimmed = source.trim();

    if (trimmed.toLowerCase() === 'latest') {
      try {
        core.info(`Fetching latest security rules from ${REMOTE_RULES_URL}...`);
        const [checksums, response] = await Promise.all([
          fetchRemoteChecksums(),
          fetchWithTimeout(REMOTE_RULES_URL, {}, 15000)
        ]);
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        const raw = await response.text();
        verifyChecksum(raw, checksums, 'rules.json');
        const data = JSON.parse(raw) as any;
        const list = Array.isArray(data) ? data : (data?.rules || []);
        const converted = this.parseRulesList(list);
        if (converted.length > 0) {
          core.info(`Successfully loaded ${converted.length} rules dynamically from wide-rules.`);
          return converted;
        }
      } catch (error) {
        core.warning(`Failed to fetch latest rules dynamically: ${String(error)}. Falling back to embedded rules.`);
      }
      return [...SECURITY_RULES];
    }

    if (trimmed.toLowerCase() !== 'embedded') {
      const fullPath = resolve(workspaceDir, trimmed);
      if (existsSync(fullPath)) {
        try {
          const raw = readFileSync(fullPath, 'utf8');
          const data = JSON.parse(raw);
          const list = Array.isArray(data) ? data : (data?.rules || []);
          const converted = this.parseRulesList(list);
          if (converted.length > 0) {
            core.info(`Loaded ${converted.length} custom rules from ${trimmed}.`);
            return converted;
          }
        } catch (err) {
          core.warning(`Failed to parse custom rules from ${trimmed}: ${String(err)}. Using embedded rules.`);
        }
      } else {
        core.warning(`Custom rules path not found: ${trimmed}. Using embedded rules.`);
      }
    }

    const siblingRules = resolve(workspaceDir, '../wide-rules/dist/rules.json');
    if (existsSync(siblingRules)) {
      try {
        const raw = readFileSync(siblingRules, 'utf8');
        const data = JSON.parse(raw);
        const list = Array.isArray(data) ? data : (data?.rules || []);
        const converted = this.parseRulesList(list);
        if (converted.length > 0) {
          return converted;
        }
      } catch {
        void 0;
      }
    }

    return [...SECURITY_RULES];
  }

  public static async loadAgentRules(
    source = 'embedded',
    workspaceDir = process.cwd()
  ): Promise<SecurityRule[]> {
    const allRules = await this.loadRules(source, workspaceDir);
    const filtered = allRules.filter(r => r.category === 'AI_SECURITY' || r.id.includes('ai-'));
    if (filtered.length > 0) {
      return filtered;
    }
    return [...DEFAULT_AGENT_RULES];
  }

  public static buildAgentInstructions(rules?: SecurityRule[]): string {
    const targetRules = Array.isArray(rules) && rules.length > 0 ? rules : [...DEFAULT_AGENT_RULES];
    const lines: string[] = [];
    for (const r of targetRules) {
      const text = (r.instruction || r.message || '').trim();
      if (text) {
        lines.push(`- ${text}`);
      }
    }
    return lines.join('\n');
  }

  public static sanitizeOutput(text: string, rules?: SecurityRule[]): string {
    if (!text || typeof text !== 'string') return '';
    const targetRules = Array.isArray(rules) && rules.length > 0 ? rules : [...DEFAULT_AGENT_RULES];
    let result = text
      .replace(EMOJI_ZWJ_RE, '')
      .replace(EMOJI_KEYCAP_RE, '')
      .replace(EMOJI_MODIFIER_RE, '')
      .replace(EMOJI_PICTOGRAPHIC_RE, '')
      .replace(EMOJI_PRESENTATION_RE, '')
      .replace(EMOJI_BMP_RE, '')
      .replace(EMOJI_SURROGATE_RE, '');
    for (const r of targetRules) {
      if ((r.id === 'wide/ai-no-emojis' || r.id.includes('emoji')) && r.pattern) {
        try {
          const src = r.pattern.source;
          const flags = src.includes('\\uD800') ? 'g' : 'gu';
          const cacheKey = `${flags}:${src}`;
          let compiled = SANITIZER_REGEX_CACHE.get(cacheKey);
          if (!compiled) {
            if (SANITIZER_REGEX_CACHE.size >= 64) SANITIZER_REGEX_CACHE.clear();
            compiled = new RegExp(src, flags);
            SANITIZER_REGEX_CACHE.set(cacheKey, compiled);
          }
          result = result.replace(compiled, '');
        } catch {}
      }
    }
    return result;
  }

  private static parseRulesList(list: any[]): SecurityRule[] {
    const result: SecurityRule[] = [];
    for (const item of list) {
      if (!item.id || !item.pattern) continue;
      try {
        const notMatchRaw = item['not-match'] || item.notMatch;
        result.push({
          id: item.id,
          cwe: item.cwe || 'N/A',
          category: item.category || 'General Security',
          severity: item.severity || 'MEDIUM',
          languages: item.languages || ['all'],
          pattern: new RegExp(item.pattern, 'i'),
          notMatch: typeof notMatchRaw === 'string' && notMatchRaw ? new RegExp(notMatchRaw, 'i') : undefined,
          sourcePattern: item['source-pattern'] ? new RegExp(item['source-pattern'], 'i') : undefined,
          message: item.message || '',
          remediation: item.remediation || '',
          instruction: item.instruction || item.message || ''
        });
      } catch {
        continue;
      }
    }
    return result;
  }

  public static async loadAdvisories(
    source = 'embedded',
    workspaceDir = process.cwd()
  ): Promise<Record<string, any>> {
    if (source.trim().toLowerCase() === 'latest') {
      try {
        const [checksums, res] = await Promise.all([
          fetchRemoteChecksums(),
          fetchWithTimeout(REMOTE_OSV_URL, {}, 15000)
        ]);
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }
        const raw = await res.text();
        verifyChecksum(raw, checksums, 'osv-bundle.json');
        return JSON.parse(raw);
      } catch (err) {
        core.warning(`Failed to fetch latest OSV advisories: ${String(err)}.`);
      }
    }
    const candidates = [
      resolve(workspaceDir, '.wide', 'osv.json'),
      resolve(workspaceDir, '../wide-rules/dist/osv-bundle.json')
    ];
    for (const file of candidates) {
      if (existsSync(file)) {
        try {
          return JSON.parse(readFileSync(file, 'utf8'));
        } catch {
          void 0;
        }
      }
    }
    return { npm: [], pip: [], maven: [], go: [] };
  }
}

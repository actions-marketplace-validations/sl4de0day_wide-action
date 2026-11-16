import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const currentDir = dirname(fileURLToPath(import.meta.url));
const rootDir = resolve(currentDir, '..');
const rulesDistDir = process.env.WIDE_RULES_DIST_DIR
  ? resolve(rootDir, process.env.WIDE_RULES_DIST_DIR)
  : resolve(rootDir, '../wide-rules/dist');
const rulesSrcPath = resolve(rulesDistDir, 'rules.min.json');
const osvSrcPath = resolve(rulesDistDir, 'osv-bundle.min.json');
const outPath = resolve(rootDir, 'src/engine/embedded-bundle.ts');

if (!existsSync(rulesSrcPath) || !existsSync(osvSrcPath)) {
  console.error(`Missing rules.min.json or osv-bundle.min.json in ${rulesDistDir}.`);
  process.exit(1);
}

const rawRules = JSON.parse(readFileSync(rulesSrcPath, 'utf8'));
const rulesList = (Array.isArray(rawRules) ? rawRules : rawRules.rules || []).map((r) => {
  const compact = {
    id: r.id,
    cwe: r.cwe || 'N/A',
    category: r.category || 'GENERAL',
    severity: r.severity || 'MEDIUM',
    languages: Array.isArray(r.languages) ? r.languages : ['all'],
    pattern: r.pattern,
    message: r.message || '',
    remediation: r.remediation || ''
  };
  if (r['not-match']) compact['not-match'] = r['not-match'];
  if (r['source-pattern']) compact['source-pattern'] = r['source-pattern'];
  if (r.instruction) compact.instruction = r.instruction;
  if (r.flags) compact.flags = r.flags;
  return compact;
});

const rawOsv = JSON.parse(readFileSync(osvSrcPath, 'utf8'));
const ecosystems = ['npm', 'pip', 'maven', 'go', 'cargo', 'nuget', 'composer', 'rubygems'];
const compactOsv = {};
for (const eco of ecosystems) {
  compactOsv[eco] = Array.isArray(rawOsv[eco]) ? rawOsv[eco] : [];
}

const output = [
  'export interface CompactEmbeddedRule {',
  '  readonly id: string;',
  '  readonly cwe: string;',
  '  readonly category: string;',
  '  readonly severity: string;',
  '  readonly languages: readonly string[];',
  '  readonly pattern: string;',
  "  readonly 'not-match'?: string;",
  "  readonly 'source-pattern'?: string;",
  '  readonly message: string;',
  '  readonly remediation: string;',
  '  readonly instruction?: string;',
  '  readonly flags?: string;',
  '}',
  '',
  'export interface EmbeddedAdvisoryEntry {',
  '  readonly name: string;',
  '  readonly ge?: string;',
  '  readonly lt?: string;',
  '  readonly le?: string;',
  '  readonly id: string;',
  '  readonly ghsaId?: string;',
  '  readonly cve?: string;',
  '  readonly cwe?: string;',
  '  readonly sev: string;',
  '  readonly note?: string;',
  '  readonly kev?: boolean;',
  '  readonly epss?: number;',
  '}',
  '',
  `export const EMBEDDED_RULES_VERSION = ${JSON.stringify(String(rawRules.version || '0.4151126'))};`,
  `export const EMBEDDED_RULES_DATA: readonly CompactEmbeddedRule[] = ${JSON.stringify(rulesList)};`,
  `export const EMBEDDED_OSV_DATA: Record<string, readonly EmbeddedAdvisoryEntry[]> = ${JSON.stringify(compactOsv)};`,
  ''
].join('\n');

writeFileSync(outPath, output, 'utf8');
console.log(`Synced ${rulesList.length} rules and ${Object.values(compactOsv).reduce((a, b) => a + b.length, 0)} advisories into src/engine/embedded-bundle.ts (${Math.round(output.length / 1024)} KB).`);

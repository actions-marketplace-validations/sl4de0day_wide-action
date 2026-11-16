import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, join, relative, resolve } from 'node:path';
import { SeverityLevel, VulnerabilityFinding } from '../types.js';
import { EmbeddedAdvisoryEntry } from './embedded-bundle.js';
import { normalizeSeverity } from './rules.js';

export interface ManifestDependency {
  ecosystem: string;
  name: string;
  version: string;
  line: number;
  snippet: string;
}

const MANIFEST_NAMES = new Set([
  'package.json',
  'package-lock.json',
  'requirements.txt',
  'go.mod',
  'cargo.toml',
  'pom.xml'
]);

const IGNORED_DIRS = new Set([
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

export function compareVersions(a: string, b: string): number {
  const pa = cleanVersionParts(a);
  const pb = cleanVersionParts(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const va = pa[i] ?? 0;
    const vb = pb[i] ?? 0;
    if (va > vb) return 1;
    if (va < vb) return -1;
  }
  return 0;
}

function cleanVersionParts(raw: string): number[] {
  const cleaned = String(raw || '')
    .trim()
    .replace(/^[vV^~=<>\s]+/, '')
    .split(/[-+\s]/)[0];
  if (!cleaned) return [];
  return cleaned
    .split('.')
    .map((part) => {
      const m = /^(\d+)/.exec(part);
      return m ? parseInt(m[1], 10) : 0;
    });
}

export function isVersionAffected(version: string, adv: { ge?: string; lt?: string }): boolean {
  if (!version || /^\*|latest|workspace:/i.test(version)) return false;
  if (!/^\d/.test(version.replace(/^[vV^~=<>]+/, ''))) return false;
  if (adv.ge && compareVersions(version, adv.ge) < 0) return false;
  if (adv.lt && compareVersions(version, adv.lt) >= 0) return false;
  return Boolean(adv.lt || adv.ge);
}

function findLineForToken(lines: string[], token: string, startHint = 0): number {
  const lower = token.toLowerCase();
  for (let i = Math.max(0, startHint); i < lines.length; i++) {
    if (lines[i].toLowerCase().includes(lower)) return i + 1;
  }
  return 1;
}

export function parseManifestDependencies(filePath: string, content: string): ManifestDependency[] {
  const base = basename(filePath).toLowerCase();
  const lines = content.split(/\r?\n/);
  const deps: ManifestDependency[] = [];
  const seen = new Set<string>();

  const pushDep = (ecosystem: string, name: string, rawVersion: string, line: number, snippet: string) => {
    const cleanVer = String(rawVersion || '').trim().replace(/^[~^>=<\s]+/, '').split(/\s+/)[0];
    if (!name || !cleanVer || /^\*|latest|workspace:|file:|git\+|https?:/i.test(cleanVer)) return;
    if (!/\d/.test(cleanVer)) return;
    const key = `${ecosystem}:${name.toLowerCase()}@${cleanVer}:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    deps.push({ ecosystem, name, version: cleanVer, line, snippet: snippet.trim() });
  };

  if (base === 'package.json') {
    try {
      const pkg = JSON.parse(content);
      const merged = Object.assign({}, pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies);
      for (const [name, ver] of Object.entries(merged)) {
        if (typeof ver !== 'string') continue;
        const ln = findLineForToken(lines, `"${name}"`);
        pushDep('npm', name, ver, ln, lines[ln - 1] || `"${name}": "${ver}"`);
      }
    } catch {}
    return deps;
  }

  if (base === 'package-lock.json') {
    try {
      const lock = JSON.parse(content);
      if (lock.packages && typeof lock.packages === 'object') {
        for (const [pkgPath, info] of Object.entries<any>(lock.packages)) {
          const pkgName = pkgPath.split('node_modules/').pop();
          if (pkgName && info && typeof info.version === 'string') {
            const ln = findLineForToken(lines, `"${pkgPath}"`);
            pushDep('npm', pkgName, info.version, ln, lines[ln - 1] || `"${pkgPath}": "${info.version}"`);
          }
        }
      } else if (lock.dependencies && typeof lock.dependencies === 'object') {
        for (const [pkgName, info] of Object.entries<any>(lock.dependencies)) {
          if (info && typeof info.version === 'string') {
            const ln = findLineForToken(lines, `"${pkgName}"`);
            pushDep('npm', pkgName, info.version, ln, lines[ln - 1] || `"${pkgName}": "${info.version}"`);
          }
        }
      }
    } catch {}
    return deps;
  }

  if (base === 'requirements.txt') {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\s*#/.test(line)) continue;
      const m = /^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(?:==|>=|~=)\s*([0-9][0-9A-Za-z.\-]*)/.exec(line);
      if (m) {
        pushDep('pip', m[1], m[2], i + 1, line);
      }
    }
    return deps;
  }

  if (base === 'go.mod') {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\s*\/\//.test(line)) continue;
      const m = /^\s*(?:require\s+)?([A-Za-z0-9._~/-]+\.[A-Za-z0-9._~/-]+)\s+(v[0-9][0-9A-Za-z.\-+]*)/.exec(line);
      if (m) {
        pushDep('go', m[1], m[2], i + 1, line);
      }
    }
    return deps;
  }

  if (base === 'cargo.toml') {
    let section = '';
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#')) continue;
      const secMatch = /^\[([^\]]+)\]/.exec(line);
      if (secMatch) {
        section = secMatch[1].trim().toLowerCase();
        continue;
      }
      if (!section.endsWith('dependencies')) continue;
      const simple = /^([A-Za-z0-9_-]+)\s*=\s*["']([^"']+)["']/.exec(line);
      if (simple) {
        pushDep('cargo', simple[1], simple[2], i + 1, line);
        continue;
      }
      const inlineTable = /^([A-Za-z0-9_-]+)\s*=\s*\{[^}]*\bversion\s*=\s*["']([^"']+)["']/.exec(line);
      if (inlineTable) {
        pushDep('cargo', inlineTable[1], inlineTable[2], i + 1, line);
      }
    }
    return deps;
  }

  if (base === 'pom.xml') {
    const depBlockRe = /<dependency\b[^>]*>([\s\S]*?)<\/dependency>/gi;
    let m: RegExpExecArray | null;
    while ((m = depBlockRe.exec(content)) !== null) {
      const block = m[1];
      const groupId = /<groupId>\s*([^<\s]+)\s*<\/groupId>/i.exec(block)?.[1];
      const artifactId = /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/i.exec(block)?.[1];
      const version = /<version>\s*([^<\s]+)\s*<\/version>/i.exec(block)?.[1];
      if (groupId && artifactId && version && !version.startsWith('${')) {
        const line = content.slice(0, m.index).split(/\r?\n/).length;
        pushDep('maven', `${groupId}:${artifactId}`, version, line, `<dependency>${groupId}:${artifactId}:${version}</dependency>`);
        pushDep('maven', artifactId, version, line, `<dependency>${groupId}:${artifactId}:${version}</dependency>`);
      }
    }
  }

  return deps;
}

export function isManifestPath(relPath: string): boolean {
  const normalized = relPath.replace(/\\/g, '/');
  const base = basename(normalized).toLowerCase();
  if (!MANIFEST_NAMES.has(base)) return false;
  const segments = normalized.split('/');
  for (let i = 0; i < segments.length - 1; i++) {
    if (IGNORED_DIRS.has(segments[i])) return false;
  }
  return true;
}

function collectManifestFiles(dir: string): string[] {
  const results: string[] = [];
  if (!existsSync(dir)) return results;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectManifestFiles(full));
    } else if (entry.isFile() && MANIFEST_NAMES.has(entry.name.toLowerCase())) {
      results.push(full);
    }
  }
  return results;
}

export function scanWorkspaceDependencies(options: {
  workspaceDir: string;
  advisories: Record<string, readonly EmbeddedAdvisoryEntry[]>;
  onlyDiff?: boolean;
  modifiedFiles?: Map<string, Set<number>>;
  minRank: number;
  severityRanks: Record<SeverityLevel, number>;
}): VulnerabilityFinding[] {
  const { workspaceDir, advisories, onlyDiff, modifiedFiles, minRank, severityRanks } = options;
  if (!advisories || typeof advisories !== 'object') return [];

  const targets: Array<{ fullPath: string; relPath: string; changedLines?: Set<number> }> = [];
  if (onlyDiff) {
    if (modifiedFiles) {
      for (const [rawPath, changedLines] of modifiedFiles.entries()) {
        if (!changedLines || changedLines.size === 0) continue;
        const relPath = rawPath.replace(/\\/g, '/');
        if (!isManifestPath(relPath)) continue;
        targets.push({ fullPath: resolve(workspaceDir, relPath), relPath, changedLines });
      }
    }
  } else {
    for (const fullPath of collectManifestFiles(workspaceDir)) {
      const relPath = relative(workspaceDir, fullPath).replace(/\\/g, '/');
      targets.push({ fullPath, relPath });
    }
  }

  const findings: VulnerabilityFinding[] = [];
  const emitted = new Set<string>();

  for (const target of targets) {
    let raw: Buffer;
    try {
      const st = statSync(target.fullPath);
      if (!st.isFile() || st.size > 4 * 1024 * 1024) continue;
      raw = readFileSync(target.fullPath);
    } catch {
      continue;
    }
    const content = raw.toString('utf8');
    const deps = parseManifestDependencies(target.relPath, content);

    for (const dep of deps) {
      if (target.changedLines && !target.changedLines.has(dep.line)) continue;
      const ecoList = advisories[dep.ecosystem] || [];
      if (!Array.isArray(ecoList) || ecoList.length === 0) continue;
      const depLower = dep.name.toLowerCase();

      for (const adv of ecoList) {
        if (!adv || !adv.name || adv.name.toLowerCase() !== depLower) continue;
        if (!isVersionAffected(dep.version, adv)) continue;
        const severity = normalizeSeverity(adv.sev);
        if (severityRanks[severity] < minRank) continue;

        const dedupKey = `${target.relPath}:${dep.line}:${adv.id}`;
        if (emitted.has(dedupKey)) continue;
        emitted.add(dedupKey);

        const tags: string[] = [];
        if (adv.kev) tags.push('CISA KEV');
        if (typeof adv.epss === 'number' && adv.epss > 0) tags.push(`EPSS ${(adv.epss * 100).toFixed(1)}%`);
        const tagSuffix = tags.length > 0 ? ` [${tags.join(', ')}]` : '';

        findings.push({
          id: `sca-${adv.id}-${target.relPath}-${dep.line}`,
          ruleId: adv.id,
          title: 'Vulnerable Dependency',
          description: `${dep.name}@${dep.version} is affected by ${adv.id}${tagSuffix}: ${adv.note || 'known security advisory'}`,
          severity,
          file: target.relPath,
          line: dep.line,
          snippet: dep.snippet,
          cwe: adv.cwe || 'CWE-1395',
          remediation: adv.lt
            ? `Upgrade ${dep.name} to version ${adv.lt} or later.`
            : `Upgrade ${dep.name} to a patched release.`,
          source: 'sca',
          packageName: dep.name,
          fixedVersion: adv.lt,
          kev: Boolean(adv.kev),
          epss: typeof adv.epss === 'number' ? adv.epss : undefined
        });
      }
    }
  }

  return findings;
}

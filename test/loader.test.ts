import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RuleLoader } from '../src/engine/loader.js';
import { DEFAULT_AGENT_RULES, SECURITY_RULES } from '../src/engine/rules.js';
import { SecurityScanner } from '../src/engine/scanner.js';

describe('Action RuleLoader', () => {
  it('loads all 729 canonical embedded rules and OSV advisories by default', async () => {
    const rules = await RuleLoader.loadRules('embedded');
    assert.ok(Array.isArray(rules));
    assert.ok(rules.length >= 729);
    const advisories = await RuleLoader.loadAdvisories('embedded');
    assert.ok(Array.isArray(advisories.npm) && advisories.npm.length > 0);
    assert.ok(Array.isArray(advisories.maven) && advisories.maven.length > 0);
    assert.ok(Array.isArray(advisories.cargo) && advisories.cargo.length > 0);
  });

  it('falls back to embedded rules when custom file is missing', async () => {
    const rules = await RuleLoader.loadRules('non_existent_rules.json');
    assert.ok(Array.isArray(rules));
    assert.ok(rules.length >= 20);
  });

  it('parses not-match rules and suppresses matching lines in scanner', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'wide-action-loader-'));
    try {
      const customRulesPath = join(tmpDir, 'custom-rules.json');
      writeFileSync(
        customRulesPath,
        JSON.stringify([
          {
            id: 'wide/test-not-match',
            cwe: 'CWE-999',
            category: 'Test',
            severity: 'HIGH',
            languages: ['ts'],
            pattern: 'dangerousOp\\(',
            'not-match': 'trustedArg',
            message: 'Dangerous operation'
          }
        ]),
        'utf8'
      );
      writeFileSync(
        join(tmpDir, 'target.ts'),
        'dangerousOp(userInput);\ndangerousOp(trustedArg);\n',
        'utf8'
      );

      const loaded = await RuleLoader.loadRules(customRulesPath, tmpDir);
      assert.equal(loaded.length, 1);
      assert.ok(loaded[0].notMatch instanceof RegExp);

      const scanner = new SecurityScanner(tmpDir);
      const res = await scanner.scan({ onlyDiff: false, rules: loaded });
      const hits = res.findings.filter(f => f.ruleId === 'wide/test-not-match');
      assert.equal(hits.length, 1);
      assert.equal(hits[0].line, 1);

      const advisories = await RuleLoader.loadAdvisories('embedded', tmpDir);
      assert.ok(advisories && typeof advisories === 'object');
      assert.ok(Array.isArray(advisories.npm));

      assert.equal(RuleLoader.sanitizeOutput('Hello 😀⭐ℹ️1️⃣👨‍💻🇷🇺 World', []), 'Hello  World');
      assert.equal(RuleLoader.sanitizeOutput('Clean 1 + 2 -> 3', loaded), 'Clean 1 + 2 -> 3');
      assert.equal(RuleLoader.sanitizeOutput('Leaky 🚨', loaded), 'Leaky ');
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('includes all 13 canonical agent rules and fixed cwe079 pattern', () => {
    const ids = new Set(DEFAULT_AGENT_RULES.map(r => r.id));
    assert.equal(DEFAULT_AGENT_RULES.length, 13);
    assert.ok(ids.has('wide/ai-no-system-prompt-leak'));
    assert.ok(ids.has('wide/ai-direct-file-edits'));
    assert.ok(ids.has('wide/ai-native-tool-priority'));
    assert.ok(ids.has('wide/ai-language-matching'));
    const cwe079 = DEFAULT_AGENT_RULES.find(r => r.id === 'wide/cwe079-ai-prompt-injection');
    assert.ok(cwe079);
    assert.equal(cwe079.pattern.test('const prompt = `User said: ${req.body.query}`;'), true);
  });

  it('verifies SHA256SUMS when loading latest rules and falls back on checksum mismatch', async () => {
    const origFetch = globalThis.fetch;
    try {
      const payload = JSON.stringify({
        rules: [
          {
            id: 'wide/remote-verified',
            cwe: 'CWE-79',
            category: 'XSS',
            severity: 'HIGH',
            languages: ['js'],
            pattern: 'innerHTML\\s*=',
            message: 'Unsafe innerHTML'
          }
        ]
      });
      const validSha = createHash('sha256').update(payload).digest('hex');

      globalThis.fetch = (async (input: string | URL | Request) => {
        const url = String(input);
        if (url.endsWith('SHA256SUMS')) {
          return new Response(`${validSha}  rules.json\n`, { status: 200 });
        }
        return new Response(payload, { status: 200 });
      }) as typeof fetch;

      const verified = await RuleLoader.loadRules('latest');
      assert.equal(verified.length, 1);
      assert.equal(verified[0].id, 'wide/remote-verified');

      globalThis.fetch = (async (input: string | URL | Request) => {
        const url = String(input);
        if (url.endsWith('SHA256SUMS')) {
          return new Response(`${'0'.repeat(64)}  rules.json\n`, { status: 200 });
        }
        return new Response(payload, { status: 200 });
      }) as typeof fetch;

      const fallback = await RuleLoader.loadRules('latest');
      assert.equal(fallback.length, SECURITY_RULES.length);
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});

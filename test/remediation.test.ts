import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { RemediationEngine } from '../src/remediation/engine.js';
import { formatInlineComment } from '../src/reporter/markdown.js';
import { VulnerabilityFinding } from '../src/types.js';

describe('AI Remediation Engine', () => {
  it('extracts code cleanly from suggestion blocks', () => {
    const engine = new RemediationEngine({ provider: 'gemini', apiKey: 'test' });

    const rawWithSuggestion = [
      'Here is the fix:',
      '```suggestion',
      'const query = pool.query("SELECT * FROM users WHERE id = $1", [req.query.id]);',
      '```'
    ].join('\n');

    const patch = engine.extractSuggestionCode(rawWithSuggestion);
    assert.equal(
      patch,
      'const query = pool.query("SELECT * FROM users WHERE id = $1", [req.query.id]);'
    );
  });

  it('extracts code from generic language fences if model omitted suggestion keyword', () => {
    const engine = new RemediationEngine({ provider: 'claude', apiKey: 'test' });

    const rawWithCodeFence = [
      '```typescript',
      'execFile("ping", ["-c", "1", host]);',
      '```'
    ].join('\n');

    const patch = engine.extractSuggestionCode(rawWithCodeFence);
    assert.equal(patch, 'execFile("ping", ["-c", "1", host]);');
  });

  it('returns null when raw response is empty', () => {
    const engine = new RemediationEngine({ provider: 'openai', apiKey: 'test' });
    assert.equal(engine.extractSuggestionCode(''), null);
  });

  it('returns null and skips execution gracefully when API key is missing', async () => {
    const engine = new RemediationEngine({ provider: 'gemini', apiKey: '' });
    const finding: VulnerabilityFinding = {
      id: 'f1',
      ruleId: 'WIDE-SEC-001',
      title: 'SQL Injection',
      description: 'SQLi',
      severity: 'CRITICAL',
      file: 'src/app.ts',
      line: 10,
      snippet: 'const q = "SELECT * FROM users WHERE id = " + id;',
      remediation: 'Parameterize'
    };

    const patch = await engine.generatePatch(finding);
    assert.equal(patch, null);
  });

  it('renders interactive suggestion block in inline markdown comment', () => {
    const finding: VulnerabilityFinding = {
      id: 'f1',
      ruleId: 'WIDE-SEC-001',
      title: 'SQL Injection',
      description: 'SQLi',
      severity: 'CRITICAL',
      file: 'src/app.ts',
      line: 10,
      snippet: 'const q = "SELECT * FROM users WHERE id = " + id;',
      suggestedPatch: 'const q = await db.query("SELECT * FROM users WHERE id = $1", [id]);',
      remediation: 'Parameterize'
    };

    const md = formatInlineComment(finding);
    assert.ok(md.includes('**AI Suggested Fix (Click "Commit suggestion" to apply):**'));
    assert.ok(md.includes('```suggestion'));
    assert.ok(md.includes('const q = await db.query("SELECT * FROM users WHERE id = $1", [id]);'));
  });

  it('sends Gemini key in header instead of URL, uses model override, and enforces patch quality scoring', async () => {
    const origFetch = globalThis.fetch;
    let seenUrl = '';
    let seenKeyHeader = '';
    let seenModelBody = '';
    try {
      globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        seenUrl = String(input);
        const headers = init?.headers as Record<string, string> | undefined;
        seenKeyHeader = headers?.['x-goog-api-key'] || '';
        seenModelBody = String(init?.body || '');
        return new Response(
          JSON.stringify({
            candidates: [
              {
                content: {
                  parts: [{ text: '```suggestion\nconst q = await db.query("SELECT * FROM users WHERE id = $1", [id]);\n```' }]
                }
              }
            ]
          }),
          { status: 200 }
        );
      }) as typeof fetch;

      const engine = new RemediationEngine({
        provider: 'gemini',
        model: 'gemini-2.5-pro',
        apiKey: 'secret-test-key'
      });
      const finding: VulnerabilityFinding = {
        id: 'f2',
        ruleId: 'wide/sql-concatenation',
        title: 'INJECTION',
        description: 'SQLi',
        severity: 'CRITICAL',
        file: 'src/app.ts',
        line: 10,
        snippet: 'const q = "SELECT * FROM users WHERE id = " + id;',
        remediation: 'Use bound parameters'
      };

      const patch = await engine.generatePatch(finding);
      assert.equal(patch, 'const q = await db.query("SELECT * FROM users WHERE id = $1", [id]);');
      assert.equal(seenUrl.includes('key='), false);
      assert.equal(seenUrl.includes('gemini-2.5-pro'), true);
      assert.equal(seenKeyHeader, 'secret-test-key');
      assert.equal(engine.selectBestCandidatePatch(['const q = "SELECT * FROM users WHERE id = " + id;'], finding.snippet || ''), null);
      assert.ok(seenModelBody.includes('Ecosystem Agent Guardrails'));
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it('parses structured AI triage verdicts and avoids patching mitigated or false-positive findings', () => {
    const engine = new RemediationEngine({ provider: 'gemini', apiKey: 'test' });
    const exploitable = engine.parseTriageResponse(
      [
        'VERDICT: EXPLOITABLE',
        'REASON: User query input reaches pool.query without parameterization.',
        '```suggestion',
        'const q = await pool.query("SELECT * FROM users WHERE id = $1", [id]);',
        '```'
      ].join('\n'),
      'const q = pool.query("SELECT * FROM users WHERE id = " + id);'
    );
    assert.equal(exploitable.verdict, 'EXPLOITABLE');
    assert.ok(exploitable.reason?.includes('pool.query'));
    assert.equal(exploitable.patch, 'const q = await pool.query("SELECT * FROM users WHERE id = $1", [id]);');

    const falsePos = engine.parseTriageResponse(
      'VERDICT: FALSE_POSITIVE\nREASON: Input was coerced via Number() upstream.',
      'pool.query(sql);'
    );
    assert.equal(falsePos.verdict, 'FALSE_POSITIVE');
    assert.equal(falsePos.patch, null);
  });

  it('aligns patch indentation to match original snippet indentation', () => {
    const engine = new RemediationEngine({ provider: 'gemini', apiKey: 'test' });
    const original = '    const q = "SELECT * FROM users WHERE id = " + id;';
    const unindentedPatch = 'const q = pool.query("SELECT * FROM users WHERE id = $1", [id]);';
    const selected = engine.selectBestCandidatePatch([unindentedPatch], original);
    assert.equal(selected, '    const q = pool.query("SELECT * FROM users WHERE id = $1", [id]);');
  });
});

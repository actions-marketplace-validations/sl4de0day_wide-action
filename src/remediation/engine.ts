import * as core from '@actions/core';
import { VulnerabilityFinding } from '../types.js';
import { WeightedScorer, Criterion, Commitment } from './decision.js';
import { RuleLoader } from '../engine/loader.js';
import { SecurityRule } from '../engine/rules.js';
import { fetchWithTimeout, withRetry } from '../retry.js';

export interface RemediationOptions {
  provider: string;
  apiKey: string;
  model?: string;
  timeoutMs?: number;
}

export type TriageVerdict = 'EXPLOITABLE' | 'MITIGATED' | 'FALSE_POSITIVE';

export interface TriageAndRemediationResult {
  verdict?: TriageVerdict;
  reason?: string;
  patch: string | null;
}

const MIN_PATCH_QUALITY_SCORE = 0.5;

export class RemediationEngine {
  private provider: string;
  private apiKey: string;
  private model: string;
  private timeoutMs: number;

  constructor(options: RemediationOptions) {
    this.provider = options.provider.trim().toLowerCase();
    this.apiKey = options.apiKey || this.resolveApiKey(this.provider);
    this.model = (options.model || '').trim();
    this.timeoutMs = options.timeoutMs || 15000;
  }

  public async analyzeAndRemediate(
    finding: VulnerabilityFinding,
    surroundingContext = '',
    agentRules?: readonly SecurityRule[]
  ): Promise<TriageAndRemediationResult> {
    if (!this.apiKey) {
      core.info(`AI Remediation skipped: No API key provided for provider '${this.provider}'.`);
      return { patch: null };
    }

    const prompt = this.buildPrompt(finding, surroundingContext, agentRules);

    try {
      let rawResponse: string | null = null;

      if (this.provider === 'gemini') {
        rawResponse = await this.callGemini(prompt);
      } else if (this.provider === 'claude') {
        rawResponse = await this.callClaude(prompt);
      } else if (this.provider === 'deepseek') {
        rawResponse = await this.callOpenAiCompatible(
          'https://api.deepseek.com',
          this.model || 'deepseek-chat',
          prompt
        );
      } else if (this.provider === 'openai') {
        rawResponse = await this.callOpenAiCompatible(
          'https://api.openai.com/v1',
          this.model || 'gpt-4o-mini',
          prompt
        );
      } else {
        core.warning(`Unsupported AI provider for remediation: ${this.provider}`);
        return { patch: null };
      }

      if (!rawResponse) return { patch: null };
      const parsed = this.parseTriageResponse(rawResponse, finding.snippet || '', agentRules);
      return parsed;
    } catch (error) {
      core.warning(`AI Remediation error with ${this.provider}: ${String(error)}`);
      return { patch: null };
    }
  }

  public async generatePatch(
    finding: VulnerabilityFinding,
    surroundingContext = '',
    agentRules?: readonly SecurityRule[]
  ): Promise<string | null> {
    const res = await this.analyzeAndRemediate(finding, surroundingContext, agentRules);
    return res.patch;
  }

  public parseTriageResponse(
    raw: string,
    originalSnippet: string,
    agentRules?: readonly SecurityRule[]
  ): TriageAndRemediationResult {
    const verdictMatch = /^VERDICT:\s*(EXPLOITABLE|MITIGATED|FALSE_POSITIVE)\b/im.exec(raw);
    const reasonMatch = /^REASON:\s*(.+)$/im.exec(raw);
    const verdict = verdictMatch ? (verdictMatch[1].toUpperCase() as TriageVerdict) : undefined;
    const reason = reasonMatch ? reasonMatch[1].trim() : undefined;

    if (verdict === 'FALSE_POSITIVE' || verdict === 'MITIGATED') {
      const explicitSuggestion = raw.match(/```suggestion\r?\n([\s\S]*?)\r?\n```/);
      if (!explicitSuggestion) {
        return { verdict, reason, patch: null };
      }
    }

    const extracted = this.extractSuggestionCode(raw, agentRules);
    if (!extracted) return { verdict, reason, patch: null };
    const patch = this.selectBestCandidatePatch([extracted], originalSnippet);
    return { verdict, reason, patch };
  }

  private resolveApiKey(provider: string): string {
    switch (provider) {
      case 'gemini':
        return process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || '';
      case 'claude':
        return process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY || '';
      case 'deepseek':
        return process.env.DEEPSEEK_API_KEY || '';
      case 'openai':
        return process.env.OPENAI_API_KEY || '';
      default:
        return '';
    }
  }

  public buildPrompt(
    finding: VulnerabilityFinding,
    context: string,
    agentRules?: readonly SecurityRule[]
  ): string {
    const guardrails = RuleLoader.buildAgentInstructions(agentRules ? [...agentRules] : undefined);
    const parts = [
      'You are an automated secure code remediation assistant.',
      `Vulnerability Detected: ${finding.title} (${finding.cwe || 'CWE'})`,
      `Severity: ${finding.severity}`,
      `File: ${finding.file} at line ${finding.line}`,
      `Description: ${finding.description}`,
      `Standard Remediation: ${finding.remediation}`,
      '',
      'Vulnerable Snippet:',
      finding.snippet || '',
      '',
      context ? `Surrounding Context:\n${context}\n` : '',
      'First verify reachability and existing sanitization in the surrounding context.',
      'Start your response with:',
      'VERDICT: EXPLOITABLE | MITIGATED | FALSE_POSITIVE',
      'REASON: <one concise technical sentence explaining the flow or mitigation>',
      'If VERDICT is EXPLOITABLE, provide a direct replacement for ONLY the vulnerable line or minimal code block inside:',
      '```suggestion',
      '<replacement code here>',
      '```'
    ];
    if (guardrails) {
      parts.push('', 'Ecosystem Agent Guardrails (wide-rules):', guardrails);
    }
    return parts.join('\n');
  }

  private async postJsonWithRetry(
    url: string,
    headers: Record<string, string>,
    payload: unknown,
    label: string
  ): Promise<any> {
    return withRetry(
      async () => {
        const response = await fetchWithTimeout(
          url,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...headers },
            body: JSON.stringify(payload)
          },
          this.timeoutMs
        );
        if (!response.ok) {
          const text = await response.text();
          const err: any = new Error(`${label} HTTP ${response.status}: ${text}`);
          err.status = response.status;
          err.retryAfter = response.headers.get('retry-after');
          throw err;
        }
        return response.json();
      },
      {
        maxAttempts: 3,
        baseDelayMs: 400,
        onRetry: (_err, attempt, delayMs) => core.debug(`Retrying ${label} request (attempt ${attempt}, delay ${delayMs}ms)`)
      }
    );
  }

  private async callGemini(prompt: string): Promise<string | null> {
    const modelName = encodeURIComponent(this.model || 'gemini-2.5-flash');
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent`;
    const payload = {
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.2, maxOutputTokens: 1024 }
    };
    const data = await this.postJsonWithRetry(
      url,
      { 'x-goog-api-key': this.apiKey },
      payload,
      'Gemini'
    );
    return data?.candidates?.[0]?.content?.parts?.[0]?.text || null;
  }

  private async callClaude(prompt: string): Promise<string | null> {
    const url = 'https://api.anthropic.com/v1/messages';
    const payload = {
      model: this.model || 'claude-sonnet-4-20250514',
      max_tokens: 1024,
      temperature: 0.2,
      messages: [{ role: 'user', content: prompt }]
    };
    const data = await this.postJsonWithRetry(
      url,
      { 'x-api-key': this.apiKey, 'anthropic-version': '2023-06-01' },
      payload,
      'Claude'
    );
    return data?.content?.[0]?.text || null;
  }

  private async callOpenAiCompatible(
    baseUrl: string,
    model: string,
    prompt: string
  ): Promise<string | null> {
    const url = `${baseUrl.replace(/\/+$/, '')}/chat/completions`;
    const payload = {
      model,
      temperature: 0.2,
      max_tokens: 1024,
      messages: [{ role: 'user', content: prompt }]
    };
    const data = await this.postJsonWithRetry(
      url,
      { Authorization: `Bearer ${this.apiKey}` },
      payload,
      model
    );
    return data?.choices?.[0]?.message?.content || null;
  }

  public extractSuggestionCode(raw: string, agentRules?: readonly SecurityRule[]): string | null {
    if (!raw) return null;
    const rulesArg = agentRules ? [...agentRules] : undefined;

    const match = raw.match(/```suggestion\r?\n([\s\S]*?)\r?\n```/);
    if (match && match[1] !== undefined) {
      return RuleLoader.sanitizeOutput(match[1].trimEnd(), rulesArg);
    }

    const codeBlockMatch = raw.match(/```(?:[a-zA-Z0-9_\-]+)?\r?\n([\s\S]*?)\r?\n```/);
    if (codeBlockMatch && codeBlockMatch[1] !== undefined) {
      return RuleLoader.sanitizeOutput(codeBlockMatch[1].trimEnd(), rulesArg);
    }

    const trimmed = raw.trim();
    if (trimmed && !trimmed.includes('```')) {
      return RuleLoader.sanitizeOutput(trimmed, rulesArg);
    }

    return null;
  }

  public scoreCandidatePatch(patch: string, originalSnippet: string): number {
    const cleanPatch = patch.trim();
    const cleanOrig = originalSnippet.trim();
    const scorer = new WeightedScorer(
      new Criterion(0.5, () => (cleanPatch.length > 0 && cleanPatch !== cleanOrig ? 1.0 : 0.0)),
      new Criterion(0.3, () => (cleanPatch.length < 2000 ? 1.0 : Math.max(0.0, 1.0 - (cleanPatch.length - 2000) / 2000))),
      new Criterion(0.2, () => (!cleanPatch.includes('TODO') && !cleanPatch.includes('FIXME') ? 1.0 : 0.0))
    );
    return scorer.score(0);
  }

  public selectBestCandidatePatch(candidates: readonly string[], originalSnippet: string): string | null {
    const cleanOrig = originalSnippet.trim();
    const commitment = new Commitment(60.0, 0.0);
    let chosen: string | null = null;

    for (let i = 0; i < candidates.length; i++) {
      const candidate = (candidates[i] || '').trimEnd();
      if (!candidate.trim() || candidate.trim() === cleanOrig) continue;
      const score = this.scoreCandidatePatch(candidate, originalSnippet);
      if (score >= MIN_PATCH_QUALITY_SCORE && commitment.shouldReplace(score, 0.05, i + 1)) {
        commitment.adopt(score, i + 1);
        chosen = candidate;
      }
    }
    return chosen;
  }
}

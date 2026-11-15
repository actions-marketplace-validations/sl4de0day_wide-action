export interface RetryOptions {
  maxAttempts?: number;
  baseDelayMs?: number;
  shouldRetry?: (error: unknown) => boolean;
  onRetry?: (error: unknown, attempt: number, delayMs: number) => void;
}

const RETRYABLE_HTTP_STATUSES = new Set([408, 425, 429, 500, 502, 503, 504]);

export function isRetryableHttpStatus(status: number, headers?: Record<string, string | number | undefined>): boolean {
  if (RETRYABLE_HTTP_STATUSES.has(status)) return true;
  if (status === 403 && headers) {
    const remaining = String(headers['x-ratelimit-remaining'] ?? '');
    const retryAfter = headers['retry-after'];
    return remaining === '0' || retryAfter !== undefined;
  }
  return false;
}

export function extractRetryAfterMs(error: unknown): number | null {
  const err = error as any;
  const rawHeader = err?.response?.headers?.['retry-after'] ?? err?.headers?.['retry-after'] ?? err?.retryAfter;
  if (rawHeader === undefined || rawHeader === null) return null;
  const seconds = Number(rawHeader);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(seconds * 1000, 30000);
  }
  return null;
}

export function defaultShouldRetry(error: unknown): boolean {
  const err = error as any;
  const status = typeof err?.status === 'number' ? err.status : typeof err?.statusCode === 'number' ? err.statusCode : undefined;
  if (status !== undefined) {
    return isRetryableHttpStatus(status, err?.response?.headers ?? err?.headers);
  }
  const msg = String(err?.message ?? err ?? '').toLowerCase();
  const code = String(err?.code ?? '').toUpperCase();
  if (['ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN', 'ENOTFOUND', 'UND_ERR_CONNECT_TIMEOUT'].includes(code)) {
    return true;
  }
  return err?.name === 'AbortError' || msg.includes('rate limit') || msg.includes('fetch failed') || msg.includes('timed out');
}

export async function withRetry<T>(fn: () => Promise<T>, options: RetryOptions = {}): Promise<T> {
  const maxAttempts = Math.max(1, options.maxAttempts ?? 3);
  const baseDelayMs = Math.max(10, options.baseDelayMs ?? 300);
  const shouldRetry = options.shouldRetry ?? defaultShouldRetry;

  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt >= maxAttempts || !shouldRetry(error)) {
        throw error;
      }
      const headerDelay = extractRetryAfterMs(error);
      const jitter = Math.floor(Math.random() * 100);
      const delayMs = headerDelay ?? (baseDelayMs * Math.pow(2, attempt - 1) + jitter);
      options.onRetry?.(error, attempt, delayMs);
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }
  throw lastError;
}

export async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs = 15000
): Promise<Response> {
  const controller = new AbortController();
  const externalSignal = init.signal;
  const abortExternal = () => controller.abort();
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort();
    else externalSignal.addEventListener('abort', abortExternal, { once: true });
  }
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await globalThis.fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
    if (externalSignal) {
      externalSignal.removeEventListener('abort', abortExternal);
    }
  }
}

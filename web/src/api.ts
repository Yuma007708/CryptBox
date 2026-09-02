import { apiUrl } from './config.js';

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

async function toError(response: Response): Promise<ApiError> {
  let message = `HTTP ${response.status}`;
  try {
    const body = (await response.json()) as { error?: string };
    if (body.error) message = body.error;
  } catch {
    /* JSON でないレスポンスはステータスだけ返す */
  }
  return new ApiError(message, response.status);
}

export async function postJson<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch(apiUrl(path), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal,
  });
  if (!response.ok) throw await toError(response);
  return (await response.json()) as T;
}

export async function deleteJson<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(apiUrl(path), {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw await toError(response);
  return (await response.json()) as T;
}

export async function putBytes(path: string, body: Uint8Array, signal?: AbortSignal): Promise<void> {
  const response = await fetch(apiUrl(path), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: body as BodyInit,
    signal,
  });
  if (!response.ok) throw await toError(response);
}

const RETRYABLE = new Set([408, 429, 500, 502, 503, 504]);

/** ネットワーク断や一時的なエラーを指数バックオフで再試行する */
export async function withRetry<T>(
  task: () => Promise<T>,
  options: { attempts?: number; signal?: AbortSignal; onRetry?: (attempt: number) => void } = {},
): Promise<T> {
  const attempts = options.attempts ?? 5;
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    if (options.signal?.aborted) throw new DOMException('中止されました', 'AbortError');
    try {
      return await task();
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') throw error;
      if (error instanceof ApiError && !RETRYABLE.has(error.status)) throw error;
      lastError = error;
      if (attempt === attempts) break;
      options.onRetry?.(attempt);
      const backoff = Math.min(16000, 500 * 2 ** (attempt - 1));
      const jitter = Math.random() * 250;
      await new Promise((resolve) => setTimeout(resolve, backoff + jitter));
    }
  }
  throw lastError;
}

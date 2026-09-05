import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { uploadBundle } from '../../web/src/upload.js';
import type { FileSource } from '../../web/src/filesource.js';

/**
 * アップロード中に `pagehide`（タブを閉じる・リロード等）が起きたら、
 * サーバー側のアップロードセッションを解放する DELETE を keepalive 付きで送る。
 * 完了・中断後はリスナーを外し、以後の pagehide では送らない。
 */

function makeFileSource(name: string, bytes: Uint8Array): FileSource {
  return {
    name,
    type: 'application/octet-stream',
    size: bytes.length,
    key: `test:${name}`,
    async read(start, end) {
      return bytes.subarray(start, end);
    },
    async close() {
      /* no-op */
    },
  };
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
}

describe('uploadBundle: pagehide でのセッション解放', () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let putGate: Deferred<void>;

  beforeEach(() => {
    putGate = deferred<void>();
    fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = (init?.method ?? 'GET').toUpperCase();

      if (method === 'POST' && url.endsWith('/api/uploads')) {
        return jsonResponse({ uploadToken: 'upload-token-1', files: [{ index: 0 }] });
      }
      if (method === 'PUT' && url.includes('/api/uploads/upload-token-1/files/0/parts/')) {
        await putGate.promise;
        return new Response(null, { status: 200 });
      }
      if (method === 'POST' && url.endsWith('/api/uploads/upload-token-1/complete')) {
        return jsonResponse({ token: 'share-token', expiresAt: Date.now() + 3600_000, maxDownloads: 1 });
      }
      if (method === 'DELETE' && url.endsWith('/api/uploads/upload-token-1')) {
        return new Response(null, { status: 200 });
      }
      throw new Error(`unexpected fetch: ${method} ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function runUpload() {
    const file = makeFileSource('a.txt', new TextEncoder().encode('hello world'));
    const controller = new AbortController();
    return uploadBundle({
      files: [file],
      password: '',
      expiresIn: 3600,
      maxDownloads: 1,
      signal: controller.signal,
      onStage: () => undefined,
      onProgress: () => undefined,
    });
  }

  it('アップロード中に pagehide が起きたら DELETE を keepalive 付きで送る', async () => {
    const uploadPromise = runUpload();

    // セッション作成（POST /api/uploads）が終わり、PUT が飛び始めるまで待つ
    await vi.waitFor(() => {
      expect(
        fetchMock.mock.calls.some(([input]) =>
          input.toString().includes('/api/uploads/upload-token-1/files/0/parts/'),
        ),
      ).toBe(true);
    });

    window.dispatchEvent(new Event('pagehide'));

    await vi.waitFor(() => {
      const deleteCall = fetchMock.mock.calls.find(
        ([input, init]) =>
          (init?.method ?? '').toUpperCase() === 'DELETE' &&
          input.toString().endsWith('/api/uploads/upload-token-1'),
      );
      expect(deleteCall).toBeTruthy();
      expect((deleteCall![1] as RequestInit).keepalive).toBe(true);
    });

    // アップロード自体は継続させて後始末する
    putGate.resolve();
    await uploadPromise;
  });

  it('完了後は pagehide で DELETE を送らない', async () => {
    putGate.resolve();
    await runUpload();

    fetchMock.mockClear();
    window.dispatchEvent(new Event('pagehide'));

    expect(
      fetchMock.mock.calls.some(([, init]) => (init?.method ?? '').toUpperCase() === 'DELETE'),
    ).toBe(false);
  });
});

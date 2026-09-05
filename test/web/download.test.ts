import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { decryptedStream, refreshGrant } from '../../web/src/download.js';
import { encryptChunk, importCek, randomBytes } from '../../web/src/crypto.js';
import { toBase64Url } from '../../shared/format.js';

describe('refreshGrant', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('X-Grant ヘッダーと authToken を送り、grant / expiresAt を受け取る', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ grant: 'new-grant', expiresAt: 123456 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    const authToken = new Uint8Array([1, 2, 3]);
    const result = await refreshGrant('tok', authToken, 'old-grant');

    expect(result).toEqual({ grant: 'new-grant', expiresAt: 123456 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toContain('/api/files/tok/refresh');
    expect((init.headers as Record<string, string>)['X-Grant']).toBe('old-grant');
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
    expect(JSON.parse(init.body as string)).toEqual({ authToken: toBase64Url(authToken) });
  });

  it('403 応答は ApiError として投げる（呼び出し側で claim にフォールバックしない判断に使う）', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'グラントが無効です' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    await expect(refreshGrant('tok', new Uint8Array([1]), 'old-grant')).rejects.toMatchObject({
      status: 403,
      message: 'グラントが無効です',
    });
  });
});

describe('decryptedStream: 429 の Retry-After 追従', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  async function readAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) chunks.push(value);
    }
    const total = chunks.reduce((sum, c) => sum + c.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      out.set(c, offset);
      offset += c.length;
    }
    return out;
  }

  it('Retry-After ヘッダーがあればその秒数（上限90秒）待ってから再試行する', async () => {
    vi.useFakeTimers();

    const cekRaw = randomBytes(32);
    const cek = await importCek(cekRaw);
    const noncePrefix = randomBytes(4);
    const plain = new TextEncoder().encode('hello');
    const cipher = await encryptChunk(cek, plain, noncePrefix, 0, 1);

    const file = {
      index: 0,
      plainSize: plain.length,
      cipherSize: cipher.length,
      chunkSize: 1024,
      totalChunks: 1,
      noncePrefix: toBase64Url(noncePrefix),
      wrappedCek: 'AAAA',
      wrapNonce: 'AAAA',
      metaCipher: 'AAAA',
      metaNonce: 'AAAA',
    };

    let call = 0;
    const fetchMock = vi.fn(async () => {
      call += 1;
      if (call === 1) {
        return new Response(JSON.stringify({ error: 'too many requests' }), {
          status: 429,
          headers: { 'Content-Type': 'application/json', 'Retry-After': '5' },
        });
      }
      return new Response(cipher as BodyInit, { status: 200 });
    });
    vi.stubGlobal('fetch', fetchMock);

    const stream = decryptedStream({
      token: 'tok',
      grant: 'g',
      file,
      cek,
      signal: new AbortController().signal,
      onProgress: () => undefined,
    });

    const resultPromise = readAll(stream);

    // 429 を観測するまで進める
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));

    // まだ 5 秒経っていなければ再試行しない
    await vi.advanceTimersByTimeAsync(4000);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    // 5 秒経過したら Retry-After に従って再試行する
    await vi.advanceTimersByTimeAsync(1500);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));

    const result = await resultPromise;
    expect(new TextDecoder().decode(result)).toBe('hello');
  });

  it('Retry-After が無ければ従来の指数バックオフで再試行する', async () => {
    vi.useFakeTimers();

    const cekRaw = randomBytes(32);
    const cek = await importCek(cekRaw);
    const noncePrefix = randomBytes(4);
    const plain = new TextEncoder().encode('hello');
    const cipher = await encryptChunk(cek, plain, noncePrefix, 0, 1);

    const file = {
      index: 0,
      plainSize: plain.length,
      cipherSize: cipher.length,
      chunkSize: 1024,
      totalChunks: 1,
      noncePrefix: toBase64Url(noncePrefix),
      wrappedCek: 'AAAA',
      wrapNonce: 'AAAA',
      metaCipher: 'AAAA',
      metaNonce: 'AAAA',
    };

    let call = 0;
    const fetchMock = vi.fn(async () => {
      call += 1;
      if (call === 1) {
        return new Response(JSON.stringify({ error: 'too many requests' }), {
          status: 429,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response(cipher as BodyInit, { status: 200 });
    });
    vi.stubGlobal('fetch', fetchMock);

    const stream = decryptedStream({
      token: 'tok',
      grant: 'g',
      file,
      cek,
      signal: new AbortController().signal,
      onProgress: () => undefined,
    });

    const resultPromise = readAll(stream);

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    // 指数バックオフ 1 回目は 1000ms（500 * 2^1）
    await vi.advanceTimersByTimeAsync(1200);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));

    const result = await resultPromise;
    expect(new TextDecoder().decode(result)).toBe('hello');
  });
});

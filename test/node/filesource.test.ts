import { describe, expect, it } from 'vitest';
import { fromNativePath } from '../../web/src/filesource.js';

/** テスト用の擬似ファイル */
const CONTENT = new Uint8Array(1000).map((_, i) => i % 251);

/** iOS の WebViewAssetHandler と同じく Range に正しく応える fetch */
const rangeFetch: typeof fetch = async (_url, init) => {
  const header = new Headers(init?.headers).get('Range');
  if (!header) return new Response(CONTENT, { status: 200 });
  const [, from, to] = /bytes=(\d+)-(\d+)/.exec(header)!;
  const slice = CONTENT.subarray(Number(from), Number(to) + 1);
  return new Response(slice, {
    status: 206,
    headers: { 'Content-Range': `bytes ${from}-${to}/${CONTENT.length}` },
  });
};

/** Android の WebViewLocalServer と同じく、Range を無視して常に全体を細切れで流す fetch */
const streamingFetch: typeof fetch = async () => {
  let offset = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (offset >= CONTENT.length) {
        controller.close();
        return;
      }
      const piece = CONTENT.subarray(offset, Math.min(CONTENT.length, offset + 64));
      offset += piece.length;
      controller.enqueue(piece);
    },
  });
  return new Response(body, { status: 200 });
};

const file = {
  name: 'a.bin',
  mimeType: 'application/octet-stream',
  size: CONTENT.length,
  path: '/tmp/a.bin',
};
const toUrl = (path: string) => `capacitor://localhost/_capacitor_file_${path}`;

describe('ネイティブファイルの読み出し (Range: iOS)', () => {
  it('任意の区間をランダムアクセスで取り出せる', async () => {
    const source = fromNativePath(file, { fetchImpl: rangeFetch, useRange: true, toUrl });
    expect(Array.from(await source.read(300, 320))).toEqual(Array.from(CONTENT.subarray(300, 320)));
    expect(Array.from(await source.read(0, 10))).toEqual(Array.from(CONTENT.subarray(0, 10)));
    expect(Array.from(await source.read(990, 1000))).toEqual(
      Array.from(CONTENT.subarray(990, 1000)),
    );
    expect((await source.read(5, 5)).length).toBe(0);
  });

  it('Range が無視されたら失敗として検出する（黙って壊れたデータを返さない）', async () => {
    const source = fromNativePath(file, { fetchImpl: streamingFetch, useRange: true, toUrl });
    await expect(source.read(100, 200)).rejects.toThrow();
  });
});

describe('ネイティブファイルの読み出し (逐次ストリーム: Android)', () => {
  it('順番に読めば全体を復元できる', async () => {
    const source = fromNativePath(file, { fetchImpl: streamingFetch, useRange: false, toUrl });
    const chunk = 300;
    const out = new Uint8Array(CONTENT.length);
    for (let start = 0; start < CONTENT.length; start += chunk) {
      const end = Math.min(CONTENT.length, start + chunk);
      out.set(await source.read(start, end), start);
    }
    expect(Array.from(out)).toEqual(Array.from(CONTENT));
    await source.close();
  });

  it('同時に呼んでも呼び出し順に直列化される（アップロードの並列ワーカー想定）', async () => {
    const source = fromNativePath(file, { fetchImpl: streamingFetch, useRange: false, toUrl });
    const parts = await Promise.all([
      source.read(0, 400),
      source.read(400, 800),
      source.read(800, 1000),
    ]);
    const joined = new Uint8Array(CONTENT.length);
    joined.set(parts[0], 0);
    joined.set(parts[1], 400);
    joined.set(parts[2], 800);
    expect(Array.from(joined)).toEqual(Array.from(CONTENT));
  });

  it('順番を飛ばした読み出しは拒否する', async () => {
    const source = fromNativePath(file, { fetchImpl: streamingFetch, useRange: false, toUrl });
    await expect(source.read(100, 200)).rejects.toThrow(/順番/);
  });
});

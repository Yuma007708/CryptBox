import { SELF, env } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { applySchema, resetTables } from './helpers.js';
import { GCM_TAG_BYTES, toBase64Url } from '../shared/format.js';
import { randomBytes } from '../web/src/crypto.js';

/**
 * パート PUT のサイズ検証（fail-closed）。
 * 宣言 (Content-Length) と実際に流れてきたバイト数の両方が期待値と一致しない限り、
 * R2 にはパートを書き込まない。
 */
const ORIGIN = 'https://cryptbox.test';
const CHUNK_SIZE = 5 * 1024 * 1024;
const PLAIN_SIZE = 100;
/** 1 チャンクに収まるファイルなので、期待される暗号文長は平文 + GCM タグ */
const EXPECTED = PLAIN_SIZE + GCM_TAG_BYTES;

const json = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

/**
 * 長さを事前に確定できないボディ。
 * Uint8Array をそのまま渡すとランタイムが Content-Length を補ってしまうため、
 * 「ヘッダー欠落」「宣言と実体の不一致」を作るには遅延ストリームが要る。
 */
function lazyStream(total: number): ReadableStream<Uint8Array> {
  let sent = 0;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (sent >= total) {
        controller.close();
        return;
      }
      const size = Math.min(64, total - sent);
      sent += size;
      controller.enqueue(new Uint8Array(size));
    },
  });
}

async function openSession(): Promise<string> {
  const created = await SELF.fetch(
    `${ORIGIN}/api/uploads`,
    json({ chunkSize: CHUNK_SIZE, files: [{ plainSize: PLAIN_SIZE }] }),
  );
  expect(created.status).toBe(200);
  return ((await created.json()) as { uploadToken: string }).uploadToken;
}

function putPart(uploadToken: string, init: RequestInit): Promise<Response> {
  return SELF.fetch(`${ORIGIN}/api/uploads/${uploadToken}/files/0/parts/0`, init);
}

async function errorOf(response: Response): Promise<string | undefined> {
  return ((await response.json()) as { error?: string }).error;
}

/** 宣言 (Content-Length) が期待値と違うときのメッセージ */
const DECLARED_MISMATCH = 'チャンクの長さが不正です';
/** 宣言は正しいが、実際に流れてきたバイト数が違うときのメッセージ */
const BODY_MISMATCH = '送信されたデータ量が宣言と一致しません';

beforeAll(applySchema);
beforeEach(resetTables);

describe('PUT パートのサイズ検証', () => {
  it('期待どおりの長さなら 200', async () => {
    const uploadToken = await openSession();
    const response = await putPart(uploadToken, { method: 'PUT', body: new Uint8Array(EXPECTED) });
    expect(response.status).toBe(200);
  });

  it('Content-Length が無ければ 400（R2 には書かない）', async () => {
    const uploadToken = await openSession();
    const response = await putPart(uploadToken, {
      method: 'PUT',
      body: lazyStream(EXPECTED),
      duplex: 'half',
    } as RequestInit);
    expect(response.status).toBe(400);
    const parts = await env.DB.prepare(`SELECT COUNT(*) AS n FROM upload_parts`).first<{ n: number }>();
    expect(parts?.n).toBe(0);
  });

  it('Content-Length が期待値と違えば 400（宣言不一致）', async () => {
    const uploadToken = await openSession();
    const response = await putPart(uploadToken, {
      method: 'PUT',
      body: new Uint8Array(EXPECTED + 1),
    });
    expect(response.status).toBe(400);
    expect(await errorOf(response)).toBe(DECLARED_MISMATCH);
  });

  it('実ボディが宣言より長ければ 400（実体不一致。理由まで区別する）', async () => {
    const uploadToken = await openSession();
    const response = await putPart(uploadToken, {
      method: 'PUT',
      headers: { 'Content-Length': String(EXPECTED) },
      body: lazyStream(EXPECTED + 500),
      duplex: 'half',
    } as RequestInit);
    expect(response.status).toBe(400);
    // 宣言 (Content-Length) は正しいので、宣言不一致とは別のメッセージになる。
    // ここが DECLARED_MISMATCH に戻ったら「実体の検証が効いていない」ことのサイン
    expect(await errorOf(response)).toBe(BODY_MISMATCH);
    const parts = await env.DB.prepare(`SELECT COUNT(*) AS n FROM upload_parts`).first<{ n: number }>();
    expect(parts?.n).toBe(0);
  });

  it('実ボディが宣言より短ければ 400（実体不一致）', async () => {
    const uploadToken = await openSession();
    const response = await putPart(uploadToken, {
      method: 'PUT',
      headers: { 'Content-Length': String(EXPECTED) },
      body: lazyStream(EXPECTED - 10),
      duplex: 'half',
    } as RequestInit);
    expect(response.status).toBe(400);
    expect(await errorOf(response)).toBe(BODY_MISMATCH);
    const parts = await env.DB.prepare(`SELECT COUNT(*) AS n FROM upload_parts`).first<{ n: number }>();
    expect(parts?.n).toBe(0);
  });
});

describe('complete 時の R2 実サイズ照合', () => {
  it('保存済みサイズが期待値と合わなければ中止し、確定したオブジェクトも消す', async () => {
    const uploadToken = await openSession();
    expect((await putPart(uploadToken, { method: 'PUT', body: new Uint8Array(EXPECTED) })).status).toBe(200);

    const key = await env.DB.prepare(`SELECT r2_key FROM upload_files`).first<{ r2_key: string }>();
    expect(key?.r2_key).toBeTruthy();

    // R2 に載っている実体（116 バイト）と、メタデータ上の期待値をずらす
    await env.DB.prepare(`UPDATE upload_files SET plain_size = ?`).bind(PLAIN_SIZE + 999).run();

    const completed = await SELF.fetch(
      `${ORIGIN}/api/uploads/${uploadToken}/complete`,
      json({
        expiresIn: 3600,
        maxDownloads: null,
        authHash: 'a'.repeat(64),
        kdfSalt: toBase64Url(randomBytes(32)),
        hasPassword: false,
        files: [
          {
            noncePrefix: toBase64Url(randomBytes(4)),
            wrappedCek: toBase64Url(randomBytes(48)),
            wrapNonce: toBase64Url(randomBytes(12)),
            metaCipher: toBase64Url(randomBytes(64)),
            metaNonce: toBase64Url(randomBytes(12)),
          },
        ],
      }),
    );
    expect(completed.status).toBe(400);

    // バンドルは作られず、確定してしまった R2 オブジェクトも残っていない
    const bundles = await env.DB.prepare(`SELECT COUNT(*) AS n FROM bundles`).first<{ n: number }>();
    expect(bundles?.n).toBe(0);
    expect(await env.BUCKET.head(key!.r2_key)).toBeNull();
  });
});

import { SELF, env } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { applySchema, resetTables } from './helpers.js';
import { purge } from '../src/index.js';
import {
  decryptChunk,
  decryptMeta,
  deriveAuthToken,
  deriveKeysFromMaterial,
  encryptChunk,
  encryptMeta,
  importCek,
  randomBytes,
  sha256Hex,
  unwrapCek,
  wrapCek,
} from '../web/src/crypto.js';
import {
  KDF_SALT_BYTES,
  KEY_BYTES,
  LINK_SECRET_BYTES,
  NONCE_BYTES,
  NONCE_PREFIX_BYTES,
  PW_SALT_BYTES,
  toBase64Url,
  fromBase64Url,
  totalChunks,
} from '../shared/format.js';

const ORIGIN = 'https://cryptbox.test';
const CHUNK_SIZE = 5 * 1024 * 1024;

/**
 * workerd は実行時の WebAssembly.compile を禁じているため、この結合テストでは
 * Argon2id の代わりに SHA-256 でパスワードを伸長する。
 * サーバーは伸長方式を一切知らない（受け取るのは検証値のハッシュだけ）ので、
 * ここで検証したいサーバー側の振る舞いは変わらない。
 * Argon2id 自体は test/node/argon2.test.ts で検証している。
 */
const ARGON2_PARAMS = { memoryKiB: 1024, iterations: 1, parallelism: 1, hashLength: 32 };

async function stretch(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const encoded = new TextEncoder().encode(password);
  const input = new Uint8Array(salt.length + encoded.length);
  input.set(salt, 0);
  input.set(encoded, salt.length);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input));
}

interface Uploaded {
  token: string;
  linkSecret: Uint8Array;
  authToken: Uint8Array;
}

async function upload(
  plain: Uint8Array,
  options: { expiresIn?: number; maxDownloads?: number | null; password?: string } = {},
): Promise<Uploaded> {
  const linkSecret = randomBytes(LINK_SECRET_BYTES);
  const kdfSalt = randomBytes(KDF_SALT_BYTES);
  const pwSalt = randomBytes(PW_SALT_BYTES);
  const noncePrefix = randomBytes(NONCE_PREFIX_BYTES);
  const wrapNonce = randomBytes(NONCE_BYTES);
  const metaNonce = randomBytes(NONCE_BYTES);
  const cekRaw = randomBytes(KEY_BYTES);
  const cek = await importCek(cekRaw);

  const keys = await deriveKeysFromMaterial({
    linkSecret,
    kdfSalt,
    pwKey: options.password ? await stretch(options.password, pwSalt) : null,
  });
  const authToken = await deriveAuthToken(linkSecret);

  const created = await SELF.fetch(`${ORIGIN}/api/uploads`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ plainSize: plain.length, chunkSize: CHUNK_SIZE }),
  });
  expect(created.status).toBe(200);
  const { uploadToken } = (await created.json()) as { uploadToken: string };

  const chunks = totalChunks(plain.length, CHUNK_SIZE);
  for (let i = 0; i < chunks; i++) {
    const slice = plain.subarray(i * CHUNK_SIZE, Math.min(plain.length, (i + 1) * CHUNK_SIZE));
    const cipher = await encryptChunk(cek, slice, noncePrefix, i, chunks);
    const put = await SELF.fetch(`${ORIGIN}/api/uploads/${uploadToken}/parts/${i}`, {
      method: 'PUT',
      body: cipher,
    });
    expect(put.status).toBe(200);
  }

  const completed = await SELF.fetch(`${ORIGIN}/api/uploads/${uploadToken}/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      expiresIn: options.expiresIn ?? 3600,
      maxDownloads: options.maxDownloads === undefined ? null : options.maxDownloads,
      authHash: await sha256Hex(authToken),
      hasPassword: Boolean(options.password),
      pwSalt: options.password ? toBase64Url(pwSalt) : null,
      pwParams: options.password ? ARGON2_PARAMS : null,
      pwHash: keys.pwVerifier ? await sha256Hex(keys.pwVerifier) : null,
      noncePrefix: toBase64Url(noncePrefix),
      kdfSalt: toBase64Url(kdfSalt),
      wrappedCek: toBase64Url(await wrapCek(keys.kek, cekRaw, wrapNonce)),
      wrapNonce: toBase64Url(wrapNonce),
      metaCipher: toBase64Url(
        await encryptMeta(cek, { name: 'サンプル.bin', type: '', size: plain.length }, metaNonce),
      ),
      metaNonce: toBase64Url(metaNonce),
    }),
  });
  expect(completed.status).toBe(200);
  const { token } = (await completed.json()) as { token: string };
  return { token, linkSecret, authToken };
}

async function download(uploaded: Uploaded, password?: string): Promise<Uint8Array> {
  const infoResponse = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/info`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ authToken: toBase64Url(uploaded.authToken) }),
  });
  expect(infoResponse.status).toBe(200);
  const info = (await infoResponse.json()) as Record<string, never> & {
    plainSize: number;
    chunkSize: number;
    totalChunks: number;
    noncePrefix: string;
    kdfSalt: string;
    wrappedCek: string;
    wrapNonce: string;
    metaCipher: string;
    metaNonce: string;
    pwSalt: string | null;
  };

  const keys = await deriveKeysFromMaterial({
    linkSecret: uploaded.linkSecret,
    kdfSalt: fromBase64Url(info.kdfSalt),
    pwKey: password && info.pwSalt ? await stretch(password, fromBase64Url(info.pwSalt)) : null,
  });
  const cek = await importCek(
    await unwrapCek(keys.kek, fromBase64Url(info.wrappedCek), fromBase64Url(info.wrapNonce)),
  );
  const meta = await decryptMeta(cek, fromBase64Url(info.metaCipher), fromBase64Url(info.metaNonce));
  expect(meta.name).toBe('サンプル.bin');

  const claimed = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/claim`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      authToken: toBase64Url(uploaded.authToken),
      pwVerifier: keys.pwVerifier ? toBase64Url(keys.pwVerifier) : null,
    }),
  });
  expect(claimed.status).toBe(200);
  const { grant } = (await claimed.json()) as { grant: string };

  const blob = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/blob?g=${encodeURIComponent(grant)}`);
  expect(blob.status).toBe(200);
  const cipher = new Uint8Array(await blob.arrayBuffer());

  const noncePrefix = fromBase64Url(info.noncePrefix);
  const out = new Uint8Array(info.plainSize);
  let cipherOffset = 0;
  let plainOffset = 0;
  for (let i = 0; i < info.totalChunks; i++) {
    const plainLength = Math.min(info.chunkSize, info.plainSize - i * info.chunkSize);
    const piece = cipher.subarray(cipherOffset, cipherOffset + plainLength + 16);
    out.set(await decryptChunk(cek, piece, noncePrefix, i, info.totalChunks), plainOffset);
    cipherOffset += piece.length;
    plainOffset += plainLength;
  }
  return out;
}

beforeAll(applySchema);
beforeEach(resetTables);

describe('アップロードとダウンロードの往復', () => {
  it('複数チャンクのファイルをバイト単位で復元できる', async () => {
    const plain = randomBytes(CHUNK_SIZE + 1234);
    const uploaded = await upload(plain);
    const restored = await download(uploaded);
    expect(restored.length).toBe(plain.length);
    expect(Array.from(restored.subarray(0, 64))).toEqual(Array.from(plain.subarray(0, 64)));
    expect(Array.from(restored.subarray(-64))).toEqual(Array.from(plain.subarray(-64)));
    expect(await sha256Hex(restored)).toBe(await sha256Hex(plain));
  });

  it('空ファイルも扱える', async () => {
    const uploaded = await upload(new Uint8Array(0));
    expect((await download(uploaded)).length).toBe(0);
  });

  it('パスワード付きファイルを往復できる', async () => {
    const plain = randomBytes(2048);
    const uploaded = await upload(plain, { password: 'とても長いパスフレーズ' });
    expect(await sha256Hex(await download(uploaded, 'とても長いパスフレーズ'))).toBe(
      await sha256Hex(plain),
    );
  });
});

describe('アクセス制御', () => {
  it('authToken が違えば 404', async () => {
    const uploaded = await upload(randomBytes(128));
    const response = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/info`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authToken: toBase64Url(randomBytes(32)) }),
    });
    expect(response.status).toBe(404);
  });

  it('グラント無しでは本体を取得できない', async () => {
    const uploaded = await upload(randomBytes(128));
    const response = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/blob`);
    expect(response.status).toBe(403);
  });

  it('パスワードが違えばダウンロード回数を消費せずに 401', async () => {
    const uploaded = await upload(randomBytes(128), { password: 'ただしいパスワード', maxDownloads: 1 });
    const response = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/claim`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        authToken: toBase64Url(uploaded.authToken),
        pwVerifier: toBase64Url(randomBytes(32)),
      }),
    });
    expect(response.status).toBe(401);

    const row = await env.DB.prepare('SELECT download_count FROM files').first<{
      download_count: number;
    }>();
    expect(row?.download_count).toBe(0);
  });
});

describe('ダウンロード回数制限', () => {
  it('上限に達すると 410 を返す', async () => {
    const uploaded = await upload(randomBytes(128), { maxDownloads: 1 });
    await download(uploaded);

    const second = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/claim`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authToken: toBase64Url(uploaded.authToken), pwVerifier: null }),
    });
    expect(second.status).toBe(410);
  });
});

describe('レンジ取得', () => {
  it('206 と Content-Range を返す', async () => {
    const uploaded = await upload(randomBytes(1000));
    const claimed = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/claim`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authToken: toBase64Url(uploaded.authToken), pwVerifier: null }),
    });
    const { grant } = (await claimed.json()) as { grant: string };

    const response = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/blob?g=${encodeURIComponent(grant)}`,
      { headers: { Range: 'bytes=100-199' } },
    );
    expect(response.status).toBe(206);
    expect(response.headers.get('content-range')).toBe(`bytes 100-199/${1000 + 16}`);
    expect((await response.arrayBuffer()).byteLength).toBe(100);
  });
});

describe('自動削除', () => {
  it('期限切れのファイルは本体ごと消える', async () => {
    const uploaded = await upload(randomBytes(256), { expiresIn: 3600 });
    const key = await env.DB.prepare('SELECT r2_key FROM files').first<{ r2_key: string }>();
    expect(await env.BUCKET.head(key!.r2_key)).not.toBeNull();

    const result = await purge(env, Date.now() + 3601 * 1000);
    expect(result.files).toBe(1);
    expect(await env.BUCKET.head(key!.r2_key)).toBeNull();

    const response = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/info`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authToken: toBase64Url(uploaded.authToken) }),
    });
    expect(response.status).toBe(404);
  });

  it('放棄されたアップロードセッションも消える', async () => {
    const created = await SELF.fetch(`${ORIGIN}/api/uploads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plainSize: 1024, chunkSize: CHUNK_SIZE }),
    });
    expect(created.status).toBe(200);

    const result = await purge(env, Date.now() + 25 * 60 * 60 * 1000);
    expect(result.uploads).toBe(1);
    const remaining = await env.DB.prepare('SELECT COUNT(*) AS n FROM uploads').first<{ n: number }>();
    expect(remaining?.n).toBe(0);
  });
});

describe('入力検証', () => {
  it('小さすぎる chunkSize は拒否する', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/uploads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plainSize: 100, chunkSize: 1024 }),
    });
    expect(response.status).toBe(400);
  });

  it('上限を超えるサイズは拒否する', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/uploads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plainSize: 2 * 1024 * 1024 * 1024, chunkSize: CHUNK_SIZE }),
    });
    expect(response.status).toBe(400);
  });
});

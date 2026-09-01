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
  fromBase64Url,
  toBase64Url,
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

const json = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

async function upload(
  contents: Uint8Array[],
  options: { expiresIn?: number; maxDownloads?: number | null; password?: string } = {},
): Promise<Uploaded> {
  const linkSecret = randomBytes(LINK_SECRET_BYTES);
  const kdfSalt = randomBytes(KDF_SALT_BYTES);
  const pwSalt = randomBytes(PW_SALT_BYTES);

  const keys = await deriveKeysFromMaterial({
    linkSecret,
    kdfSalt,
    pwKey: options.password ? await stretch(options.password, pwSalt) : null,
  });
  const authToken = await deriveAuthToken(linkSecret);

  const created = await SELF.fetch(
    `${ORIGIN}/api/uploads`,
    json({ chunkSize: CHUNK_SIZE, files: contents.map((plain) => ({ plainSize: plain.length })) }),
  );
  expect(created.status).toBe(200);
  const { uploadToken } = (await created.json()) as { uploadToken: string };

  const fileMetas: unknown[] = [];
  for (const [fileIndex, plain] of contents.entries()) {
    const cekRaw = randomBytes(KEY_BYTES);
    const cek = await importCek(cekRaw);
    const noncePrefix = randomBytes(NONCE_PREFIX_BYTES);
    const wrapNonce = randomBytes(NONCE_BYTES);
    const metaNonce = randomBytes(NONCE_BYTES);
    const chunks = totalChunks(plain.length, CHUNK_SIZE);

    for (let i = 0; i < chunks; i++) {
      const slice = plain.subarray(i * CHUNK_SIZE, Math.min(plain.length, (i + 1) * CHUNK_SIZE));
      const cipher = await encryptChunk(cek, slice, noncePrefix, i, chunks);
      const put = await SELF.fetch(
        `${ORIGIN}/api/uploads/${uploadToken}/files/${fileIndex}/parts/${i}`,
        { method: 'PUT', body: cipher },
      );
      expect(put.status).toBe(200);
    }

    fileMetas.push({
      noncePrefix: toBase64Url(noncePrefix),
      wrappedCek: toBase64Url(await wrapCek(keys.kek, cekRaw, wrapNonce)),
      wrapNonce: toBase64Url(wrapNonce),
      metaCipher: toBase64Url(
        await encryptMeta(
          cek,
          { name: `サンプル${fileIndex}.bin`, type: '', size: plain.length },
          metaNonce,
        ),
      ),
      metaNonce: toBase64Url(metaNonce),
    });
  }

  const completed = await SELF.fetch(
    `${ORIGIN}/api/uploads/${uploadToken}/complete`,
    json({
      expiresIn: options.expiresIn ?? 3600,
      maxDownloads: options.maxDownloads === undefined ? null : options.maxDownloads,
      authHash: await sha256Hex(authToken),
      kdfSalt: toBase64Url(kdfSalt),
      hasPassword: Boolean(options.password),
      pwSalt: options.password ? toBase64Url(pwSalt) : null,
      pwParams: options.password ? ARGON2_PARAMS : null,
      pwHash: keys.pwVerifier ? await sha256Hex(keys.pwVerifier) : null,
      files: fileMetas,
    }),
  );
  expect(completed.status).toBe(200);
  const { token } = (await completed.json()) as { token: string };
  return { token, linkSecret, authToken };
}

interface RemoteFile {
  index: number;
  plainSize: number;
  chunkSize: number;
  totalChunks: number;
  noncePrefix: string;
  wrappedCek: string;
  wrapNonce: string;
  metaCipher: string;
  metaNonce: string;
}

async function download(uploaded: Uploaded, password?: string): Promise<Uint8Array[]> {
  const infoResponse = await SELF.fetch(
    `${ORIGIN}/api/files/${uploaded.token}/info`,
    json({ authToken: toBase64Url(uploaded.authToken) }),
  );
  expect(infoResponse.status).toBe(200);
  const info = (await infoResponse.json()) as {
    kdfSalt: string;
    pwSalt: string | null;
    files: RemoteFile[];
  };

  const keys = await deriveKeysFromMaterial({
    linkSecret: uploaded.linkSecret,
    kdfSalt: fromBase64Url(info.kdfSalt),
    pwKey: password && info.pwSalt ? await stretch(password, fromBase64Url(info.pwSalt)) : null,
  });

  const claimed = await SELF.fetch(
    `${ORIGIN}/api/files/${uploaded.token}/claim`,
    json({
      authToken: toBase64Url(uploaded.authToken),
      pwVerifier: keys.pwVerifier ? toBase64Url(keys.pwVerifier) : null,
    }),
  );
  expect(claimed.status).toBe(200);
  const { grant } = (await claimed.json()) as { grant: string };

  const restored: Uint8Array[] = [];
  for (const file of info.files) {
    const cek = await importCek(
      await unwrapCek(keys.kek, fromBase64Url(file.wrappedCek), fromBase64Url(file.wrapNonce)),
    );
    const meta = await decryptMeta(
      cek,
      fromBase64Url(file.metaCipher),
      fromBase64Url(file.metaNonce),
    );
    expect(meta.name).toBe(`サンプル${file.index}.bin`);

    const blob = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/files/${file.index}/blob?g=${encodeURIComponent(grant)}`,
    );
    expect(blob.status).toBe(200);
    const cipher = new Uint8Array(await blob.arrayBuffer());

    const noncePrefix = fromBase64Url(file.noncePrefix);
    const out = new Uint8Array(file.plainSize);
    let cipherOffset = 0;
    let plainOffset = 0;
    for (let i = 0; i < file.totalChunks; i++) {
      const plainLength = Math.min(file.chunkSize, file.plainSize - i * file.chunkSize);
      const piece = cipher.subarray(cipherOffset, cipherOffset + plainLength + 16);
      out.set(await decryptChunk(cek, piece, noncePrefix, i, file.totalChunks), plainOffset);
      cipherOffset += piece.length;
      plainOffset += plainLength;
    }
    restored.push(out);
  }
  return restored;
}

beforeAll(applySchema);
beforeEach(resetTables);

describe('アップロードとダウンロードの往復', () => {
  it('複数チャンクのファイルをバイト単位で復元できる', async () => {
    const plain = randomBytes(CHUNK_SIZE + 1234);
    const [restored] = await download(await upload([plain]));
    expect(restored!.length).toBe(plain.length);
    expect(await sha256Hex(restored!)).toBe(await sha256Hex(plain));
  });

  it('1 つのリンクで複数ファイルを送れる', async () => {
    const files = [randomBytes(4096), randomBytes(CHUNK_SIZE + 10), randomBytes(1)];
    const restored = await download(await upload(files));
    expect(restored).toHaveLength(3);
    for (const [index, original] of files.entries()) {
      expect(await sha256Hex(restored[index]!)).toBe(await sha256Hex(original));
    }
  });

  it('空ファイルも扱える', async () => {
    const [restored] = await download(await upload([new Uint8Array(0)]));
    expect(restored!.length).toBe(0);
  });

  it('パスワード付きファイルを往復できる', async () => {
    const plain = randomBytes(2048);
    const uploaded = await upload([plain], { password: 'とても長いパスフレーズ' });
    const [restored] = await download(uploaded, 'とても長いパスフレーズ');
    expect(await sha256Hex(restored!)).toBe(await sha256Hex(plain));
  });
});

describe('アクセス制御', () => {
  it('authToken が違えば 404', async () => {
    const uploaded = await upload([randomBytes(128)]);
    const response = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/info`,
      json({ authToken: toBase64Url(randomBytes(32)) }),
    );
    expect(response.status).toBe(404);
  });

  it('グラント無しでは本体を取得できない', async () => {
    const uploaded = await upload([randomBytes(128)]);
    const response = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/files/0/blob`);
    expect(response.status).toBe(403);
  });

  it('パスワードが違えばダウンロード回数を消費せずに 401', async () => {
    const uploaded = await upload([randomBytes(128)], {
      password: 'ただしいパスワード',
      maxDownloads: 1,
    });
    const response = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/claim`,
      json({
        authToken: toBase64Url(uploaded.authToken),
        pwVerifier: toBase64Url(randomBytes(32)),
      }),
    );
    expect(response.status).toBe(401);

    const row = await env.DB.prepare('SELECT download_count FROM bundles').first<{
      download_count: number;
    }>();
    expect(row?.download_count).toBe(0);
  });

  it('リンクを知っていれば即時削除できる', async () => {
    const uploaded = await upload([randomBytes(256)]);
    const deleted = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authToken: toBase64Url(uploaded.authToken) }),
    });
    expect(deleted.status).toBe(200);

    const after = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/info`,
      json({ authToken: toBase64Url(uploaded.authToken) }),
    );
    expect(after.status).toBe(404);
    const files = await env.DB.prepare('SELECT COUNT(*) AS n FROM bundle_files').first<{ n: number }>();
    expect(files?.n).toBe(0);
  });
});

describe('ダウンロード回数制限', () => {
  it('バンドル単位で数える（ファイル数では減らない）', async () => {
    const uploaded = await upload([randomBytes(128), randomBytes(128)], { maxDownloads: 1 });
    await download(uploaded);

    const row = await env.DB.prepare('SELECT download_count FROM bundles').first<{
      download_count: number;
    }>();
    expect(row?.download_count).toBe(1);

    const second = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/claim`,
      json({ authToken: toBase64Url(uploaded.authToken), pwVerifier: null }),
    );
    expect(second.status).toBe(410);
  });
});

describe('回数到達時の完全削除', () => {
  async function claimGrant(uploaded: Uploaded): Promise<string> {
    const claimed = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/claim`,
      json({ authToken: toBase64Url(uploaded.authToken), pwVerifier: null }),
    );
    expect(claimed.status).toBe(200);
    return ((await claimed.json()) as { grant: string }).grant;
  }

  it('最後の 1 回が finish した瞬間に R2 ごと消え、リンクも無効になる', async () => {
    const uploaded = await upload([randomBytes(256), randomBytes(64)], { maxDownloads: 1 });
    const keys = await env.DB.prepare('SELECT r2_key FROM bundle_files').all<{ r2_key: string }>();
    const grant = await claimGrant(uploaded);

    const finish = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/finish`, json({ grant }));
    expect(finish.status).toBe(200);
    expect(((await finish.json()) as { deleted: boolean }).deleted).toBe(true);

    // R2 のオブジェクトも D1 の行も残っていない
    for (const key of keys.results) expect(await env.BUCKET.head(key.r2_key)).toBeNull();
    const rows = await env.DB.prepare('SELECT COUNT(*) AS n FROM bundles').first<{ n: number }>();
    expect(rows?.n).toBe(0);

    // リンクは無効
    const info = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/info`,
      json({ authToken: toBase64Url(uploaded.authToken) }),
    );
    expect(info.status).toBe(404);
  });

  it('上限に達していなければ finish しても消えない', async () => {
    const uploaded = await upload([randomBytes(128)], { maxDownloads: 2 });
    const grant = await claimGrant(uploaded);
    const finish = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/finish`, json({ grant }));
    expect(((await finish.json()) as { deleted: boolean }).deleted).toBe(false);

    const info = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/info`,
      json({ authToken: toBase64Url(uploaded.authToken) }),
    );
    expect(info.status).toBe(200);
  });

  it('finish が来なくても ping の途絶から猶予時間で purge が消す', async () => {
    const uploaded = await upload([randomBytes(128)], { maxDownloads: 1 });
    const grant = await claimGrant(uploaded);

    // ダウンロード中（ping あり）は消えない
    const ping = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/ping`, json({ grant }));
    expect(ping.status).toBe(200);
    expect((await purge(env, Date.now() + 60_000)).bundles).toBe(0);

    // 途絶から 15 分（既定の猶予）を超えると消える
    expect((await purge(env, Date.now() + 16 * 60_000)).bundles).toBe(1);
  });

  it('偽のグラントでは finish も ping もできない', async () => {
    const uploaded = await upload([randomBytes(128)], { maxDownloads: 1 });
    const finish = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/finish`,
      json({ grant: 'x.y.z' }),
    );
    expect(finish.status).toBe(403);
  });
});

describe('期限切れ時の完全削除', () => {
  it('期限切れリンクへのアクセスで、その場で R2 ごと消える', async () => {
    const uploaded = await upload([randomBytes(256)]);
    const keys = await env.DB.prepare('SELECT r2_key FROM bundle_files').all<{ r2_key: string }>();

    await env.DB.prepare('UPDATE bundles SET expires_at = ?').bind(Date.now() - 1000).run();

    const info = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/info`,
      json({ authToken: toBase64Url(uploaded.authToken) }),
    );
    expect(info.status).toBe(410);

    for (const key of keys.results) expect(await env.BUCKET.head(key.r2_key)).toBeNull();
    const rows = await env.DB.prepare('SELECT COUNT(*) AS n FROM bundles').first<{ n: number }>();
    expect(rows?.n).toBe(0);
  });
});

describe('レンジ取得', () => {
  it('206 と Content-Range を返す', async () => {
    const uploaded = await upload([randomBytes(1000)]);
    const claimed = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/claim`,
      json({ authToken: toBase64Url(uploaded.authToken), pwVerifier: null }),
    );
    const { grant } = (await claimed.json()) as { grant: string };

    const response = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/files/0/blob?g=${encodeURIComponent(grant)}`,
      { headers: { Range: 'bytes=100-199' } },
    );
    expect(response.status).toBe(206);
    expect(response.headers.get('content-range')).toBe(`bytes 100-199/${1000 + 16}`);
    expect((await response.arrayBuffer()).byteLength).toBe(100);
  });
});

describe('自動削除', () => {
  it('期限切れのバンドルは本体ごと消える', async () => {
    const uploaded = await upload([randomBytes(256), randomBytes(256)], { expiresIn: 3600 });
    const keys = await env.DB.prepare('SELECT r2_key FROM bundle_files').all<{ r2_key: string }>();
    expect(keys.results).toHaveLength(2);
    for (const key of keys.results) expect(await env.BUCKET.head(key.r2_key)).not.toBeNull();

    const result = await purge(env, Date.now() + 3601 * 1000);
    expect(result.bundles).toBe(1);
    for (const key of keys.results) expect(await env.BUCKET.head(key.r2_key)).toBeNull();

    const response = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/info`,
      json({ authToken: toBase64Url(uploaded.authToken) }),
    );
    expect(response.status).toBe(404);
  });

  it('放棄されたアップロードセッションも消える', async () => {
    const created = await SELF.fetch(
      `${ORIGIN}/api/uploads`,
      json({ chunkSize: CHUNK_SIZE, files: [{ plainSize: 1024 }] }),
    );
    expect(created.status).toBe(200);

    const result = await purge(env, Date.now() + 25 * 60 * 60 * 1000);
    expect(result.uploads).toBe(1);
    const remaining = await env.DB.prepare('SELECT COUNT(*) AS n FROM uploads').first<{ n: number }>();
    expect(remaining?.n).toBe(0);
  });
});

describe('入力検証', () => {
  it('小さすぎる chunkSize は拒否する', async () => {
    const response = await SELF.fetch(
      `${ORIGIN}/api/uploads`,
      json({ chunkSize: 1024, files: [{ plainSize: 100 }] }),
    );
    expect(response.status).toBe(400);
  });

  it('合計サイズが上限を超えると拒否する', async () => {
    const response = await SELF.fetch(
      `${ORIGIN}/api/uploads`,
      json({
        chunkSize: CHUNK_SIZE,
        files: [{ plainSize: 600 * 1024 * 1024 }, { plainSize: 600 * 1024 * 1024 }],
      }),
    );
    expect(response.status).toBe(400);
  });

  it('ファイル数が 0 なら拒否する', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/uploads`, json({ chunkSize: CHUNK_SIZE, files: [] }));
    expect(response.status).toBe(400);
  });

  it('complete でファイル数が合わなければ拒否する', async () => {
    const created = await SELF.fetch(
      `${ORIGIN}/api/uploads`,
      json({ chunkSize: CHUNK_SIZE, files: [{ plainSize: 10 }] }),
    );
    const { uploadToken } = (await created.json()) as { uploadToken: string };
    const response = await SELF.fetch(
      `${ORIGIN}/api/uploads/${uploadToken}/complete`,
      json({
        expiresIn: 3600,
        maxDownloads: null,
        authHash: 'a'.repeat(64),
        kdfSalt: toBase64Url(randomBytes(KDF_SALT_BYTES)),
        hasPassword: false,
        files: [],
      }),
    );
    expect(response.status).toBe(400);
  });
});

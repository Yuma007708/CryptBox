import { Hono } from 'hono';
import type { Env } from './env.js';
import { GRANT_TTL_MS, UPLOAD_TTL_MS, maxFileSize } from './env.js';
import {
  BadRequest,
  decodeFixed,
  isHash,
  randomBytes,
  sha256Hex,
  signGrant,
  timingSafeEqual,
  verifyGrant,
} from './lib.js';
import {
  FILE_TOKEN_BYTES,
  GCM_TAG_BYTES,
  KDF_SALT_BYTES,
  MAX_EXPIRY_SECONDS,
  NONCE_BYTES,
  NONCE_PREFIX_BYTES,
  PW_SALT_BYTES,
  cipherTotalSize,
  fromBase64Url,
  toBase64Url,
  totalChunks as computeChunks,
} from '../shared/format.js';

/** R2 マルチパートの制約 */
const MIN_CHUNK_SIZE = 5 * 1024 * 1024;
const MAX_CHUNK_SIZE = 64 * 1024 * 1024;
const MAX_PARTS = 10000;

const app = new Hono<{ Bindings: Env }>();

/* ------------------------------------------------------------------ *
 * 共通ミドルウェア
 * ------------------------------------------------------------------ */

app.use('*', async (c, next) => {
  await next();
  const headers = c.res.headers;
  headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Permissions-Policy', 'interest-cohort=(), geolocation=(), camera=(), microphone=()');
  if (headers.get('content-type')?.includes('text/html')) {
    headers.set(
      'Content-Security-Policy',
      [
        "default-src 'self'",
        // hash-wasm (Argon2id) を動かすため WASM のコンパイルのみ許可する
        "script-src 'self' 'wasm-unsafe-eval'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "worker-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
      ].join('; '),
    );
  }
});

app.onError((err, c) => {
  if (err instanceof BadRequest) return c.json({ error: err.message }, 400);
  console.error('unhandled error', err);
  return c.json({ error: 'サーバー内部エラー' }, 500);
});

/** アップロード API を閉じたい場合は UPLOAD_TOKEN を設定する */
function assertUploadAllowed(c: { req: { header: (name: string) => string | undefined }; env: Env }) {
  const expected = c.env.UPLOAD_TOKEN;
  if (!expected) return;
  const header = c.req.header('authorization') ?? '';
  const presented = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!timingSafeEqual(presented, expected)) throw new BadRequest('アップロードが許可されていません');
}

function requireInt(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new BadRequest(`${field} が不正です`);
  }
  return value;
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    throw new BadRequest('JSON の解析に失敗しました');
  }
  if (typeof body !== 'object' || body === null) throw new BadRequest('JSON の形式が不正です');
  return body as Record<string, unknown>;
}

/* ------------------------------------------------------------------ *
 * アップロード
 * ------------------------------------------------------------------ */

interface UploadRow {
  id: string;
  r2_key: string;
  r2_upload_id: string;
  plain_size: number;
  chunk_size: number;
  total_chunks: number;
}

app.post('/api/uploads', async (c) => {
  assertUploadAllowed(c);
  const body = await readJson(c.req.raw);
  const plainSize = requireInt(body.plainSize, 'plainSize');
  const chunkSize = requireInt(body.chunkSize, 'chunkSize');

  if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE) {
    throw new BadRequest('chunkSize が許容範囲外です');
  }
  const limit = maxFileSize(c.env);
  if (plainSize > limit) {
    throw new BadRequest(`ファイルが大きすぎます (上限 ${limit} バイト)`);
  }
  const chunks = computeChunks(plainSize, chunkSize);
  if (chunks > MAX_PARTS) throw new BadRequest('チャンク数が多すぎます');

  const uploadToken = toBase64Url(randomBytes(32));
  const id = await sha256Hex(uploadToken);
  const r2Key = `blob/${toBase64Url(randomBytes(24))}`;
  const multipart = await c.env.BUCKET.createMultipartUpload(r2Key);
  const now = Date.now();

  await c.env.DB.prepare(
    `INSERT INTO uploads (id, r2_key, r2_upload_id, created_at, abandon_at, plain_size, chunk_size, total_chunks)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(id, r2Key, multipart.uploadId, now, now + UPLOAD_TTL_MS, plainSize, chunkSize, chunks)
    .run();

  return c.json({ uploadToken, totalChunks: chunks, chunkSize });
});

async function loadUpload(env: Env, uploadToken: string): Promise<UploadRow> {
  const id = await sha256Hex(uploadToken);
  const row = await env.DB.prepare(
    `SELECT id, r2_key, r2_upload_id, plain_size, chunk_size, total_chunks FROM uploads WHERE id = ?`,
  )
    .bind(id)
    .first<UploadRow>();
  if (!row) throw new BadRequest('アップロードセッションが見つかりません');
  return row;
}

app.put('/api/uploads/:token/parts/:index', async (c) => {
  assertUploadAllowed(c);
  const upload = await loadUpload(c.env, c.req.param('token'));
  const index = Number(c.req.param('index'));
  if (!Number.isInteger(index) || index < 0 || index >= upload.total_chunks) {
    throw new BadRequest('チャンク番号が不正です');
  }
  if (!c.req.raw.body) throw new BadRequest('ボディがありません');

  const isLast = index === upload.total_chunks - 1;
  const expected = isLast
    ? upload.plain_size - index * upload.chunk_size + GCM_TAG_BYTES
    : upload.chunk_size + GCM_TAG_BYTES;
  const declared = Number(c.req.header('content-length'));
  if (Number.isFinite(declared) && declared !== expected) {
    throw new BadRequest('チャンクの長さが不正です');
  }

  const multipart = c.env.BUCKET.resumeMultipartUpload(upload.r2_key, upload.r2_upload_id);
  // R2 のパート番号は 1 始まり
  const part = await multipart.uploadPart(index + 1, c.req.raw.body);

  await c.env.DB.prepare(
    `INSERT INTO upload_parts (upload_id, part_number, etag) VALUES (?, ?, ?)
     ON CONFLICT (upload_id, part_number) DO UPDATE SET etag = excluded.etag`,
  )
    .bind(upload.id, part.partNumber, part.etag)
    .run();

  return c.json({ index, etag: part.etag });
});

app.post('/api/uploads/:token/complete', async (c) => {
  assertUploadAllowed(c);
  const upload = await loadUpload(c.env, c.req.param('token'));
  const body = await readJson(c.req.raw);

  const expiresIn = requireInt(body.expiresIn, 'expiresIn');
  if (expiresIn <= 0 || expiresIn > MAX_EXPIRY_SECONDS) throw new BadRequest('有効期限が不正です');

  let maxDownloads: number | null = null;
  if (body.maxDownloads !== null && body.maxDownloads !== undefined) {
    maxDownloads = requireInt(body.maxDownloads, 'maxDownloads');
    if (maxDownloads < 1 || maxDownloads > 10000) throw new BadRequest('ダウンロード回数が不正です');
  }

  // 鍵素材そのものではなく、その一方向ハッシュのみを受け取る
  const authHash = body.authHash;
  if (!isHash(authHash)) throw new BadRequest('authHash が不正です');

  const hasPassword = body.hasPassword === true;
  let pwSalt: string | null = null;
  let pwParams: string | null = null;
  let pwHash: string | null = null;
  if (hasPassword) {
    decodeFixed(body.pwSalt, PW_SALT_BYTES, 'pwSalt');
    pwSalt = body.pwSalt as string;
    if (!isHash(body.pwHash)) throw new BadRequest('pwHash が不正です');
    pwHash = body.pwHash;
    if (typeof body.pwParams !== 'object' || body.pwParams === null) {
      throw new BadRequest('pwParams が不正です');
    }
    pwParams = JSON.stringify(body.pwParams);
  }

  decodeFixed(body.noncePrefix, NONCE_PREFIX_BYTES, 'noncePrefix');
  decodeFixed(body.kdfSalt, KDF_SALT_BYTES, 'kdfSalt');
  decodeFixed(body.wrapNonce, NONCE_BYTES, 'wrapNonce');
  decodeFixed(body.metaNonce, NONCE_BYTES, 'metaNonce');
  if (typeof body.wrappedCek !== 'string' || body.wrappedCek.length > 512) {
    throw new BadRequest('wrappedCek が不正です');
  }
  if (typeof body.metaCipher !== 'string' || body.metaCipher.length > 8192) {
    throw new BadRequest('metaCipher が不正です');
  }

  // すべてのパートが揃っているか確認する
  const parts = await c.env.DB.prepare(
    `SELECT part_number, etag FROM upload_parts WHERE upload_id = ? ORDER BY part_number`,
  )
    .bind(upload.id)
    .all<{ part_number: number; etag: string }>();
  if (parts.results.length !== upload.total_chunks) {
    throw new BadRequest(
      `未送信のチャンクがあります (${parts.results.length}/${upload.total_chunks})`,
    );
  }

  const multipart = c.env.BUCKET.resumeMultipartUpload(upload.r2_key, upload.r2_upload_id);
  await multipart.complete(
    parts.results.map((p) => ({ partNumber: p.part_number, etag: p.etag })),
  );

  const fileToken = toBase64Url(randomBytes(FILE_TOKEN_BYTES));
  const fileId = await sha256Hex(fileToken);
  const now = Date.now();
  const expiresAt = now + expiresIn * 1000;
  const cipherSize = cipherTotalSize(upload.plain_size, upload.chunk_size);

  await c.env.DB.batch([
    c.env.DB.prepare(
      `INSERT INTO files (
         id, r2_key, created_at, expires_at, max_downloads, download_count,
         plain_size, cipher_size, chunk_size, total_chunks, nonce_prefix,
         kdf_salt, wrapped_cek, wrap_nonce, meta_cipher, meta_nonce,
         auth_hash, has_password, pw_salt, pw_params, pw_hash
       ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      fileId,
      upload.r2_key,
      now,
      expiresAt,
      maxDownloads,
      upload.plain_size,
      cipherSize,
      upload.chunk_size,
      upload.total_chunks,
      body.noncePrefix as string,
      body.kdfSalt as string,
      body.wrappedCek,
      body.wrapNonce as string,
      body.metaCipher,
      body.metaNonce as string,
      authHash,
      hasPassword ? 1 : 0,
      pwSalt,
      pwParams,
      pwHash,
    ),
    c.env.DB.prepare(`DELETE FROM upload_parts WHERE upload_id = ?`).bind(upload.id),
    c.env.DB.prepare(`DELETE FROM uploads WHERE id = ?`).bind(upload.id),
  ]);

  return c.json({ token: fileToken, expiresAt, maxDownloads });
});

app.delete('/api/uploads/:token', async (c) => {
  const upload = await loadUpload(c.env, c.req.param('token'));
  const multipart = c.env.BUCKET.resumeMultipartUpload(upload.r2_key, upload.r2_upload_id);
  await multipart.abort().catch(() => undefined);
  await c.env.DB.batch([
    c.env.DB.prepare(`DELETE FROM upload_parts WHERE upload_id = ?`).bind(upload.id),
    c.env.DB.prepare(`DELETE FROM uploads WHERE id = ?`).bind(upload.id),
  ]);
  return c.json({ ok: true });
});

/* ------------------------------------------------------------------ *
 * ダウンロード
 * ------------------------------------------------------------------ */

interface FileRow {
  id: string;
  r2_key: string;
  created_at: number;
  expires_at: number;
  max_downloads: number | null;
  download_count: number;
  plain_size: number;
  cipher_size: number;
  chunk_size: number;
  total_chunks: number;
  nonce_prefix: string;
  kdf_salt: string;
  wrapped_cek: string;
  wrap_nonce: string;
  meta_cipher: string;
  meta_nonce: string;
  auth_hash: string;
  has_password: number;
  pw_salt: string | null;
  pw_params: string | null;
  pw_hash: string | null;
}

/**
 * リンクトークンとファイル固有の authToken の両方を検証する。
 * どちらも URL フラグメント由来なので、リンクを知らない第三者は到達できない。
 */
async function authorize(env: Env, token: string, authToken: unknown): Promise<FileRow> {
  const id = await sha256Hex(token);
  const row = await env.DB.prepare(`SELECT * FROM files WHERE id = ?`).bind(id).first<FileRow>();
  if (!row) throw new NotFound();
  if (typeof authToken !== 'string') throw new NotFound();
  let presented: string;
  try {
    presented = await sha256Hex(fromBase64Url(authToken));
  } catch {
    throw new NotFound();
  }
  if (!timingSafeEqual(presented, row.auth_hash)) throw new NotFound();
  if (row.expires_at <= Date.now()) throw new Gone('有効期限が切れています');
  return row;
}

class NotFound extends Error {}
class Gone extends Error {}

function errorResponse(err: unknown): Response | null {
  if (err instanceof NotFound) {
    return Response.json({ error: 'ファイルが見つかりません' }, { status: 404 });
  }
  if (err instanceof Gone) {
    return Response.json({ error: err.message }, { status: 410 });
  }
  return null;
}

app.post('/api/files/:token/info', async (c) => {
  const body = await readJson(c.req.raw);
  let row: FileRow;
  try {
    row = await authorize(c.env, c.req.param('token'), body.authToken);
  } catch (err) {
    const res = errorResponse(err);
    if (res) return res;
    throw err;
  }

  const remaining =
    row.max_downloads === null ? null : Math.max(0, row.max_downloads - row.download_count);
  if (remaining === 0) return c.json({ error: 'ダウンロード回数の上限に達しています' }, 410);

  return c.json({
    plainSize: row.plain_size,
    cipherSize: row.cipher_size,
    chunkSize: row.chunk_size,
    totalChunks: row.total_chunks,
    noncePrefix: row.nonce_prefix,
    kdfSalt: row.kdf_salt,
    wrappedCek: row.wrapped_cek,
    wrapNonce: row.wrap_nonce,
    metaCipher: row.meta_cipher,
    metaNonce: row.meta_nonce,
    hasPassword: row.has_password === 1,
    pwSalt: row.pw_salt,
    pwParams: row.pw_params ? JSON.parse(row.pw_params) : null,
    expiresAt: row.expires_at,
    maxDownloads: row.max_downloads,
    remainingDownloads: remaining,
  });
});

app.post('/api/files/:token/claim', async (c) => {
  const body = await readJson(c.req.raw);
  let row: FileRow;
  try {
    row = await authorize(c.env, c.req.param('token'), body.authToken);
  } catch (err) {
    const res = errorResponse(err);
    if (res) return res;
    throw err;
  }

  // パスワードは Argon2id で導出した検証値のハッシュで確認する。
  // 誤入力ではダウンロード回数を消費しない。
  if (row.has_password === 1) {
    if (typeof body.pwVerifier !== 'string') {
      return c.json({ error: 'パスワードが必要です' }, 401);
    }
    let presented: string;
    try {
      presented = await sha256Hex(fromBase64Url(body.pwVerifier));
    } catch {
      return c.json({ error: 'パスワードが違います' }, 401);
    }
    if (!timingSafeEqual(presented, row.pw_hash ?? '')) {
      return c.json({ error: 'パスワードが違います' }, 401);
    }
  }

  const now = Date.now();
  const claimed = await c.env.DB.prepare(
    `UPDATE files
        SET download_count = download_count + 1, last_claim_at = ?
      WHERE id = ?
        AND expires_at > ?
        AND (max_downloads IS NULL OR download_count < max_downloads)`,
  )
    .bind(now, row.id, now)
    .run();

  if (!claimed.meta.changes) {
    return c.json({ error: 'ダウンロード回数の上限に達しています' }, 410);
  }

  const expiresAt = Math.min(now + GRANT_TTL_MS, row.expires_at);
  const grant = await signGrant(c.env.GRANT_SECRET, row.id, expiresAt);
  const remaining =
    row.max_downloads === null ? null : Math.max(0, row.max_downloads - row.download_count - 1);

  return c.json({ grant, grantExpiresAt: expiresAt, remainingDownloads: remaining });
});

app.get('/api/files/:token/blob', async (c) => {
  const id = await sha256Hex(c.req.param('token'));
  const grant = c.req.query('g') ?? '';
  if (!(await verifyGrant(c.env.GRANT_SECRET, grant, id, Date.now()))) {
    return c.json({ error: 'ダウンロード権限がありません' }, 403);
  }

  const row = await c.env.DB.prepare(
    `SELECT r2_key, cipher_size FROM files WHERE id = ?`,
  )
    .bind(id)
    .first<{ r2_key: string; cipher_size: number }>();
  if (!row) return c.json({ error: 'ファイルが見つかりません' }, 404);

  const range = parseRange(c.req.header('range'), row.cipher_size);
  if (range === 'invalid') {
    return new Response('Range Not Satisfiable', {
      status: 416,
      headers: { 'Content-Range': `bytes */${row.cipher_size}` },
    });
  }

  const object = await c.env.BUCKET.get(
    row.r2_key,
    range ? { range: { offset: range.start, length: range.end - range.start + 1 } } : undefined,
  );
  if (!object) return c.json({ error: 'ファイルが見つかりません' }, 404);

  const headers = new Headers({
    'Content-Type': 'application/octet-stream',
    'Accept-Ranges': 'bytes',
    'Cache-Control': 'no-store',
  });
  if (range) {
    headers.set('Content-Range', `bytes ${range.start}-${range.end}/${row.cipher_size}`);
    headers.set('Content-Length', String(range.end - range.start + 1));
    return new Response(object.body, { status: 206, headers });
  }
  headers.set('Content-Length', String(row.cipher_size));
  return new Response(object.body, { status: 200, headers });
});

/** 送信者・受信者いずれも、リンクを知っていれば即時削除できる */
app.delete('/api/files/:token', async (c) => {
  const body = await readJson(c.req.raw);
  let row: FileRow;
  try {
    row = await authorize(c.env, c.req.param('token'), body.authToken);
  } catch (err) {
    const res = errorResponse(err);
    if (res) return res;
    throw err;
  }
  await c.env.BUCKET.delete(row.r2_key);
  await c.env.DB.prepare(`DELETE FROM files WHERE id = ?`).bind(row.id).run();
  return c.json({ ok: true });
});

function parseRange(
  header: string | undefined,
  size: number,
): { start: number; end: number } | null | 'invalid' {
  if (!header) return null;
  const match = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!match) return 'invalid';
  const [, startText, endText] = match;
  if (startText === '' && endText === '') return 'invalid';

  let start: number;
  let end: number;
  if (startText === '') {
    const suffix = Number(endText);
    if (suffix <= 0) return 'invalid';
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = Number(startText);
    end = endText === '' ? size - 1 : Number(endText);
  }
  if (!Number.isFinite(start) || !Number.isFinite(end)) return 'invalid';
  if (start > end || start >= size) return 'invalid';
  return { start, end: Math.min(end, size - 1) };
}

/* ------------------------------------------------------------------ *
 * 静的アセット (SPA)
 * ------------------------------------------------------------------ */

app.all('/api/*', (c) => c.json({ error: 'Not Found' }, 404));
app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));

/* ------------------------------------------------------------------ *
 * 自動削除 (Cron Trigger)
 * ------------------------------------------------------------------ */

export async function purge(env: Env, now = Date.now()): Promise<{ files: number; uploads: number }> {
  // 期限切れ、またはダウンロード上限に達してグラント有効期間も過ぎたもの
  const expired = await env.DB.prepare(
    `SELECT id, r2_key FROM files
      WHERE expires_at <= ?
         OR (max_downloads IS NOT NULL
             AND download_count >= max_downloads
             AND last_claim_at IS NOT NULL
             AND last_claim_at + ? <= ?)
      LIMIT 500`,
  )
    .bind(now, GRANT_TTL_MS, now)
    .all<{ id: string; r2_key: string }>();

  for (const row of expired.results) {
    await env.BUCKET.delete(row.r2_key);
    await env.DB.prepare(`DELETE FROM files WHERE id = ?`).bind(row.id).run();
  }

  // 放棄されたマルチパートアップロード
  const stale = await env.DB.prepare(
    `SELECT id, r2_key, r2_upload_id FROM uploads WHERE abandon_at <= ? LIMIT 200`,
  )
    .bind(now)
    .all<{ id: string; r2_key: string; r2_upload_id: string }>();

  for (const row of stale.results) {
    await env.BUCKET.resumeMultipartUpload(row.r2_key, row.r2_upload_id)
      .abort()
      .catch(() => undefined);
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM upload_parts WHERE upload_id = ?`).bind(row.id),
      env.DB.prepare(`DELETE FROM uploads WHERE id = ?`).bind(row.id),
    ]);
  }

  return { files: expired.results.length, uploads: stale.results.length };
}

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(
      purge(env).then((result) => {
        console.log(`purged files=${result.files} uploads=${result.uploads}`);
      }),
    );
  },
} satisfies ExportedHandler<Env>;

import { Hono } from 'hono';
import type { Env } from './env.js';
import { GRANT_TTL_MS, UPLOAD_TTL_MS, downloadGraceMs, maxFileSize } from './env.js';
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
  MAX_FILES_PER_BUNDLE,
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
 * 共通
 * ------------------------------------------------------------------ */

app.use('/api/*', async (c, next) => {
  await next();
  c.res.headers.set('Cache-Control', 'no-store');
  c.res.headers.set('X-Content-Type-Options', 'nosniff');
  c.res.headers.set('Referrer-Policy', 'no-referrer');
});

app.onError((err, c) => {
  if (err instanceof BadRequest) return c.json({ error: err.message }, 400);
  console.error('unhandled error', err);
  return c.json({ error: 'サーバー内部エラー' }, 500);
});

class NotFound extends Error {}
class Gone extends Error {}

function errorResponse(err: unknown): Response | null {
  if (err instanceof NotFound) {
    return Response.json({ error: 'ファイルが見つかりません' }, { status: 404 });
  }
  if (err instanceof Gone) return Response.json({ error: err.message }, { status: 410 });
  return null;
}

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
  chunk_size: number;
  file_count: number;
}

interface UploadFileRow {
  file_index: number;
  r2_key: string;
  r2_upload_id: string;
  plain_size: number;
  total_chunks: number;
}

app.post('/api/uploads', async (c) => {
  assertUploadAllowed(c);
  const body = await readJson(c.req.raw);
  const chunkSize = requireInt(body.chunkSize, 'chunkSize');
  if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE) {
    throw new BadRequest('chunkSize が許容範囲外です');
  }

  if (!Array.isArray(body.files) || body.files.length === 0) {
    throw new BadRequest('files が空です');
  }
  if (body.files.length > MAX_FILES_PER_BUNDLE) {
    throw new BadRequest(`1 度に送れるのは ${MAX_FILES_PER_BUNDLE} ファイルまでです`);
  }

  const limit = maxFileSize(c.env);
  const sizes = body.files.map((file, index) => {
    if (typeof file !== 'object' || file === null) throw new BadRequest('files が不正です');
    return requireInt((file as Record<string, unknown>).plainSize, `files[${index}].plainSize`);
  });
  const totalSize = sizes.reduce((sum, size) => sum + size, 0);
  if (totalSize > limit) throw new BadRequest(`合計サイズが大きすぎます (上限 ${limit} バイト)`);

  const chunkCounts = sizes.map((size) => {
    const chunks = computeChunks(size, chunkSize);
    if (chunks > MAX_PARTS) throw new BadRequest('チャンク数が多すぎます');
    return chunks;
  });

  const uploadToken = toBase64Url(randomBytes(32));
  const id = await sha256Hex(uploadToken);
  const now = Date.now();

  const statements = [
    c.env.DB.prepare(
      `INSERT INTO uploads (id, created_at, abandon_at, chunk_size, file_count)
       VALUES (?, ?, ?, ?, ?)`,
    ).bind(id, now, now + UPLOAD_TTL_MS, chunkSize, sizes.length),
  ];

  for (let index = 0; index < sizes.length; index++) {
    const r2Key = `blob/${toBase64Url(randomBytes(24))}`;
    const multipart = await c.env.BUCKET.createMultipartUpload(r2Key);
    statements.push(
      c.env.DB.prepare(
        `INSERT INTO upload_files (upload_id, file_index, r2_key, r2_upload_id, plain_size, total_chunks)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(id, index, r2Key, multipart.uploadId, sizes[index], chunkCounts[index]),
    );
  }
  await c.env.DB.batch(statements);

  return c.json({
    uploadToken,
    chunkSize,
    files: chunkCounts.map((chunks, index) => ({ index, totalChunks: chunks })),
  });
});

async function loadUpload(env: Env, uploadToken: string): Promise<UploadRow> {
  const id = await sha256Hex(uploadToken);
  const row = await env.DB.prepare(
    `SELECT id, chunk_size, file_count FROM uploads WHERE id = ?`,
  )
    .bind(id)
    .first<UploadRow>();
  if (!row) throw new BadRequest('アップロードセッションが見つかりません');
  return row;
}

async function loadUploadFile(env: Env, uploadId: string, index: number): Promise<UploadFileRow> {
  const row = await env.DB.prepare(
    `SELECT file_index, r2_key, r2_upload_id, plain_size, total_chunks
       FROM upload_files WHERE upload_id = ? AND file_index = ?`,
  )
    .bind(uploadId, index)
    .first<UploadFileRow>();
  if (!row) throw new BadRequest('ファイル番号が不正です');
  return row;
}

app.put('/api/uploads/:token/files/:file/parts/:chunk', async (c) => {
  assertUploadAllowed(c);
  const upload = await loadUpload(c.env, c.req.param('token'));
  const fileIndex = Number(c.req.param('file'));
  if (!Number.isInteger(fileIndex) || fileIndex < 0 || fileIndex >= upload.file_count) {
    throw new BadRequest('ファイル番号が不正です');
  }
  const file = await loadUploadFile(c.env, upload.id, fileIndex);

  const chunkIndex = Number(c.req.param('chunk'));
  if (!Number.isInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= file.total_chunks) {
    throw new BadRequest('チャンク番号が不正です');
  }
  if (!c.req.raw.body) throw new BadRequest('ボディがありません');

  const isLast = chunkIndex === file.total_chunks - 1;
  const expected = isLast
    ? file.plain_size - chunkIndex * upload.chunk_size + GCM_TAG_BYTES
    : upload.chunk_size + GCM_TAG_BYTES;
  const declared = Number(c.req.header('content-length'));
  if (Number.isFinite(declared) && declared !== expected) {
    throw new BadRequest('チャンクの長さが不正です');
  }

  const multipart = c.env.BUCKET.resumeMultipartUpload(file.r2_key, file.r2_upload_id);
  // R2 のパート番号は 1 始まり
  const part = await multipart.uploadPart(chunkIndex + 1, c.req.raw.body);

  await c.env.DB.prepare(
    `INSERT INTO upload_parts (upload_id, file_index, part_number, etag) VALUES (?, ?, ?, ?)
     ON CONFLICT (upload_id, file_index, part_number) DO UPDATE SET etag = excluded.etag`,
  )
    .bind(upload.id, fileIndex, part.partNumber, part.etag)
    .run();

  return c.json({ fileIndex, chunkIndex, etag: part.etag });
});

/** complete で受け取る、ファイルごとの暗号メタデータを検証する */
function validateFileMeta(value: unknown, index: number): Record<string, string> {
  if (typeof value !== 'object' || value === null) throw new BadRequest(`files[${index}] が不正です`);
  const meta = value as Record<string, unknown>;
  decodeFixed(meta.noncePrefix, NONCE_PREFIX_BYTES, `files[${index}].noncePrefix`);
  decodeFixed(meta.wrapNonce, NONCE_BYTES, `files[${index}].wrapNonce`);
  decodeFixed(meta.metaNonce, NONCE_BYTES, `files[${index}].metaNonce`);
  if (typeof meta.wrappedCek !== 'string' || meta.wrappedCek.length > 512) {
    throw new BadRequest(`files[${index}].wrappedCek が不正です`);
  }
  if (typeof meta.metaCipher !== 'string' || meta.metaCipher.length > 8192) {
    throw new BadRequest(`files[${index}].metaCipher が不正です`);
  }
  return {
    noncePrefix: meta.noncePrefix as string,
    wrapNonce: meta.wrapNonce as string,
    metaNonce: meta.metaNonce as string,
    wrappedCek: meta.wrappedCek,
    metaCipher: meta.metaCipher,
  };
}

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
  if (!isHash(body.authHash)) throw new BadRequest('authHash が不正です');
  decodeFixed(body.kdfSalt, KDF_SALT_BYTES, 'kdfSalt');

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

  if (!Array.isArray(body.files) || body.files.length !== upload.file_count) {
    throw new BadRequest('files の数が一致しません');
  }
  const fileMetas = body.files.map(validateFileMeta);

  const uploadFiles = await c.env.DB.prepare(
    `SELECT file_index, r2_key, r2_upload_id, plain_size, total_chunks
       FROM upload_files WHERE upload_id = ? ORDER BY file_index`,
  )
    .bind(upload.id)
    .all<UploadFileRow>();

  const parts = await c.env.DB.prepare(
    `SELECT file_index, part_number, etag FROM upload_parts
      WHERE upload_id = ? ORDER BY file_index, part_number`,
  )
    .bind(upload.id)
    .all<{ file_index: number; part_number: number; etag: string }>();

  // すべてのパートが揃っているか確認してから R2 のマルチパートを確定する
  for (const file of uploadFiles.results) {
    const uploaded = parts.results.filter((part) => part.file_index === file.file_index);
    if (uploaded.length !== file.total_chunks) {
      throw new BadRequest(
        `未送信のチャンクがあります (ファイル ${file.file_index}: ${uploaded.length}/${file.total_chunks})`,
      );
    }
  }

  for (const file of uploadFiles.results) {
    const uploaded = parts.results.filter((part) => part.file_index === file.file_index);
    const multipart = c.env.BUCKET.resumeMultipartUpload(file.r2_key, file.r2_upload_id);
    await multipart.complete(
      uploaded.map((part) => ({ partNumber: part.part_number, etag: part.etag })),
    );
  }

  const shareToken = toBase64Url(randomBytes(FILE_TOKEN_BYTES));
  const bundleId = await sha256Hex(shareToken);
  const now = Date.now();
  const expiresAt = now + expiresIn * 1000;
  const totalPlainSize = uploadFiles.results.reduce((sum, file) => sum + file.plain_size, 0);

  const statements = [
    c.env.DB.prepare(
      `INSERT INTO bundles (
         id, created_at, expires_at, max_downloads, download_count, file_count, total_plain_size,
         kdf_salt, auth_hash, has_password, pw_salt, pw_params, pw_hash
       ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      bundleId,
      now,
      expiresAt,
      maxDownloads,
      uploadFiles.results.length,
      totalPlainSize,
      body.kdfSalt as string,
      body.authHash,
      hasPassword ? 1 : 0,
      pwSalt,
      pwParams,
      pwHash,
    ),
  ];

  for (const file of uploadFiles.results) {
    const meta = fileMetas[file.file_index]!;
    statements.push(
      c.env.DB.prepare(
        `INSERT INTO bundle_files (
           bundle_id, file_index, r2_key, plain_size, cipher_size, chunk_size, total_chunks,
           nonce_prefix, wrapped_cek, wrap_nonce, meta_cipher, meta_nonce
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        bundleId,
        file.file_index,
        file.r2_key,
        file.plain_size,
        cipherTotalSize(file.plain_size, upload.chunk_size),
        upload.chunk_size,
        file.total_chunks,
        meta.noncePrefix,
        meta.wrappedCek,
        meta.wrapNonce,
        meta.metaCipher,
        meta.metaNonce,
      ),
    );
  }

  statements.push(
    c.env.DB.prepare(`DELETE FROM upload_parts WHERE upload_id = ?`).bind(upload.id),
    c.env.DB.prepare(`DELETE FROM upload_files WHERE upload_id = ?`).bind(upload.id),
    c.env.DB.prepare(`DELETE FROM uploads WHERE id = ?`).bind(upload.id),
  );
  await c.env.DB.batch(statements);

  return c.json({ token: shareToken, expiresAt, maxDownloads });
});

app.delete('/api/uploads/:token', async (c) => {
  const upload = await loadUpload(c.env, c.req.param('token'));
  const files = await c.env.DB.prepare(
    `SELECT file_index, r2_key, r2_upload_id, plain_size, total_chunks
       FROM upload_files WHERE upload_id = ?`,
  )
    .bind(upload.id)
    .all<UploadFileRow>();

  for (const file of files.results) {
    await c.env.BUCKET.resumeMultipartUpload(file.r2_key, file.r2_upload_id)
      .abort()
      .catch(() => undefined);
  }
  await c.env.DB.batch([
    c.env.DB.prepare(`DELETE FROM upload_parts WHERE upload_id = ?`).bind(upload.id),
    c.env.DB.prepare(`DELETE FROM upload_files WHERE upload_id = ?`).bind(upload.id),
    c.env.DB.prepare(`DELETE FROM uploads WHERE id = ?`).bind(upload.id),
  ]);
  return c.json({ ok: true });
});

/* ------------------------------------------------------------------ *
 * ダウンロード
 * ------------------------------------------------------------------ */

interface BundleRow {
  id: string;
  created_at: number;
  expires_at: number;
  max_downloads: number | null;
  download_count: number;
  active_downloads: number;
  file_count: number;
  total_plain_size: number;
  kdf_salt: string;
  auth_hash: string;
  has_password: number;
  pw_salt: string | null;
  pw_params: string | null;
  pw_hash: string | null;
}

interface BundleFileRow {
  file_index: number;
  r2_key: string;
  plain_size: number;
  cipher_size: number;
  chunk_size: number;
  total_chunks: number;
  nonce_prefix: string;
  wrapped_cek: string;
  wrap_nonce: string;
  meta_cipher: string;
  meta_nonce: string;
}

/**
 * 共有トークンと authToken の両方を検証する。
 * どちらも URL 由来だが、authToken はフラグメントの鍵からしか作れないため、
 * アクセスログにトークンが残っても第三者は API を叩けない。
 */
async function authorize(env: Env, token: string, authToken: unknown): Promise<BundleRow> {
  const id = await sha256Hex(token);
  const row = await env.DB.prepare(`SELECT * FROM bundles WHERE id = ?`).bind(id).first<BundleRow>();
  if (!row) throw new NotFound();
  if (typeof authToken !== 'string') throw new NotFound();
  let presented: string;
  try {
    presented = await sha256Hex(fromBase64Url(authToken));
  } catch {
    throw new NotFound();
  }
  if (!timingSafeEqual(presented, row.auth_hash)) throw new NotFound();
  if (row.expires_at <= Date.now()) {
    // 期限切れは Cron を待たず、アクセスされた時点で R2 ごと消す
    await deleteBundle(env, row.id);
    throw new Gone('有効期限が切れています');
  }
  return row;
}

app.post('/api/files/:token/info', async (c) => {
  const body = await readJson(c.req.raw);
  let bundle: BundleRow;
  try {
    bundle = await authorize(c.env, c.req.param('token'), body.authToken);
  } catch (err) {
    const res = errorResponse(err);
    if (res) return res;
    throw err;
  }

  const remaining =
    bundle.max_downloads === null
      ? null
      : Math.max(0, bundle.max_downloads - bundle.download_count);
  if (remaining === 0) return c.json({ error: 'ダウンロード回数の上限に達しています' }, 410);

  const files = await c.env.DB.prepare(
    `SELECT file_index, plain_size, cipher_size, chunk_size, total_chunks,
            nonce_prefix, wrapped_cek, wrap_nonce, meta_cipher, meta_nonce
       FROM bundle_files WHERE bundle_id = ? ORDER BY file_index`,
  )
    .bind(bundle.id)
    .all<BundleFileRow>();

  return c.json({
    createdAt: bundle.created_at,
    expiresAt: bundle.expires_at,
    maxDownloads: bundle.max_downloads,
    remainingDownloads: remaining,
    totalPlainSize: bundle.total_plain_size,
    kdfSalt: bundle.kdf_salt,
    hasPassword: bundle.has_password === 1,
    pwSalt: bundle.pw_salt,
    pwParams: bundle.pw_params ? JSON.parse(bundle.pw_params) : null,
    files: files.results.map((file) => ({
      index: file.file_index,
      plainSize: file.plain_size,
      cipherSize: file.cipher_size,
      chunkSize: file.chunk_size,
      totalChunks: file.total_chunks,
      noncePrefix: file.nonce_prefix,
      wrappedCek: file.wrapped_cek,
      wrapNonce: file.wrap_nonce,
      metaCipher: file.meta_cipher,
      metaNonce: file.meta_nonce,
    })),
  });
});

app.post('/api/files/:token/claim', async (c) => {
  const body = await readJson(c.req.raw);
  let bundle: BundleRow;
  try {
    bundle = await authorize(c.env, c.req.param('token'), body.authToken);
  } catch (err) {
    const res = errorResponse(err);
    if (res) return res;
    throw err;
  }

  // パスワードは Argon2id で導出した検証値のハッシュで確認する。
  // 誤入力ではダウンロード回数を消費しない。
  if (bundle.has_password === 1) {
    if (typeof body.pwVerifier !== 'string') {
      return c.json({ error: 'パスワードが必要です' }, 401);
    }
    let presented: string;
    try {
      presented = await sha256Hex(fromBase64Url(body.pwVerifier));
    } catch {
      return c.json({ error: 'パスワードが違います' }, 401);
    }
    if (!timingSafeEqual(presented, bundle.pw_hash ?? '')) {
      return c.json({ error: 'パスワードが違います' }, 401);
    }
  }

  const now = Date.now();
  const claimed = await c.env.DB.prepare(
    `UPDATE bundles
        SET download_count = download_count + 1,
            active_downloads = active_downloads + 1,
            last_activity_at = ?
      WHERE id = ?
        AND expires_at > ?
        AND (max_downloads IS NULL OR download_count < max_downloads)`,
  )
    .bind(now, bundle.id, now)
    .run();

  if (!claimed.meta.changes) {
    return c.json({ error: 'ダウンロード回数の上限に達しています' }, 410);
  }

  const expiresAt = Math.min(now + GRANT_TTL_MS, bundle.expires_at);
  const grant = await signGrant(c.env.GRANT_SECRET, bundle.id, expiresAt);
  const remaining =
    bundle.max_downloads === null
      ? null
      : Math.max(0, bundle.max_downloads - bundle.download_count - 1);

  return c.json({ grant, grantExpiresAt: expiresAt, remainingDownloads: remaining });
});

/**
 * ダウンロード中の生存信号。回数上限に達したバンドルは、この信号が
 * 途絶えてから猶予時間が過ぎると Cron が削除する。
 */
app.post('/api/files/:token/ping', async (c) => {
  const body = await readJson(c.req.raw);
  const bundleId = await sha256Hex(c.req.param('token'));
  if (typeof body.grant !== 'string' || !(await verifyGrant(c.env.GRANT_SECRET, body.grant, bundleId, Date.now()))) {
    return c.json({ error: 'ダウンロード権限がありません' }, 403);
  }
  await c.env.DB.prepare(`UPDATE bundles SET last_activity_at = ? WHERE id = ?`)
    .bind(Date.now(), bundleId)
    .run();
  return c.json({ ok: true });
});

/**
 * ダウンロード完了（またはページ離脱）の通知。アクティブ数を減らし、
 * 回数上限に達していてアクティブが 0 になった瞬間に完全削除する。
 * これにより「最後の 1 回が終わったらすぐ消える」が成立する。
 */
app.post('/api/files/:token/finish', async (c) => {
  const body = await readJson(c.req.raw);
  const bundleId = await sha256Hex(c.req.param('token'));
  if (typeof body.grant !== 'string' || !(await verifyGrant(c.env.GRANT_SECRET, body.grant, bundleId, Date.now()))) {
    return c.json({ error: 'ダウンロード権限がありません' }, 403);
  }

  await c.env.DB.prepare(
    `UPDATE bundles
        SET active_downloads = MAX(0, active_downloads - 1), last_activity_at = ?
      WHERE id = ?`,
  )
    .bind(Date.now(), bundleId)
    .run();

  const row = await c.env.DB.prepare(
    `SELECT max_downloads, download_count, active_downloads FROM bundles WHERE id = ?`,
  )
    .bind(bundleId)
    .first<{ max_downloads: number | null; download_count: number; active_downloads: number }>();
  if (!row) return c.json({ ok: true, deleted: true });

  const exhausted = row.max_downloads !== null && row.download_count >= row.max_downloads;
  if (exhausted && row.active_downloads <= 0) {
    await deleteBundle(c.env, bundleId);
    return c.json({ ok: true, deleted: true });
  }
  return c.json({ ok: true, deleted: false });
});

app.get('/api/files/:token/files/:file/blob', async (c) => {
  const bundleId = await sha256Hex(c.req.param('token'));
  const grant = c.req.query('g') ?? '';
  if (!(await verifyGrant(c.env.GRANT_SECRET, grant, bundleId, Date.now()))) {
    return c.json({ error: 'ダウンロード権限がありません' }, 403);
  }

  const fileIndex = Number(c.req.param('file'));
  if (!Number.isInteger(fileIndex) || fileIndex < 0) {
    return c.json({ error: 'ファイル番号が不正です' }, 400);
  }

  const row = await c.env.DB.prepare(
    `SELECT r2_key, cipher_size FROM bundle_files WHERE bundle_id = ? AND file_index = ?`,
  )
    .bind(bundleId, fileIndex)
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
  let bundle: BundleRow;
  try {
    bundle = await authorize(c.env, c.req.param('token'), body.authToken);
  } catch (err) {
    const res = errorResponse(err);
    if (res) return res;
    throw err;
  }
  await deleteBundle(c.env, bundle.id);
  return c.json({ ok: true });
});

async function deleteBundle(env: Env, bundleId: string): Promise<void> {
  const files = await env.DB.prepare(`SELECT r2_key FROM bundle_files WHERE bundle_id = ?`)
    .bind(bundleId)
    .all<{ r2_key: string }>();
  for (const file of files.results) {
    await env.BUCKET.delete(file.r2_key);
  }
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM bundle_files WHERE bundle_id = ?`).bind(bundleId),
    env.DB.prepare(`DELETE FROM bundles WHERE id = ?`).bind(bundleId),
  ]);
}

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

export async function purge(
  env: Env,
  now = Date.now(),
): Promise<{ bundles: number; uploads: number }> {
  const grace = downloadGraceMs(env);
  // 期限切れ、またはダウンロード上限に達したもの。
  // 上限到達後は finish 通知（アクティブ 0）で即座に、
  // 通知が来ない場合も ping の途絶から猶予時間で削除する。
  const expired = await env.DB.prepare(
    `SELECT id FROM bundles
      WHERE expires_at <= ?
         OR (max_downloads IS NOT NULL
             AND download_count >= max_downloads
             AND (active_downloads <= 0
                  OR last_activity_at IS NULL
                  OR last_activity_at + ? <= ?))
      LIMIT 200`,
  )
    .bind(now, grace, now)
    .all<{ id: string }>();

  for (const row of expired.results) {
    await deleteBundle(env, row.id);
  }

  // 放棄されたアップロードセッション
  const stale = await env.DB.prepare(`SELECT id FROM uploads WHERE abandon_at <= ? LIMIT 100`)
    .bind(now)
    .all<{ id: string }>();

  for (const row of stale.results) {
    const files = await env.DB.prepare(
      `SELECT r2_key, r2_upload_id FROM upload_files WHERE upload_id = ?`,
    )
      .bind(row.id)
      .all<{ r2_key: string; r2_upload_id: string }>();
    for (const file of files.results) {
      await env.BUCKET.resumeMultipartUpload(file.r2_key, file.r2_upload_id)
        .abort()
        .catch(() => undefined);
    }
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM upload_parts WHERE upload_id = ?`).bind(row.id),
      env.DB.prepare(`DELETE FROM upload_files WHERE upload_id = ?`).bind(row.id),
      env.DB.prepare(`DELETE FROM uploads WHERE id = ?`).bind(row.id),
    ]);
  }

  return { bundles: expired.results.length, uploads: stale.results.length };
}

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(
      purge(env).then((result) => {
        console.log(`purged bundles=${result.bundles} uploads=${result.uploads}`);
      }),
    );
  },
} satisfies ExportedHandler<Env>;

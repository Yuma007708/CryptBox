import { Hono } from 'hono';
import type { Env } from './env.js';
import {
  GRANT_TTL_MS,
  UPLOAD_TTL_MS,
  downloadGraceMs,
  maxFileSize,
  maxExpiryHours,
  allowedAppOrigins,
  receiptRetentionMs,
  turnstileSiteKey,
  turnstileHostnames,
  operatorName,
  operatorContact,
  reportRetentionDays,
} from './env.js';
import {
  BadRequest,
  decodeFixed,
  isHash,
  randomBytes,
  sha256Hex,
  signGrant,
  signReceipt,
  timingSafeEqual,
  verifyGrant,
  verifyReceiptSignature,
} from './lib.js';
import {
  FILE_TOKEN_BYTES,
  GCM_TAG_BYTES,
  KDF_SALT_BYTES,
  MAX_FILES_PER_BUNDLE,
  NONCE_BYTES,
  NONCE_PREFIX_BYTES,
  PW_SALT_BYTES,
  cipherTotalSize,
  fromBase64Url,
  toBase64Url,
  totalChunks as computeChunks,
} from '../shared/format.js';
import { isDeletionReceiptShape, type DeletionReason, type DeletionReceipt } from '../shared/receipt.js';

/** R2 マルチパートの制約 */
const MIN_CHUNK_SIZE = 5 * 1024 * 1024;
const MAX_CHUNK_SIZE = 64 * 1024 * 1024;
const MAX_PARTS = 10000;

const app = new Hono<{ Bindings: Env }>();

/* ------------------------------------------------------------------ *
 * 共通
 * ------------------------------------------------------------------ */

/**
 * CORS: ブラウザ版は同一オリジンなので不要だが、
 * スマホアプリ (Capacitor) は capacitor://localhost 等から API を呼ぶ。
 * 許可リストにあるオリジンからの呼び出しにだけ CORS ヘッダーを返す。
 */
app.use('/api/*', async (c, next) => {
  const origin = c.req.header('origin');
  const allowed = origin !== undefined && allowedAppOrigins(c.env).has(origin);

  if (c.req.method === 'OPTIONS') {
    if (!allowed) return c.body(null, 403);
    return c.body(null, 204, {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, Range',
      'Access-Control-Max-Age': '86400',
      Vary: 'Origin',
    });
  }

  await next();
  c.res.headers.set('Cache-Control', 'no-store');
  c.res.headers.set('X-Content-Type-Options', 'nosniff');
  c.res.headers.set('Referrer-Policy', 'no-referrer');
  if (allowed) {
    c.res.headers.set('Access-Control-Allow-Origin', origin);
    c.res.headers.set('Access-Control-Expose-Headers', 'Content-Range, Content-Length, Accept-Ranges');
    c.res.headers.append('Vary', 'Origin');
  }
});

app.onError((err, c) => {
  if (err instanceof BadRequest) return c.json({ error: err.message }, 400);
  console.error('unhandled error', err);
  return c.json({ error: 'サーバー内部エラー' }, 500);
});

class NotFound extends Error {}
class Gone extends Error {
  constructor(
    message: string,
    readonly receipt: DeletionReceipt | null,
  ) {
    super(message);
  }
}

function errorResponse(err: unknown): Response | null {
  if (err instanceof NotFound) {
    return Response.json({ error: 'ファイルが見つかりません' }, { status: 404 });
  }
  if (err instanceof Gone) {
    return Response.json({ error: err.message, receipt: err.receipt }, { status: 410 });
  }
  return null;
}

/** `Authorization: Bearer <token>` からトークンを取り出す。スキームは大文字小文字を問わない */
function extractBearer(header: string): string {
  const match = /^bearer\s+(.*)$/i.exec(header);
  return match ? match[1]! : '';
}

/** アップロード API を閉じたい場合は UPLOAD_TOKEN を設定する */
function assertUploadAllowed(c: { req: { header: (name: string) => string | undefined }; env: Env }) {
  const expected = c.env.UPLOAD_TOKEN;
  if (!expected) return;
  const presented = extractBearer(c.req.header('authorization') ?? '');
  if (!timingSafeEqual(presented, expected)) throw new BadRequest('アップロードが許可されていません');
}

/** siteverify のレスポンス形。ドキュメントに無いフィールドを送ってくることもあるので緩めに扱う */
interface SiteverifyResponse {
  success?: boolean;
  hostname?: string;
  action?: string;
  'error-codes'?: string[];
}

/** siteverify に送るトークンの長さ上限。Turnstile のトークンはこれより大幅に短い */
const MAX_TOKEN_LENGTH = 2048;

/**
 * Cloudflare Turnstile のトークンを検証する。
 * `TURNSTILE_SECRET` が未設定、または `TURNSTILE_SITE_KEY` が未設定（クライアントに
 * サイトキーを配っていない = そもそもトークンを送れない片肺状態）なら検証をスキップする
 * （開発・セルフホストの既定）。
 * ネットワークエラー・応答不正はすべて失敗（false）として扱う（fail-closed）。
 */
async function verifyTurnstile(
  env: Env,
  token: unknown,
  remoteIp: string | undefined,
): Promise<boolean> {
  const secret = env.TURNSTILE_SECRET;
  if (!secret) return true;
  if (!turnstileSiteKey(env)) return true;
  if (typeof token !== 'string' || token.length === 0) return false;
  if (token.length > MAX_TOKEN_LENGTH) return false;

  const form = new URLSearchParams({ secret, response: token });
  if (remoteIp) form.set('remoteip', remoteIp);

  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return false;
    const result = (await res.json()) as SiteverifyResponse;
    if (result.success !== true) {
      if (result['error-codes']?.length) {
        console.warn('Turnstile siteverify failed', result['error-codes']);
      }
      return false;
    }

    const allowedHostnames = turnstileHostnames(env);
    if (allowedHostnames && !(result.hostname !== undefined && allowedHostnames.has(result.hostname))) {
      console.warn('Turnstile siteverify hostname mismatch', result.hostname);
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * IP あたりの回数を絞る（Workers Rate Limiting）。
 * `limiter` が無ければ（ローカル・セルフホストの既定）制限しない。
 */
async function checkRateLimit(
  c: { req: { header: (name: string) => string | undefined }; env: Env },
  limiter: RateLimit | undefined,
): Promise<boolean> {
  if (!limiter) return true;
  const key = rateLimitKey(c.req.header('cf-connecting-ip'));
  const { success } = await limiter.limit({ key });
  return success;
}

/**
 * レート制限のキーに使う IP の正規化。
 * IPv6 はホスト部が可変（同一利用者でも接続のたびに変わりうる）ため /64 プレフィックスに丸める。
 * IPv4 やパース不能な値はそのまま使う。
 */
export function rateLimitKey(ip: string | undefined): string {
  // 本番では Cloudflare が cf-connecting-ip を必ず付与するため、ここに来ることはない。
  // 到達した場合は前段の構成（プロキシ・ローカル実行）に異常があるということ。
  if (!ip) return 'unknown';
  if (!ip.includes(':')) return ip;

  const hextets = ip.split(':');
  // "::" 短縮を含む IPv6 を /64 (先頭 4 hextet) に丸める。
  // 短縮が無ければ先頭 4 個、あれば "::" より前の hextet を優先する。
  const doubleColonIndex = ip.indexOf('::');
  let prefixHextets: string[];
  if (doubleColonIndex !== -1) {
    const before = ip.slice(0, doubleColonIndex).split(':').filter(Boolean);
    prefixHextets = [...before, ...Array(4).fill('0')].slice(0, 4);
  } else {
    prefixHextets = hextets.slice(0, 4);
  }
  return `${prefixHextets.join(':')}::/64`;
}

/**
 * 運営者による無効化 API (`/api/admin/*`) を保護する。
 * `ADMIN_TOKEN` 未設定、または `Authorization: Bearer` が一致しなければ
 * エンドポイント自体が存在しないかのように 404 を返す。
 * 提示値・期待値の両方を SHA-256 で固定長にしてから比較する
 * （timingSafeEqual は長さが違うと即 false を返すため、長さの違いが漏れるのを防ぐ）。
 */
async function checkAdminAuth(c: { req: { header: (name: string) => string | undefined }; env: Env }): Promise<boolean> {
  const expected = c.env.ADMIN_TOKEN;
  if (!expected) return false;
  const presented = extractBearer(c.req.header('authorization') ?? '');
  const [presentedHash, expectedHash] = await Promise.all([sha256Hex(presented), sha256Hex(expected)]);
  return timingSafeEqual(presentedHash, expectedHash);
}

const REPORT_REASONS = new Set(['malware', 'illegal', 'copyright', 'other']);

/** 通報の detail の最大文字数（コードポイント数え） */
const MAX_DETAIL_CODEPOINTS = 500;

/**
 * 制御文字 (Cc) とサロゲート単体 (Cs) を空白に置換する。改行 (\n) だけは残す。
 * 通報の detail は自由入力なので、ログ・DB に制御文字が紛れ込むのを防ぐ。
 */
function sanitizeDetail(raw: string): string {
  return raw.replace(/[\p{Cc}\p{Cs}]/gu, (ch) => (ch === '\n' ? ch : ' '));
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

/**
 * このホストの上限値を公開する。セルフホストでは環境変数で変わるため、
 * クライアントはビルド時の定数ではなくこの値を表示に使う。
 */
app.get('/api/config', (c) => {
  return c.json({
    maxFileSize: maxFileSize(c.env),
    maxExpiryHours: maxExpiryHours(c.env),
    turnstileSiteKey: turnstileSiteKey(c.env),
    operatorName: operatorName(c.env),
    operatorContact: operatorContact(c.env),
  });
});

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

  if (!(await checkRateLimit(c, c.env.UPLOAD_LIMITER))) {
    return c.json(
      { error: 'アップロードが多すぎます。しばらくしてから再度お試しください' },
      429,
      { 'Retry-After': '60' },
    );
  }

  const body = await readJson(c.req.raw);

  if (!(await verifyTurnstile(c.env, body.turnstileToken, c.req.header('cf-connecting-ip')))) {
    return c.json({ error: '認証に失敗しました。ページを再読み込みしてもう一度お試しください' }, 403);
  }

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
  const maxExpirySeconds = maxExpiryHours(c.env) * 3600;
  if (expiresIn <= 0 || expiresIn > maxExpirySeconds) {
    throw new BadRequest(`有効期限が不正です (上限 ${maxExpiryHours(c.env)} 時間)`);
  }

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
    const { receipt } = await deleteBundle(env, row.id, 'expired');
    throw new Gone('有効期限が切れています', receipt);
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
    const { receipt } = await deleteBundle(c.env, bundleId, 'limit_reached');
    return c.json({ ok: true, deleted: true, receipt });
  }
  return c.json({ ok: true, deleted: false });
});

/**
 * バンドルの削除レシートを取得する。
 * 共有 URL のパス部分（トークン）はログや Referer に残り得るため、他のエンドポイントと
 * 同様に authToken（フラグメントの鍵からしか作れない）も必須にする。
 */
app.post('/api/files/:token/receipt', async (c) => {
  const body = await readJson(c.req.raw);
  const notFound = () => c.json({ error: 'ファイルが見つかりません' }, 404);

  if (typeof body.authToken !== 'string') return notFound();
  let presented: string;
  try {
    presented = await sha256Hex(fromBase64Url(body.authToken));
  } catch {
    return notFound();
  }

  const bundleId = await sha256Hex(c.req.param('token'));

  const receiptRow = await c.env.DB.prepare(
    `SELECT bundle_id, created_at, deleted_at, reason, file_count, total_plain_size, signature, auth_hash
       FROM deletion_receipts WHERE bundle_id = ?`,
  )
    .bind(bundleId)
    .first<{
      bundle_id: string;
      created_at: number;
      deleted_at: number;
      reason: DeletionReason;
      file_count: number;
      total_plain_size: number;
      signature: string;
      auth_hash: string;
    }>();

  if (receiptRow) {
    if (!timingSafeEqual(presented, receiptRow.auth_hash)) return notFound();
    const receipt: DeletionReceipt = {
      version: 1,
      bundleId: receiptRow.bundle_id,
      createdAt: receiptRow.created_at,
      deletedAt: receiptRow.deleted_at,
      reason: receiptRow.reason,
      fileCount: receiptRow.file_count,
      totalPlainSize: receiptRow.total_plain_size,
      signature: receiptRow.signature,
    };
    return c.json({ deleted: true, receipt });
  }

  const bundle = await c.env.DB.prepare(`SELECT id, auth_hash FROM bundles WHERE id = ?`)
    .bind(bundleId)
    .first<{ id: string; auth_hash: string }>();
  if (bundle) {
    if (!timingSafeEqual(presented, bundle.auth_hash)) return notFound();
    return c.json({ deleted: false });
  }

  return notFound();
});

/** 削除レシートの署名検証。DB は見ず、署名を再計算するだけ */
app.post('/api/receipts/verify', async (c) => {
  const body = await readJson(c.req.raw);
  const candidate = body.receipt;
  if (!isDeletionReceiptShape(candidate)) return c.json({ valid: false });
  const valid = await verifyReceiptSignature(c.env.GRANT_SECRET, candidate);
  return c.json({ valid });
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
  const result = await deleteBundle(c.env, bundle.id, 'sender_deleted');
  if (!result.ok) {
    // R2 の削除が一部失敗。D1 の行はまだ残っているので、そのまま再試行すればよい（冪等）
    return c.json({ ok: false, pending: result.pending }, 500);
  }
  return c.json({ ok: true, receipt: result.receipt });
});

interface DeleteBundleResult {
  /** true なら R2 の全ファイルと D1 とも削除済み。false なら一部の R2 削除が失敗し、D1 はまだ残っている */
  ok: boolean;
  /** 削除に失敗した r2_key。ok:true なら空配列 */
  pending: string[];
  /** ok:true のときのレシート。bundles 行が既に存在しない（二重削除）場合は null */
  receipt: DeletionReceipt | null;
}

/**
 * バンドルを R2 + D1 から完全削除する。冪等（同じ bundleId に何度呼んでもよい）。
 * R2 の削除が 1 件でも失敗したら D1 の行は消さず、失敗したキーを pending として返す
 * （中途半端に D1 だけ消えて R2 に孤児オブジェクトが残る事態を避ける）。
 * R2 が全件消えたときだけ、同じ DB.batch 内で D1 削除と削除レシートの INSERT を行う。
 */
async function deleteBundle(
  env: Env,
  bundleId: string,
  reason: DeletionReason,
): Promise<DeleteBundleResult> {
  const bundle = await env.DB.prepare(
    `SELECT created_at, file_count, total_plain_size, auth_hash FROM bundles WHERE id = ?`,
  )
    .bind(bundleId)
    .first<{ created_at: number; file_count: number; total_plain_size: number; auth_hash: string }>();

  const files = await env.DB.prepare(`SELECT r2_key FROM bundle_files WHERE bundle_id = ?`)
    .bind(bundleId)
    .all<{ r2_key: string }>();

  const pending: string[] = [];
  for (const file of files.results) {
    try {
      await env.BUCKET.delete(file.r2_key);
    } catch (err) {
      console.error(`R2 delete failed for ${file.r2_key}`, err);
      pending.push(file.r2_key);
    }
  }
  if (pending.length > 0) return { ok: false, pending, receipt: null };

  const statements = [
    env.DB.prepare(`DELETE FROM bundle_files WHERE bundle_id = ?`).bind(bundleId),
    env.DB.prepare(`DELETE FROM bundles WHERE id = ?`).bind(bundleId),
  ];

  let receipt: DeletionReceipt | null = null;
  if (bundle) {
    const unsigned = {
      version: 1 as const,
      bundleId,
      createdAt: bundle.created_at,
      deletedAt: Date.now(),
      reason,
      fileCount: bundle.file_count,
      totalPlainSize: bundle.total_plain_size,
    };
    const signature = await signReceipt(env.GRANT_SECRET, unsigned);
    receipt = { ...unsigned, signature };
    statements.push(
      env.DB.prepare(
        `INSERT INTO deletion_receipts
           (bundle_id, created_at, deleted_at, reason, file_count, total_plain_size, signature, auth_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (bundle_id) DO UPDATE SET
           deleted_at = excluded.deleted_at,
           reason = excluded.reason,
           file_count = excluded.file_count,
           total_plain_size = excluded.total_plain_size,
           signature = excluded.signature,
           auth_hash = excluded.auth_hash`,
      ).bind(
        bundleId,
        unsigned.createdAt,
        unsigned.deletedAt,
        reason,
        unsigned.fileCount,
        unsigned.totalPlainSize,
        signature,
        bundle.auth_hash,
      ),
    );
  }

  await env.DB.batch(statements);
  return { ok: true, pending: [], receipt };
}

/* ------------------------------------------------------------------ *
 * 通報 / 運営者による無効化
 * ------------------------------------------------------------------ */

/**
 * 受信ページからの通報。認証不要（通報者はリンクを持っているだけの人）。
 * 存在しないトークンでも同じ 200 を返す（存在オラクルにしない）。
 */
app.post('/api/files/:token/report', async (c) => {
  if (!(await checkRateLimit(c, c.env.REPORT_LIMITER))) {
    return c.json({ error: '通報が多すぎます。しばらくしてから再度お試しください' }, 429);
  }

  const contentType = c.req.header('content-type') ?? '';
  if (!contentType.toLowerCase().startsWith('application/json')) {
    return c.json({ error: 'Content-Type は application/json にしてください' }, 415);
  }

  const body = await readJson(c.req.raw);
  if (typeof body.reason !== 'string' || !REPORT_REASONS.has(body.reason)) {
    throw new BadRequest('reason が不正です');
  }
  let detail: string | null = null;
  if (body.detail !== undefined && body.detail !== null) {
    if (typeof body.detail !== 'string' || [...body.detail].length > MAX_DETAIL_CODEPOINTS) {
      throw new BadRequest(`detail が不正です（${MAX_DETAIL_CODEPOINTS} 文字まで）`);
    }
    detail = sanitizeDetail(body.detail);
  }

  const bundleId = await sha256Hex(c.req.param('token'));
  // 同一バンドル・同一理由への通報は 1 行に集約し、件数だけ増やす。
  // これにより行数は理由の種類数（4）で自然に上限化され、明示的な件数上限は不要。
  // 応答パスにはバンドルの存在チェックを入れない（存在オラクルにしない）。
  await c.env.DB.prepare(
    `INSERT INTO reports (bundle_id, reason, detail, reported_at) VALUES (?, ?, ?, ?)
     ON CONFLICT (bundle_id, reason) DO UPDATE SET
       count = count + 1,
       reported_at = excluded.reported_at,
       detail = COALESCE(reports.detail, excluded.detail),
       handled_at = NULL`,
  )
    .bind(bundleId, body.reason, detail, Date.now())
    .run();

  return c.json({ ok: true });
});

interface ReportRow {
  id: number;
  bundle_id: string;
  reason: string;
  /** 通報者入力の untrusted な文字列。UI に出す場合はエスケープ必須 */
  detail: string | null;
  count: number;
  reported_at: number;
}

/** 運営者向け: 未処理の通報一覧を新しい順に返す */
app.get('/api/admin/reports', async (c) => {
  if (!(await checkAdminAuth(c))) return c.json({ error: 'Not Found' }, 404);

  const requested = Number(c.req.query('limit') ?? '50');
  const limit = Number.isInteger(requested) && requested > 0 && requested <= 200 ? requested : 50;

  const rows = await c.env.DB.prepare(
    `SELECT id, bundle_id, reason, detail, count, reported_at FROM reports
      WHERE handled_at IS NULL
      ORDER BY reported_at DESC
      LIMIT ?`,
  )
    .bind(limit)
    .all<ReportRow>();

  return c.json({
    reports: rows.results.map((row) => ({
      id: row.id,
      bundleId: row.bundle_id,
      reason: row.reason,
      detail: row.detail,
      count: row.count,
      reportedAt: row.reported_at,
    })),
  });
});

/**
 * 運営者向け: 中身を見ずにリンク単位でバンドルを即時完全削除する。
 * 削除に成功したら、同じバンドルへの未処理の通報を処理済みにする。
 * R2 の削除が一部失敗した場合は D1 を消さず `{ ok: false, deleted: false, pending }` を返す
 * （500 にはしない）。takedown は冪等なので、そのまま再実行すればよい。
 */
app.post('/api/admin/takedown', async (c) => {
  if (!(await checkAdminAuth(c))) return c.json({ error: 'Not Found' }, 404);

  const body = await readJson(c.req.raw);
  if (!isHash(body.bundleId)) throw new BadRequest('bundleId が不正です');

  const existing = await c.env.DB.prepare(`SELECT id FROM bundles WHERE id = ?`)
    .bind(body.bundleId)
    .first<{ id: string }>();

  let deleted = false;
  if (existing) {
    const result = await deleteBundle(c.env, body.bundleId, 'takedown');
    if (!result.ok) {
      // R2 の削除が一部失敗。D1 の行はまだ残っているので、そのまま再試行すればよい（冪等）
      return c.json({ ok: false, deleted: false, pending: result.pending });
    }
    deleted = true;
    console.log(`takedown bundleId=${body.bundleId} at=${new Date().toISOString()}`);
    await c.env.DB.prepare(
      `UPDATE reports SET handled_at = ? WHERE bundle_id = ? AND handled_at IS NULL`,
    )
      .bind(Date.now(), body.bundleId)
      .run();
  }

  return c.json({ ok: true, deleted });
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

/** D1 (SQLite) の 1 クエリあたりの変数上限に収まるチャンクサイズ */
const DELETE_CHUNK_SIZE = 100;

/** id の配列を `DELETE FROM <table> WHERE id IN (...)` で一括削除する（変数上限のためチャンク分割） */
async function deleteByIds(env: Env, table: 'reports', ids: number[]): Promise<void> {
  for (let offset = 0; offset < ids.length; offset += DELETE_CHUNK_SIZE) {
    const chunk = ids.slice(offset, offset + DELETE_CHUNK_SIZE);
    const placeholders = chunk.map(() => '?').join(',');
    await env.DB.prepare(`DELETE FROM ${table} WHERE id IN (${placeholders})`)
      .bind(...chunk)
      .run();
  }
}

export async function purge(
  env: Env,
  now = Date.now(),
): Promise<{ bundles: number; uploads: number; receipts: number; reports: number }> {
  const grace = downloadGraceMs(env);
  // 期限切れ、またはダウンロード上限に達したもの。
  // 上限到達後は finish 通知（アクティブ 0）で即座に、
  // 通知が来ない場合も ping の途絶から猶予時間で削除する。
  // reason は「期限切れ」を優先する（両方の条件を満たす場合もあり得るため）
  const expired = await env.DB.prepare(
    `SELECT id, CASE WHEN expires_at <= ? THEN 'expired' ELSE 'limit_reached' END AS reason
       FROM bundles
      WHERE expires_at <= ?
         OR (max_downloads IS NOT NULL
             AND download_count >= max_downloads
             AND (active_downloads <= 0
                  OR last_activity_at IS NULL
                  OR last_activity_at + ? <= ?))
      LIMIT 200`,
  )
    .bind(now, now, grace, now)
    .all<{ id: string; reason: DeletionReason }>();

  for (const row of expired.results) {
    await deleteBundle(env, row.id, row.reason);
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

  // 保持期間を過ぎた削除レシートを消す。バンドル側 (LIMIT 200) に揃えて
  // 1 回の cron で処理する件数を刻む。500 件を超える分は次回 cron に持ち越される
  const receiptCutoff = now - receiptRetentionMs(env);
  const purgedReceipts = await env.DB.prepare(
    `DELETE FROM deletion_receipts
      WHERE bundle_id IN (
        SELECT bundle_id FROM deletion_receipts WHERE deleted_at <= ? LIMIT 500
      )`,
  )
    .bind(receiptCutoff)
    .run();

  // 保持期間を超えた通報。分割削除（1 回の purge で最大 500 件）。
  // 残りは次回の Cron 実行で引き継がれる。
  const retentionCutoff = now - reportRetentionDays(env) * 24 * 60 * 60 * 1000;
  const oldReports = await env.DB.prepare(`SELECT id FROM reports WHERE reported_at <= ? LIMIT 500`)
    .bind(retentionCutoff)
    .all<{ id: number }>();
  await deleteByIds(env, 'reports', oldReports.results.map((row) => row.id));

  // バンドルが（takedown・期限切れ等で）既に消えている通報。応答パスでは存在チェックを
  // 一切しない（存在オラクルにしないため）ので、ここで定期的に掃除する。
  const orphanReports = await env.DB.prepare(
    `SELECT id FROM reports WHERE bundle_id NOT IN (SELECT id FROM bundles) LIMIT 500`,
  ).all<{ id: number }>();
  await deleteByIds(env, 'reports', orphanReports.results.map((row) => row.id));

  return {
    bundles: expired.results.length,
    uploads: stale.results.length,
    receipts: purgedReceipts.meta.changes ?? 0,
    reports: oldReports.results.length + orphanReports.results.length,
  };
}

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(
      purge(env).then((result) => {
        console.log(
          `purged bundles=${result.bundles} uploads=${result.uploads} receipts=${result.receipts} reports=${result.reports}`,
        );
      }),
    );
  },
} satisfies ExportedHandler<Env>;

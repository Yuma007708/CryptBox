import { toBase64Url, fromBase64Url, textEncoder } from '../shared/format.js';
import { receiptSigningString, type UnsignedDeletionReceipt } from '../shared/receipt.js';

/** getRandomValues は 1 回あたり 64 KiB までなので分割して埋める */
export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 65536) {
    crypto.getRandomValues(bytes.subarray(offset, Math.min(length, offset + 65536)));
  }
  return bytes;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function sha256Hex(input: Uint8Array | string): Promise<string> {
  const data = typeof input === 'string' ? textEncoder.encode(input) : input;
  const digest = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return toHex(new Uint8Array(digest));
}

/** 長さが等しい文字列を定数時間で比較する */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** base64url で表現された固定長のバイト列を検証しつつデコードする */
export function decodeFixed(value: unknown, length: number, field: string): Uint8Array {
  if (typeof value !== 'string') throw new BadRequest(`${field} が不正です`);
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(value);
  } catch {
    throw new BadRequest(`${field} が不正です`);
  }
  if (bytes.length !== length) throw new BadRequest(`${field} の長さが不正です`);
  return bytes;
}

export class BadRequest extends Error {
  readonly status = 400;
}

/** hex 表現の SHA-256 かどうか */
export function isHash(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

/** グラント / レシートの署名鍵が使える状態か。未設定・短すぎる鍵は署名を許さない */
export function isUsableSecret(secret: unknown, minLength: number): secret is string {
  return typeof secret === 'string' && secret.length >= minLength;
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  // 呼び出し側（リクエスト先頭のミドルウェア）で弾いているはずだが、
  // 「空の鍵で署名してしまう」ことだけは絶対に起こさない
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new Error('GRANT_SECRET is not configured');
  }
  return crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret) as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

/**
 * 鍵付きハッシュ (HMAC-SHA256) の hex。
 * `sha256(message + secret)` と違い長さ延長攻撃の余地がなく、鍵と本文の
 * 境界も曖昧にならないため、IP のような短い入力の匿名化にはこちらを使う。
 */
export async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, textEncoder.encode(message) as BufferSource);
  return toHex(new Uint8Array(sig));
}

/** グラントに埋め込む一意 ID (jti) のバイト数 */
export const GRANT_JTI_BYTES = 16;

/**
 * ダウンロードグラント: ダウンロード回数を消費した証明。
 * これを持つ間は回数を再消費せずにレンジ取得・再開ができる。
 *
 * 形式: `<fileId>.<expiresAt>.<jti>.<signature>`
 * jti は 16 バイトの乱数で、`/finish` が「同じグラントでの二重の完了通知」を
 * 弾くための一意キーになる（grant_uses テーブル）。
 */
export async function signGrant(secret: string, fileId: string, expiresAt: number): Promise<string> {
  const jti = toBase64Url(randomBytes(GRANT_JTI_BYTES));
  const payload = `${fileId}.${expiresAt}.${jti}`;
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, textEncoder.encode(payload) as BufferSource);
  return `${payload}.${toBase64Url(new Uint8Array(sig))}`;
}

/**
 * グラントを検証し、有効なら jti を返す（無効なら null）。
 * 呼び出し側は jti を使って二重消費を判定できる。
 */
export async function verifyGrant(
  secret: string,
  grant: string,
  fileId: string,
  now: number,
): Promise<string | null> {
  const parts = grant.split('.');
  if (parts.length !== 4) return null;
  const [id, expText, jti, sig] = parts;
  if (!timingSafeEqual(id!, fileId)) return null;
  if (!jti) return null;
  const expiresAt = Number(expText);
  if (!Number.isFinite(expiresAt) || expiresAt <= now) return null;
  const key = await hmacKey(secret);
  let signature: Uint8Array;
  try {
    signature = fromBase64Url(sig!);
  } catch {
    return null;
  }
  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    signature as BufferSource,
    textEncoder.encode(`${id}.${expText}.${jti}`) as BufferSource,
  );
  return valid ? jti : null;
}

/**
 * 削除レシートの署名鍵は GRANT_SECRET から HKDF-SHA256 で分けて派生させる。
 * グラント署名（生の GRANT_SECRET を HMAC 鍵に使う）とは別系統にすることで、
 * レシート鍵が漏れてもグラント鍵は復元できない（HKDF は一方向）。
 * ただし GRANT_SECRET 自体が漏れた場合はグラント署名・レシート署名の両方が影響を受ける。
 */
const RECEIPT_HKDF_INFO = 'cryptbox/receipt';

async function receiptHmacKey(secret: string): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret) as BufferSource,
    'HKDF',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: textEncoder.encode(RECEIPT_HKDF_INFO) as BufferSource,
    },
    ikm,
    256,
  );
  return crypto.subtle.importKey('raw', bits, { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ]);
}

export async function signReceipt(
  secret: string,
  receipt: UnsignedDeletionReceipt,
): Promise<string> {
  const key = await receiptHmacKey(secret);
  const sig = await crypto.subtle.sign(
    'HMAC',
    key,
    textEncoder.encode(receiptSigningString(receipt)) as BufferSource,
  );
  return toBase64Url(new Uint8Array(sig));
}

/** 署名を再計算して比較する（定数時間） */
export async function verifyReceiptSignature(
  secret: string,
  receipt: UnsignedDeletionReceipt & { signature: string },
): Promise<boolean> {
  const expected = await signReceipt(secret, receipt);
  return timingSafeEqual(expected, receipt.signature);
}

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

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret) as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

/**
 * ダウンロードグラント: ダウンロード回数を消費した証明。
 * これを持つ間は回数を再消費せずにレンジ取得・再開ができる。
 */
export async function signGrant(secret: string, fileId: string, expiresAt: number): Promise<string> {
  const payload = `${fileId}.${expiresAt}`;
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, textEncoder.encode(payload) as BufferSource);
  return `${payload}.${toBase64Url(new Uint8Array(sig))}`;
}

export async function verifyGrant(
  secret: string,
  grant: string,
  fileId: string,
  now: number,
): Promise<boolean> {
  const parts = grant.split('.');
  if (parts.length !== 3) return false;
  const [id, expText, sig] = parts;
  if (!timingSafeEqual(id, fileId)) return false;
  const expiresAt = Number(expText);
  if (!Number.isFinite(expiresAt) || expiresAt <= now) return false;
  const key = await hmacKey(secret);
  let signature: Uint8Array;
  try {
    signature = fromBase64Url(sig);
  } catch {
    return false;
  }
  return crypto.subtle.verify(
    'HMAC',
    key,
    signature as BufferSource,
    textEncoder.encode(`${id}.${expText}`) as BufferSource,
  );
}

/**
 * 削除レシートの署名鍵は GRANT_SECRET から HKDF-SHA256 で分けて派生させる。
 * グラント署名（生の GRANT_SECRET を HMAC 鍵に使う）とは別系統にすることで、
 * どちらかの用途が変わっても互いに影響しない。
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

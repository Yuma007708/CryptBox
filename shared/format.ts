/**
 * CryptBox wire format v1
 *
 * すべての鍵素材はブラウザ内で生成・保持され、サーバーへは送信されない。
 * サーバーが保持するのは「暗号文」と「一方向ハッシュ」のみ。
 *
 *   linkSecret : 32B ランダム。URL のフラグメント (#) に載る = サーバーに届かない
 *   pwKey      : Argon2id(password, pwSalt) → 32B (パスワード指定時のみ)
 *   KEK        : HKDF-SHA256(ikm = linkSecret ‖ pwKey, salt = kdfSalt, info = "cryptbox/v1/kek")
 *   CEK        : 32B ランダム。ファイル本体を AES-256-GCM で暗号化する鍵
 *   wrappedCEK : AES-256-GCM(KEK) で包んだ CEK。サーバーに保存される
 *   authToken  : HKDF(linkSecret, info = "cryptbox/v1/auth")  → サーバーは SHA-256 のみ保持
 *   pwVerifier : HKDF(pwKey,      info = "cryptbox/v1/verify") → サーバーは SHA-256 のみ保持
 *
 * 本体は固定長チャンクごとに独立した AES-256-GCM で暗号化する。
 * チャンク番号と総チャンク数を AAD に束縛しているため、並べ替え・切り詰めは検知される。
 */

export const FORMAT_VERSION = 1;

/** 平文チャンクサイズ。R2 マルチパートの最小パートサイズ (5 MiB) を上回る必要がある */
export const DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024;

/** AES-GCM の認証タグ長 */
export const GCM_TAG_BYTES = 16;

/** AES-GCM の nonce 長 */
export const NONCE_BYTES = 12;

/** nonce = noncePrefix(4B) ‖ chunkIndex(8B, big endian) */
export const NONCE_PREFIX_BYTES = 4;

export const KEY_BYTES = 32;
export const LINK_SECRET_BYTES = 32;
export const KDF_SALT_BYTES = 32;
export const PW_SALT_BYTES = 16;
export const FILE_TOKEN_BYTES = 32;

export const HKDF_INFO = {
  kek: 'cryptbox/v1/kek',
  auth: 'cryptbox/v1/auth',
  verify: 'cryptbox/v1/verify',
} as const;

/**
 * authToken 導出用の固定ソルト。
 * kdfSalt はサーバー側にあり /info を叩かないと取得できないが、
 * その /info 自体が authToken を要求するため、ここだけは定数ソルトを使う。
 * ikm (linkSecret) が 256bit の乱数なので、ソルトが固定でも強度は落ちない。
 */
export const AUTH_SALT = 'cryptbox/v1/auth-salt';

export const AAD_LABEL = {
  cek: 'cryptbox/v1/cek',
  meta: 'cryptbox/v1/meta',
} as const;

/** Argon2id の既定パラメータ (OWASP 推奨 m=64MiB, t=3, p=1 相当) */
export const ARGON2_DEFAULTS = {
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 1,
  hashLength: KEY_BYTES,
} as const;

export interface Argon2Params {
  memoryKiB: number;
  iterations: number;
  parallelism: number;
  hashLength: number;
}

/** 有効期限の選択肢 (秒) */
export const EXPIRY_OPTIONS = [
  { label: '1時間', seconds: 60 * 60 },
  { label: '24時間', seconds: 60 * 60 * 24 },
  { label: '7日', seconds: 60 * 60 * 24 * 7 },
  { label: '30日', seconds: 60 * 60 * 24 * 30 },
] as const;

export const MAX_EXPIRY_SECONDS = 60 * 60 * 24 * 30;

/** 暗号化後のチャンク長 (末尾チャンク以外) */
export function cipherChunkSize(chunkSize: number): number {
  return chunkSize + GCM_TAG_BYTES;
}

/** 平文サイズから暗号文の総バイト数を求める */
export function cipherTotalSize(plainSize: number, chunkSize: number): number {
  const chunks = totalChunks(plainSize, chunkSize);
  return plainSize + chunks * GCM_TAG_BYTES;
}

export function totalChunks(plainSize: number, chunkSize: number): number {
  if (plainSize === 0) return 1;
  return Math.ceil(plainSize / chunkSize);
}

/** チャンク i の暗号文がファイル内で占める [start, end) を返す */
export function cipherChunkRange(
  index: number,
  chunkSize: number,
  plainSize: number,
): { start: number; end: number } {
  const full = cipherChunkSize(chunkSize);
  const start = index * full;
  const plainStart = index * chunkSize;
  const plainLen = Math.min(chunkSize, Math.max(0, plainSize - plainStart));
  return { start, end: start + plainLen + GCM_TAG_BYTES };
}

/** nonce を組み立てる: 4B 固定プレフィックス + 8B チャンク番号 */
export function chunkNonce(prefix: Uint8Array, index: number): Uint8Array {
  if (prefix.length !== NONCE_PREFIX_BYTES) {
    throw new Error(`nonce prefix must be ${NONCE_PREFIX_BYTES} bytes`);
  }
  const nonce = new Uint8Array(NONCE_BYTES);
  nonce.set(prefix, 0);
  new DataView(nonce.buffer).setBigUint64(NONCE_PREFIX_BYTES, BigInt(index), false);
  return nonce;
}

/** AAD = version(1B) ‖ chunkIndex(8B) ‖ totalChunks(8B) */
export function chunkAad(index: number, total: number): Uint8Array {
  const aad = new Uint8Array(17);
  aad[0] = FORMAT_VERSION;
  const view = new DataView(aad.buffer);
  view.setBigUint64(1, BigInt(index), false);
  view.setBigUint64(9, BigInt(total), false);
  return aad;
}

const B64_CHUNK = 0x8000;

export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += B64_CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + B64_CHUNK));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export const textEncoder = new TextEncoder();
export const textDecoder = new TextDecoder();

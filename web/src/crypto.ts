import { argon2id } from 'hash-wasm';
import {
  AAD_LABEL,
  ARGON2_DEFAULTS,
  type Argon2Params,
  AUTH_SALT,
  HKDF_INFO,
  KEY_BYTES,
  NONCE_BYTES,
  chunkAad,
  chunkNonce,
  textDecoder,
  textEncoder,
} from '../../shared/format.js';

export interface FileMeta {
  name: string;
  type: string;
  size: number;
}

export interface DerivedKeys {
  /** ファイル本体を暗号化する鍵をラップするための鍵 */
  kek: CryptoKey;
  /** パスワード検証値。パスワード未設定なら null */
  pwVerifier: Uint8Array | null;
}

/** getRandomValues は 1 回あたり 64 KiB までなので分割して埋める */
export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 65536) {
    crypto.getRandomValues(bytes.subarray(offset, Math.min(length, offset + 65536)));
  }
  return bytes;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  length = KEY_BYTES,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt as BufferSource,
      info: textEncoder.encode(info) as BufferSource,
    },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** Argon2id でパスワードを 32 バイトの鍵素材に伸長する */
export async function argon2Key(
  password: string,
  salt: Uint8Array,
  params: Argon2Params = ARGON2_DEFAULTS,
): Promise<Uint8Array> {
  return argon2id({
    password,
    salt,
    parallelism: params.parallelism,
    iterations: params.iterations,
    memorySize: params.memoryKiB,
    hashLength: params.hashLength,
    outputType: 'binary',
  });
}

/**
 * サーバーに提示する認証トークン。linkSecret だけから決まるので、
 * kdfSalt を取得する前（= /info を叩く前）に計算できる。
 */
export async function deriveAuthToken(linkSecret: Uint8Array): Promise<Uint8Array> {
  return hkdf(linkSecret, textEncoder.encode(AUTH_SALT), HKDF_INFO.auth);
}

/**
 * すでに伸長済みの鍵素材から鍵一式を導出する。
 * Argon2id を回さないので、テストや WASM が使えない環境から直接呼べる。
 */
export async function deriveKeysFromMaterial(options: {
  linkSecret: Uint8Array;
  kdfSalt: Uint8Array;
  pwKey?: Uint8Array | null;
}): Promise<DerivedKeys> {
  const { linkSecret, kdfSalt, pwKey } = options;
  const ikm = pwKey ? concat(linkSecret, pwKey) : linkSecret;
  const kekBytes = await hkdf(ikm, kdfSalt, HKDF_INFO.kek);
  const kek = await crypto.subtle.importKey('raw', kekBytes as BufferSource, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ]);
  return {
    kek,
    pwVerifier: pwKey ? await hkdf(pwKey, kdfSalt, HKDF_INFO.verify) : null,
  };
}

/**
 * リンクの秘密（URL フラグメント）と、任意のパスワードから鍵一式を導出する。
 * パスワードを付けた場合は「リンクを知っていること」と「パスワードを知っていること」
 * の両方が揃わないと復号できない。
 */
export async function deriveKeys(options: {
  linkSecret: Uint8Array;
  kdfSalt: Uint8Array;
  password?: string;
  pwSalt?: Uint8Array;
  pwParams?: Argon2Params;
}): Promise<DerivedKeys> {
  const { linkSecret, kdfSalt, password, pwSalt, pwParams } = options;
  let pwKey: Uint8Array | null = null;
  if (password) {
    if (!pwSalt) throw new Error('pwSalt が必要です');
    pwKey = await argon2Key(password, pwSalt, pwParams);
  }
  return deriveKeysFromMaterial({ linkSecret, kdfSalt, pwKey });
}

export async function importCek(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ]);
}

export async function wrapCek(kek: CryptoKey, cek: Uint8Array, nonce: Uint8Array): Promise<Uint8Array> {
  const cipher = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce as BufferSource,
      additionalData: textEncoder.encode(AAD_LABEL.cek) as BufferSource,
    },
    kek,
    cek as BufferSource,
  );
  return new Uint8Array(cipher);
}

export async function unwrapCek(
  kek: CryptoKey,
  wrapped: Uint8Array,
  nonce: Uint8Array,
): Promise<Uint8Array> {
  const raw = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce as BufferSource,
      additionalData: textEncoder.encode(AAD_LABEL.cek) as BufferSource,
    },
    kek,
    wrapped as BufferSource,
  );
  return new Uint8Array(raw);
}

/** ファイル名・MIME タイプもサーバーに見せないため CEK で暗号化する */
export async function encryptMeta(
  cek: CryptoKey,
  meta: FileMeta,
  nonce: Uint8Array,
): Promise<Uint8Array> {
  const cipher = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce as BufferSource,
      additionalData: textEncoder.encode(AAD_LABEL.meta) as BufferSource,
    },
    cek,
    textEncoder.encode(JSON.stringify(meta)) as BufferSource,
  );
  return new Uint8Array(cipher);
}

export async function decryptMeta(
  cek: CryptoKey,
  cipher: Uint8Array,
  nonce: Uint8Array,
): Promise<FileMeta> {
  const raw = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce as BufferSource,
      additionalData: textEncoder.encode(AAD_LABEL.meta) as BufferSource,
    },
    cek,
    cipher as BufferSource,
  );
  return JSON.parse(textDecoder.decode(raw)) as FileMeta;
}

export async function encryptChunk(
  cek: CryptoKey,
  plain: Uint8Array,
  noncePrefix: Uint8Array,
  index: number,
  total: number,
): Promise<Uint8Array> {
  const cipher = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: chunkNonce(noncePrefix, index) as BufferSource,
      additionalData: chunkAad(index, total) as BufferSource,
    },
    cek,
    plain as BufferSource,
  );
  return new Uint8Array(cipher);
}

export async function decryptChunk(
  cek: CryptoKey,
  cipher: Uint8Array,
  noncePrefix: Uint8Array,
  index: number,
  total: number,
): Promise<Uint8Array> {
  const plain = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: chunkNonce(noncePrefix, index) as BufferSource,
      additionalData: chunkAad(index, total) as BufferSource,
    },
    cek,
    cipher as BufferSource,
  );
  return new Uint8Array(plain);
}

export async function sha256Hex(input: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', input as BufferSource);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

export const NONCE_LENGTH = NONCE_BYTES;

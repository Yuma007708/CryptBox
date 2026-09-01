import { describe, expect, it } from 'vitest';
import {
  decryptChunk,
  decryptMeta,
  deriveAuthToken,
  deriveKeys,
  encryptChunk,
  encryptMeta,
  importCek,
  randomBytes,
  unwrapCek,
  wrapCek,
} from '../web/src/crypto.js';
import { KDF_SALT_BYTES, KEY_BYTES, LINK_SECRET_BYTES, NONCE_BYTES } from "../shared/format.js";

const linkSecret = randomBytes(LINK_SECRET_BYTES);
const kdfSalt = randomBytes(KDF_SALT_BYTES);

describe('鍵ラップ', () => {
  it('同じリンク秘密からは同じ KEK が導出され、CEK を往復できる', async () => {
    const keys = await deriveKeys({ linkSecret, kdfSalt });
    const cek = randomBytes(KEY_BYTES);
    const nonce = randomBytes(NONCE_BYTES);
    const wrapped = await wrapCek(keys.kek, cek, nonce);

    const again = await deriveKeys({ linkSecret, kdfSalt });
    expect(Array.from(await unwrapCek(again.kek, wrapped, nonce))).toEqual(Array.from(cek));
  });

  it('リンク秘密が違えば復号できない', async () => {
    const keys = await deriveKeys({ linkSecret, kdfSalt });
    const cek = randomBytes(KEY_BYTES);
    const nonce = randomBytes(NONCE_BYTES);
    const wrapped = await wrapCek(keys.kek, cek, nonce);

    const other = await deriveKeys({ linkSecret: randomBytes(LINK_SECRET_BYTES), kdfSalt });
    await expect(unwrapCek(other.kek, wrapped, nonce)).rejects.toThrow();
  });

  it('authToken はリンク秘密だけで決まる（kdfSalt に依存しない）', async () => {
    const a = await deriveAuthToken(linkSecret);
    const b = await deriveAuthToken(linkSecret);
    const c = await deriveAuthToken(randomBytes(LINK_SECRET_BYTES));
    expect(Array.from(a)).toEqual(Array.from(b));
    expect(Array.from(a)).not.toEqual(Array.from(c));
  });
});

describe('本体チャンクの暗号化', () => {
  const noncePrefix = randomBytes(4);

  it('往復して一致する', async () => {
    const cek = await importCek(randomBytes(KEY_BYTES));
    const plain = randomBytes(4096);
    const cipher = await encryptChunk(cek, plain, noncePrefix, 3, 10);
    expect(cipher.length).toBe(plain.length + 16);
    expect(Array.from(await decryptChunk(cek, cipher, noncePrefix, 3, 10))).toEqual(
      Array.from(plain),
    );
  });

  it('チャンクを入れ替えると検知される', async () => {
    const cek = await importCek(randomBytes(KEY_BYTES));
    const cipher = await encryptChunk(cek, randomBytes(64), noncePrefix, 3, 10);
    await expect(decryptChunk(cek, cipher, noncePrefix, 4, 10)).rejects.toThrow();
  });

  it('総チャンク数を偽ると検知される（切り詰め対策）', async () => {
    const cek = await importCek(randomBytes(KEY_BYTES));
    const cipher = await encryptChunk(cek, randomBytes(64), noncePrefix, 3, 10);
    await expect(decryptChunk(cek, cipher, noncePrefix, 3, 9)).rejects.toThrow();
  });

  it('1 バイト改ざんすると検知される', async () => {
    const cek = await importCek(randomBytes(KEY_BYTES));
    const cipher = await encryptChunk(cek, randomBytes(64), noncePrefix, 0, 1);
    cipher[5] ^= 0x01;
    await expect(decryptChunk(cek, cipher, noncePrefix, 0, 1)).rejects.toThrow();
  });
});

describe('メタデータの暗号化', () => {
  it('ファイル名を往復できる', async () => {
    const cek = await importCek(randomBytes(KEY_BYTES));
    const nonce = randomBytes(NONCE_BYTES);
    const meta = { name: '決算資料 2026年度.mov', type: 'video/quicktime', size: 12345 };
    const cipher = await encryptMeta(cek, meta, nonce);
    expect(await decryptMeta(cek, cipher, nonce)).toEqual(meta);
  });
});

import { describe, expect, it } from 'vitest';
import { argon2Key, deriveKeys, randomBytes, unwrapCek, wrapCek } from '../../web/src/crypto.js';
import { KDF_SALT_BYTES, KEY_BYTES, LINK_SECRET_BYTES, NONCE_BYTES, PW_SALT_BYTES } from '../../shared/format.js';

const linkSecret = randomBytes(LINK_SECRET_BYTES);
const kdfSalt = randomBytes(KDF_SALT_BYTES);

describe('Argon2id', () => {
  it('同じ入力からは同じ鍵、ソルトが違えば別の鍵になる', async () => {
    const salt = randomBytes(PW_SALT_BYTES);
    const params = { memoryKiB: 1024, iterations: 1, parallelism: 1, hashLength: 32 };
    const a = await argon2Key('correct horse', salt, params);
    const b = await argon2Key('correct horse', salt, params);
    const c = await argon2Key('correct horse', randomBytes(PW_SALT_BYTES), params);
    expect(a).toHaveLength(32);
    expect(Array.from(a)).toEqual(Array.from(b));
    expect(Array.from(a)).not.toEqual(Array.from(c));
  });
});

describe('パスワード（Argon2id）', () => {
  it('正しいパスワードでのみ CEK を取り出せる', async () => {
    const pwSalt = randomBytes(16);
    const params = { memoryKiB: 1024, iterations: 1, parallelism: 1, hashLength: 32 };
    const keys = await deriveKeys({ linkSecret, kdfSalt, password: 'correct horse', pwSalt, pwParams: params });
    const cek = randomBytes(KEY_BYTES);
    const nonce = randomBytes(NONCE_BYTES);
    const wrapped = await wrapCek(keys.kek, cek, nonce);

    const good = await deriveKeys({ linkSecret, kdfSalt, password: 'correct horse', pwSalt, pwParams: params });
    expect(Array.from(await unwrapCek(good.kek, wrapped, nonce))).toEqual(Array.from(cek));

    const bad = await deriveKeys({ linkSecret, kdfSalt, password: 'wrong horse', pwSalt, pwParams: params });
    await expect(unwrapCek(bad.kek, wrapped, nonce)).rejects.toThrow();
  });

  it('リンク秘密だけでは復号できない（二要素になっている）', async () => {
    const pwSalt = randomBytes(16);
    const params = { memoryKiB: 1024, iterations: 1, parallelism: 1, hashLength: 32 };
    const withPassword = await deriveKeys({ linkSecret, kdfSalt, password: 'pw', pwSalt, pwParams: params });
    const cek = randomBytes(KEY_BYTES);
    const nonce = randomBytes(NONCE_BYTES);
    const wrapped = await wrapCek(withPassword.kek, cek, nonce);

    const linkOnly = await deriveKeys({ linkSecret, kdfSalt });
    await expect(unwrapCek(linkOnly.kek, wrapped, nonce)).rejects.toThrow();
  });
});

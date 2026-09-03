import { describe, expect, it } from 'vitest';
import { signReceipt } from '../src/lib.js';
import {
  isDeletionReceiptShape,
  receiptSigningString,
  type UnsignedDeletionReceipt,
} from '../shared/receipt.js';

const base: UnsignedDeletionReceipt = {
  version: 1,
  bundleId: 'abc123',
  createdAt: 1000,
  deletedAt: 2000,
  reason: 'expired',
  fileCount: 3,
  totalPlainSize: 4096,
};

describe('receiptSigningString', () => {
  it('フィールド順序が固定された正規化文字列を作る', () => {
    expect(receiptSigningString(base)).toBe('v1|abc123|1000|2000|expired|3|4096');
  });

  it('いずれかのフィールドが変わると文字列も変わる（署名対象として安全）', () => {
    const original = receiptSigningString(base);
    expect(receiptSigningString({ ...base, reason: 'limit_reached' })).not.toBe(original);
    expect(receiptSigningString({ ...base, deletedAt: 2001 })).not.toBe(original);
    expect(receiptSigningString({ ...base, fileCount: 4 })).not.toBe(original);
    expect(receiptSigningString({ ...base, totalPlainSize: 4097 })).not.toBe(original);
    expect(receiptSigningString({ ...base, bundleId: 'other' })).not.toBe(original);
  });
});

describe('signReceipt（既知応答テスト）', () => {
  it('固定 secret と固定レシートに対する署名はこの値で固定される', async () => {
    // 鍵導出の契約（HKDF-SHA256, salt = 空, info = "cryptbox/receipt"）を固定する既知応答テスト。
    // 鍵導出（HKDF の salt/info や HMAC の方式）を変えるとこのテストが落ちる。
    // それは同時に、変更前に発行済みのレシートが以後は検証不能になる（valid: false）ことを意味する。
    // 変えるときはこの事実を認識した上で、意図的に期待値を更新すること。
    const fixed: UnsignedDeletionReceipt = {
      version: 1,
      bundleId: 'known-answer-bundle-id',
      createdAt: 1700000000000,
      deletedAt: 1700000100000,
      reason: 'sender_deleted',
      fileCount: 2,
      totalPlainSize: 123456,
    };
    const signature = await signReceipt('test-secret', fixed);
    expect(signature).toBe('WDFa8YJs6wGGoTl2wOpisSxpcYrIfrDDTkhXLffpnIg');
  });
});

describe('isDeletionReceiptShape', () => {
  it('正しい形なら true', () => {
    expect(isDeletionReceiptShape({ ...base, signature: 'sig' })).toBe(true);
  });

  it('欠落・型不正・不正な reason は false', () => {
    expect(isDeletionReceiptShape({})).toBe(false);
    expect(isDeletionReceiptShape(null)).toBe(false);
    expect(isDeletionReceiptShape({ ...base, signature: 'sig', version: 2 })).toBe(false);
    expect(isDeletionReceiptShape({ ...base, signature: 'sig', reason: 'unknown' })).toBe(false);
    expect(isDeletionReceiptShape({ ...base, signature: 'sig', fileCount: -1 })).toBe(false);
    expect(isDeletionReceiptShape({ ...base, signature: '' })).toBe(false);
  });

  it('-0 は非負整数として弾く（Object.is(-0, 0) は true だが符号付きゼロは不正値として扱う）', () => {
    expect(isDeletionReceiptShape({ ...base, signature: 'sig', createdAt: -0 })).toBe(false);
    expect(isDeletionReceiptShape({ ...base, signature: 'sig', deletedAt: -0 })).toBe(false);
    expect(isDeletionReceiptShape({ ...base, signature: 'sig', fileCount: -0 })).toBe(false);
    expect(isDeletionReceiptShape({ ...base, signature: 'sig', totalPlainSize: -0 })).toBe(false);
  });
});

import { describe, expect, it } from 'vitest';
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
});

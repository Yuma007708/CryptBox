import { describe, expect, it } from 'vitest';
import {
  GCM_TAG_BYTES,
  chunkAad,
  chunkNonce,
  cipherChunkRange,
  cipherTotalSize,
  fromBase64Url,
  toBase64Url,
  totalChunks,
} from '../shared/format.js';

describe('チャンク分割の算術', () => {
  it('端数のないサイズ', () => {
    expect(totalChunks(1024, 256)).toBe(4);
    expect(cipherTotalSize(1024, 256)).toBe(1024 + 4 * GCM_TAG_BYTES);
  });

  it('端数のあるサイズ', () => {
    expect(totalChunks(1000, 256)).toBe(4);
    expect(cipherTotalSize(1000, 256)).toBe(1000 + 4 * GCM_TAG_BYTES);
  });

  it('空ファイルでも 1 チャンク扱い', () => {
    expect(totalChunks(0, 256)).toBe(1);
    expect(cipherTotalSize(0, 256)).toBe(GCM_TAG_BYTES);
  });

  it('チャンクの範囲は隙間なく連続する', () => {
    const plainSize = 1000;
    const chunkSize = 256;
    let previousEnd = 0;
    for (let i = 0; i < totalChunks(plainSize, chunkSize); i++) {
      const range = cipherChunkRange(i, chunkSize, plainSize);
      expect(range.start).toBe(previousEnd);
      previousEnd = range.end;
    }
    expect(previousEnd).toBe(cipherTotalSize(plainSize, chunkSize));
  });
});

describe('nonce と AAD', () => {
  it('チャンクごとに nonce が変わる', () => {
    const prefix = new Uint8Array([1, 2, 3, 4]);
    expect(toBase64Url(chunkNonce(prefix, 0))).not.toBe(toBase64Url(chunkNonce(prefix, 1)));
    expect(chunkNonce(prefix, 7)).toHaveLength(12);
  });

  it('AAD にチャンク番号と総数が入る', () => {
    expect(toBase64Url(chunkAad(0, 4))).not.toBe(toBase64Url(chunkAad(0, 5)));
    expect(toBase64Url(chunkAad(1, 4))).not.toBe(toBase64Url(chunkAad(2, 4)));
  });
});

describe('base64url', () => {
  it('往復して一致する', () => {
    const bytes = new Uint8Array(300);
    crypto.getRandomValues(bytes);
    expect(Array.from(fromBase64Url(toBase64Url(bytes)))).toEqual(Array.from(bytes));
  });

  it('URL に安全な文字だけを使う', () => {
    const bytes = new Uint8Array([251, 255, 190, 239]);
    expect(toBase64Url(bytes)).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

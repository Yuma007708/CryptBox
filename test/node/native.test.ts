import { describe, expect, it } from 'vitest';
import { safeName, toBase64 } from '../../web/src/native.js';

describe('ネイティブ保存の補助', () => {
  it('base64 は標準形式で、大きな配列も往復できる', () => {
    const bytes = new Uint8Array(200_000).map((_, i) => (i * 7) % 256);
    const encoded = toBase64(bytes);
    expect(encoded).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(Buffer.from(encoded, 'base64').equals(Buffer.from(bytes))).toBe(true);
  });

  it('ファイル名からパス区切りと制御文字を除く', () => {
    expect(safeName('../etc/passwd')).toBe('.._etc_passwd');
    expect(safeName('決算 資料:2026?.mov')).toBe('決算 資料_2026_.mov');
    expect(safeName('a\tb c')).toBe('a_b c');
    expect(safeName('   ')).toBe('download');
  });
});

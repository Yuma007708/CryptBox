import { describe, expect, it } from 'vitest';
import { icon } from '../../web/src/icons.js';

describe('icon(): PATHS のプロトタイプ汚染対策', () => {
  it('既知の名前は対応するパスを描く', () => {
    expect(icon('lock').innerHTML).toContain('<rect');
  });

  it('未知の名前は file アイコンにフォールバックする', () => {
    expect(icon('unknown-name').innerHTML).toBe(icon('file').innerHTML);
  });

  it("'constructor' や '__proto__' でも Object.prototype 由来の値を引かない", () => {
    for (const name of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
      expect(icon(name).innerHTML).toBe(icon('file').innerHTML);
    }
  });
});

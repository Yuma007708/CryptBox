import { describe, expect, it } from 'vitest';
import { maxExpiryHours, maxFileSize, type Env } from '../../src/env.js';

/**
 * `MAX_FILE_SIZE` / `MAX_EXPIRY_HOURS` はセルフホスト者が環境変数で変える想定。
 * Workers 結合テストの `cloudflare:test` 環境は vitest.config.ts の bindings に固定されるため、
 * 「値を上げたら通る」というアクセサ自体の振る舞いはここで直接検証する。
 */
function mockEnv(overrides: Partial<Env>): Env {
  return { DB: {}, BUCKET: {}, ASSETS: {}, GRANT_SECRET: 'x', ...overrides } as unknown as Env;
}

describe('maxFileSize', () => {
  it('MAX_FILE_SIZE が未設定なら既定値 5 GiB を返す', () => {
    expect(maxFileSize(mockEnv({}))).toBe(5 * 1024 * 1024 * 1024);
  });

  it('MAX_FILE_SIZE を設定するとその値を返す（引き上げ可能）', () => {
    const raised = 100 * 1024 * 1024 * 1024;
    expect(maxFileSize(mockEnv({ MAX_FILE_SIZE: String(raised) }))).toBe(raised);
  });

  it('不正な値（0 以下・非数値）は既定値にフォールバックする', () => {
    expect(maxFileSize(mockEnv({ MAX_FILE_SIZE: '0' }))).toBe(5 * 1024 * 1024 * 1024);
    expect(maxFileSize(mockEnv({ MAX_FILE_SIZE: 'not-a-number' }))).toBe(5 * 1024 * 1024 * 1024);
  });
});

describe('maxExpiryHours', () => {
  it('MAX_EXPIRY_HOURS が未設定なら既定値 168 時間 (7 日) を返す', () => {
    expect(maxExpiryHours(mockEnv({}))).toBe(168);
  });

  it('MAX_EXPIRY_HOURS を設定するとその値を返す（引き上げ可能）', () => {
    expect(maxExpiryHours(mockEnv({ MAX_EXPIRY_HOURS: '720' }))).toBe(720);
  });

  it('不正な値（0 以下・非数値）は既定値にフォールバックする', () => {
    expect(maxExpiryHours(mockEnv({ MAX_EXPIRY_HOURS: '0' }))).toBe(168);
    expect(maxExpiryHours(mockEnv({ MAX_EXPIRY_HOURS: 'nope' }))).toBe(168);
  });
});

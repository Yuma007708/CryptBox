import { SELF, env } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { applySchema, resetTables } from './helpers.js';
import { purge } from '../src/index.js';
import { DEFAULT_REPORT_RETENTION_DAYS } from '../src/env.js';

const ORIGIN = 'https://cryptbox.test';
const DAY_MS = 24 * 60 * 60 * 1000;

const json = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

/** reports.bundle_id が「孤立通報」扱いにならないよう、対応する最小限の bundles 行を作る */
async function insertBundle(bundleId: string, now: number): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO bundles (
       id, created_at, expires_at, max_downloads, download_count, file_count, total_plain_size,
       kdf_salt, auth_hash, has_password
     ) VALUES (?, ?, ?, NULL, 0, 1, 0, 'salt', 'hash', 0)`,
  )
    .bind(bundleId, now, now + 3600_000)
    .run();
}

async function insertReport(bundleId: string, reason: string, reportedAt: number): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO reports (bundle_id, reason, detail, count, reported_at) VALUES (?, ?, NULL, 1, ?)`,
  )
    .bind(bundleId, reason, reportedAt)
    .run();
}

async function countReports(): Promise<number> {
  const row = await env.DB.prepare(`SELECT COUNT(*) as n FROM reports`).first<{ n: number }>();
  return row?.n ?? 0;
}

beforeAll(applySchema);
beforeEach(resetTables);

describe('purge(): reports の自動削除', () => {
  it('REPORT_RETENTION_DAYS を超えた通報は消える', async () => {
    const now = Date.now();
    await insertBundle('a'.repeat(64), now);
    await insertBundle('b'.repeat(64), now);
    await insertReport('a'.repeat(64), 'malware', now - (DEFAULT_REPORT_RETENTION_DAYS + 1) * DAY_MS);
    await insertReport('b'.repeat(64), 'other', now - (DEFAULT_REPORT_RETENTION_DAYS - 1) * DAY_MS);

    await purge(env, now);

    expect(await countReports()).toBe(1);
    const remaining = await env.DB.prepare(`SELECT bundle_id FROM reports`).first<{ bundle_id: string }>();
    expect(remaining?.bundle_id).toBe('b'.repeat(64));
  });

  it('バンドルが削除された通報も消える', async () => {
    const response = await SELF.fetch(
      `${ORIGIN}/api/files/orphan-token/report`,
      json({ reason: 'illegal' }),
    );
    expect(response.status).toBe(200);
    expect(await countReports()).toBe(1);

    // 対応する bundles 行は存在しない（この通報は bundleId が存在しないリンク宛て）ので
    // purge の孤立通報削除がそのまま効く
    await purge(env, Date.now());

    expect(await countReports()).toBe(0);
  });

  it('500 件を超える対象は 1 回の purge には持ち越される', async () => {
    const now = Date.now();
    const old = now - (DEFAULT_REPORT_RETENTION_DAYS + 1) * DAY_MS;
    // 対応する bundles 行も作り、孤立通報の削除条件には引っかからないようにする
    // （このテストは「期限超過」の分割削除だけを見る）
    const statements = [];
    for (let i = 0; i < 510; i++) {
      const bundleId = i.toString(16).padStart(64, '0');
      statements.push(
        env.DB.prepare(
          `INSERT INTO bundles (
             id, created_at, expires_at, max_downloads, download_count, file_count, total_plain_size,
             kdf_salt, auth_hash, has_password
           ) VALUES (?, ?, ?, NULL, 0, 1, 0, 'salt', 'hash', 0)`,
        ).bind(bundleId, now, now + 3600_000),
        env.DB.prepare(
          `INSERT INTO reports (bundle_id, reason, detail, count, reported_at) VALUES (?, ?, NULL, 1, ?)`,
        ).bind(bundleId, 'other', old),
      );
    }
    await env.DB.batch(statements);
    expect(await countReports()).toBe(510);

    await purge(env, now);
    expect(await countReports()).toBe(10);

    await purge(env, now);
    expect(await countReports()).toBe(0);
  });
});

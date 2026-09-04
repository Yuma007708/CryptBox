import { SELF } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { applySchema, resetTables } from '../helpers.js';

/**
 * このプロジェクトのみ UPLOAD_LIMITER を小さい上限 (3 回 / 60 秒) で設定している
 * （vitest.config.ts 参照）。通常の結合テスト（test/worker.test.ts）は
 * CF-Connecting-IP を送らない POST /api/uploads を多数実行するため、
 * 同じ binding を混ぜると共有の "unknown" キーで軒並み 429 になってしまう。
 * そのため専用プロジェクトに分離し、テストごとに別々の IP を使ってバケットを分離する。
 */
const ORIGIN = 'https://cryptbox.test';
const CHUNK_SIZE = 5 * 1024 * 1024;

const uploadBody = { chunkSize: CHUNK_SIZE, files: [{ plainSize: 100 }] };

const post = (ip: string): Promise<Response> =>
  SELF.fetch(`${ORIGIN}/api/uploads`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
    body: JSON.stringify(uploadBody),
  });

beforeAll(applySchema);
beforeEach(resetTables);

describe('レート制限 (UPLOAD_LIMITER, 上限 3 回/分)', () => {
  it('上限内は通り、超えると 429', async () => {
    const ip = '198.51.100.1';
    for (let i = 0; i < 3; i++) {
      const response = await post(ip);
      expect(response.status).toBe(200);
    }
    const fourth = await post(ip);
    expect(fourth.status).toBe(429);
  });

  it('IP ごとに別々に数える', async () => {
    const ipA = '198.51.100.2';
    const ipB = '198.51.100.3';
    for (let i = 0; i < 3; i++) {
      expect((await post(ipA)).status).toBe(200);
    }
    expect((await post(ipA)).status).toBe(429);
    // 別 IP はまだ上限に達していないので通る（ipB 側も上限まで独立して叩けることを確認する）
    for (let i = 0; i < 3; i++) {
      expect((await post(ipB)).status).toBe(200);
    }
    expect((await post(ipB)).status).toBe(429);
  });

  it('429 のときは JSON でエラーメッセージを返す', async () => {
    const ip = '198.51.100.4';
    for (let i = 0; i < 3; i++) await post(ip);
    const response = await post(ip);
    expect(response.status).toBe(429);
    expect(response.headers.get('Retry-After')).toBe('60');
    const body = (await response.json()) as { error?: string };
    expect(body.error).toBeTruthy();
  });

  it('同じ /64 内の異なる IPv6 アドレスは同じバケットを共有する', async () => {
    const ipv6A = '2001:db8:1234:5678:aaaa:bbbb:cccc:0001';
    const ipv6B = '2001:db8:1234:5678:1111:2222:3333:4444';
    for (let i = 0; i < 3; i++) {
      expect((await post(ipv6A)).status).toBe(200);
    }
    // 同じ /64 の別アドレスなので、既にバケットを使い切っている
    expect((await post(ipv6B)).status).toBe(429);
  });
});

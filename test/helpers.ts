import { env } from 'cloudflare:test';
import schema from '../src/schema.sql?raw';

/** schema.sql を D1 に流し込む（コメントを落として文ごとに実行する） */
export async function applySchema(): Promise<void> {
  const statements = schema
    .split('\n')
    .filter((line) => !line.trim().startsWith('--'))
    .join('\n')
    .split(';')
    .map((statement) => statement.trim())
    .filter(Boolean);
  for (const statement of statements) {
    await env.DB.prepare(statement).run();
  }
}

export async function resetTables(): Promise<void> {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM bundle_files'),
    env.DB.prepare('DELETE FROM bundles'),
    env.DB.prepare('DELETE FROM upload_parts'),
    env.DB.prepare('DELETE FROM upload_files'),
    env.DB.prepare('DELETE FROM uploads'),
    env.DB.prepare('DELETE FROM deletion_receipts'),
  ]);
}

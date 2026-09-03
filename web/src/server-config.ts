import { getJson } from './api.js';

export interface ServerConfig {
  maxFileSize: number;
  maxExpiryHours: number;
  /** Cloudflare Turnstile のサイトキー。未設定（セルフホストで無効化）なら null */
  turnstileSiteKey: string | null;
}

/**
 * サーバー（`GET /api/config`）から公開ホストの上限値を取得する。
 * セルフホストでは `MAX_FILE_SIZE` / `MAX_EXPIRY_HOURS` で変わるため、
 * ビルド時定数ではなくこちらを表示に使う。
 * 取得できない場合はサーバー側の既定値（5 GiB / 168 時間・Turnstile 無効）にフォールバックする。
 */
const FALLBACK: ServerConfig = {
  maxFileSize: 5 * 1024 * 1024 * 1024,
  maxExpiryHours: 168,
  turnstileSiteKey: null,
};

let cached: Promise<ServerConfig> | null = null;

export function getServerConfig(): Promise<ServerConfig> {
  if (!cached) {
    cached = getJson<ServerConfig>('/api/config').catch(() => FALLBACK);
  }
  return cached;
}

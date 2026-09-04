import { getJson } from './api.js';

export interface ServerConfig {
  maxFileSize: number;
  maxExpiryHours: number;
  adsEnabled: boolean;
  /** Cloudflare Turnstile のサイトキー。未設定（セルフホストで無効化）なら null */
  turnstileSiteKey: string | null;
  /** 運営者名。未設定ならヘルプの「運営者情報」節を省略する */
  operatorName: string | null;
  /** 運営者の連絡先。未設定ならヘルプの「運営者情報」節を省略する */
  operatorContact: string | null;
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
  adsEnabled: false,
  turnstileSiteKey: null,
  operatorName: null,
  operatorContact: null,
};

let cached: Promise<ServerConfig> | null = null;

export function getServerConfig(): Promise<ServerConfig> {
  if (!cached) {
    cached = getJson<ServerConfig>('/api/config').catch(() => FALLBACK);
  }
  return cached;
}

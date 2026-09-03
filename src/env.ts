export interface Env {
  DB: D1Database;
  BUCKET: R2Bucket;
  ASSETS: Fetcher;

  /** ダウンロードグラントの署名鍵 (wrangler secret put GRANT_SECRET) */
  GRANT_SECRET: string;

  /** 1 バンドルあたりの平文最大サイズ (バイト)。未設定なら 5 GiB */
  MAX_FILE_SIZE?: string;

  /** リンクに設定できる有効期限の上限 (時間)。未設定なら 168 (7 日) */
  MAX_EXPIRY_HOURS?: string;

  /** 設定された場合、アップロード API に Bearer トークンを要求する */
  UPLOAD_TOKEN?: string;

  /** 回数上限到達後、ping 途絶から削除までの猶予（分）。既定 15 分 */
  DOWNLOAD_GRACE_MINUTES?: string;

  /** 削除レシートの保持期間（日）。既定 90 日 */
  RECEIPT_RETENTION_DAYS?: string;

  /**
   * CORS を許可するオリジン（カンマ区切り）。
   * Capacitor アプリは capacitor://localhost (iOS) / https://localhost (Android) から
   * API を叩くため、未設定でもこの 2 つは許可する。
   */
  APP_ORIGINS?: string;

  /** Turnstile のサイトキー（公開値）。クライアントに `GET /api/config` で返す */
  TURNSTILE_SITE_KEY?: string;

  /**
   * Turnstile のシークレット（wrangler secret put TURNSTILE_SECRET）。
   * 未設定なら検証をスキップする（開発・セルフホストの既定）。
   */
  TURNSTILE_SECRET?: string;

  /**
   * IP あたりのアップロード回数を絞るレート制限 binding（Workers Rate Limiting）。
   * 未設定（ローカル・セルフホストで binding を組んでいない場合）なら制限しない。
   */
  UPLOAD_LIMITER?: RateLimit;
}

export const DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024;

/** リンクに設定できる有効期限の既定上限 (時間)。公開ホスト版はここまで */
export const DEFAULT_MAX_EXPIRY_HOURS = 168;

/** ダウンロードグラント（署名）の有効期間。巨大ファイルの転送中に切れないよう長めに取る */
export const GRANT_TTL_MS = 12 * 60 * 60 * 1000;

/**
 * 回数上限に達したバンドルを、クライアントの生存信号 (ping) が
 * 途絶えてから削除するまでの猶予。正常系では finish 通知で即時削除される。
 */
export const DEFAULT_DOWNLOAD_GRACE_MS = 15 * 60 * 1000;

/** アップロードセッションを放棄扱いにするまでの時間 */
export const UPLOAD_TTL_MS = 24 * 60 * 60 * 1000;

export function maxFileSize(env: Env): number {
  const parsed = Number(env.MAX_FILE_SIZE);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_MAX_FILE_SIZE;
}

/** 許可される有効期限の上限 (時間) */
export function maxExpiryHours(env: Env): number {
  const parsed = Number(env.MAX_EXPIRY_HOURS);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_MAX_EXPIRY_HOURS;
}

export function downloadGraceMs(env: Env): number {
  const minutes = Number(env.DOWNLOAD_GRACE_MINUTES);
  return Number.isFinite(minutes) && minutes > 0 ? minutes * 60 * 1000 : DEFAULT_DOWNLOAD_GRACE_MS;
}

/** 削除レシートの既定保持期間（日） */
export const DEFAULT_RECEIPT_RETENTION_DAYS = 90;

export function receiptRetentionMs(env: Env): number {
  const days = Number(env.RECEIPT_RETENTION_DAYS);
  const effective = Number.isFinite(days) && days > 0 ? days : DEFAULT_RECEIPT_RETENTION_DAYS;
  return effective * 24 * 60 * 60 * 1000;
}

const DEFAULT_APP_ORIGINS = ['capacitor://localhost', 'https://localhost', 'http://localhost'];

/** スマホアプリなど、別オリジンから API を呼べるオリジンの集合 */
export function allowedAppOrigins(env: Env): Set<string> {
  const extra = (env.APP_ORIGINS ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
  return new Set([...DEFAULT_APP_ORIGINS, ...extra]);
}

/** クライアントに公開する Turnstile サイトキー。未設定なら Turnstile は無効 */
export function turnstileSiteKey(env: Env): string | null {
  return env.TURNSTILE_SITE_KEY?.trim() || null;
}

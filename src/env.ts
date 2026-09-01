export interface Env {
  DB: D1Database;
  BUCKET: R2Bucket;
  ASSETS: Fetcher;

  /** ダウンロードグラントの署名鍵 (wrangler secret put GRANT_SECRET) */
  GRANT_SECRET: string;

  /** 1 バンドルあたりの平文最大サイズ (バイト)。未設定なら 100 GiB */
  MAX_FILE_SIZE?: string;

  /** 設定された場合、アップロード API に Bearer トークンを要求する */
  UPLOAD_TOKEN?: string;

  /** 回数上限到達後、ping 途絶から削除までの猶予（分）。既定 15 分 */
  DOWNLOAD_GRACE_MINUTES?: string;
}

export const DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024 * 1024;

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

export function downloadGraceMs(env: Env): number {
  const minutes = Number(env.DOWNLOAD_GRACE_MINUTES);
  return Number.isFinite(minutes) && minutes > 0 ? minutes * 60 * 1000 : DEFAULT_DOWNLOAD_GRACE_MS;
}

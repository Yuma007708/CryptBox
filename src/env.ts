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

  /** "1" のとき広告枠（ダミー）を表示する。未設定なら無効 */
  ADS_ENABLED?: string;

  /** Turnstile のサイトキー（公開値）。クライアントに `GET /api/config` で返す */
  TURNSTILE_SITE_KEY?: string;

  /**
   * Turnstile のシークレット（wrangler secret put TURNSTILE_SECRET）。
   * 未設定なら検証をスキップする（開発・セルフホストの既定）。
   */
  TURNSTILE_SECRET?: string;

  /**
   * siteverify レスポンスの `hostname` と照合する許可ホスト名（カンマ区切り）。
   * 未設定なら hostname 検証をスキップする。
   */
  TURNSTILE_HOSTNAMES?: string;

  /**
   * IP あたりのアップロード回数を絞るレート制限 binding（Workers Rate Limiting）。
   * 未設定（ローカル・セルフホストで binding を組んでいない場合）なら制限しない。
   */
  UPLOAD_LIMITER?: RateLimit;

  /** IP あたりの通報回数を絞るレート制限 binding。未設定なら制限しない */
  REPORT_LIMITER?: RateLimit;

  /**
   * IP あたりの本体取得 (`GET /api/files/:token/files/:file/blob`) 回数を絞る
   * レート制限 binding。目安 300 回/分（wrangler.jsonc の `DOWNLOAD_LIMITER`）。
   * 未設定（ローカル・セルフホストで binding を組んでいない場合）なら制限しない。
   */
  DOWNLOAD_LIMITER?: RateLimit;

  /**
   * 運営者による無効化 API (`/api/admin/*`) を保護するトークン
   * (`wrangler secret put ADMIN_TOKEN`)。未設定なら管理 API は 404 として振る舞う。
   */
  ADMIN_TOKEN?: string;

  /** `GET /api/config` で公開する運営者名。未設定ならヘルプの節を省略する */
  OPERATOR_NAME?: string;

  /** `GET /api/config` で公開する運営者の連絡先。未設定ならヘルプの節を省略する */
  OPERATOR_CONTACT?: string;

  /** 通報記録を保持する日数。未設定なら 90 日 */
  REPORT_RETENTION_DAYS?: string;
}

export const DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024;

/** リンクに設定できる有効期限の既定上限 (時間)。公開ホスト版はここまで */
export const DEFAULT_MAX_EXPIRY_HOURS = 168;

/**
 * ダウンロードグラント（署名）の有効期間。
 * 巨大ファイルの転送中に切れない長さは要るが、長すぎると「1 回分のグラントで
 * 何時間も本体を引き続けられる」窓が広がるため 2 時間に抑える。
 * 転送が長引く場合はクライアントが claim をやり直す（＝回数を再消費する）。
 */
export const GRANT_TTL_MS = 2 * 60 * 60 * 1000;

/**
 * 回数上限に達したバンドルを、クライアントの生存信号 (ping) が
 * 途絶えてから削除するまでの猶予。正常系では finish 通知で即時削除される。
 */
export const DEFAULT_DOWNLOAD_GRACE_MS = 15 * 60 * 1000;

/**
 * アップロードセッションを放棄扱いにするまでの時間。
 * 長く取ると、未完了のマルチパート（R2 に課金される断片）が滞留する。
 * 実際の送信は接続が生きている間に終わるので 2 時間で足りる。
 */
export const UPLOAD_TTL_MS = 2 * 60 * 60 * 1000;

/**
 * 同一 IP が同時に開いておけるアップロードセッション数の上限。
 * 超えると `POST /api/uploads` が 429 を返す。マルチパートを開くだけ開いて
 * 完了させない（＝R2 に断片を溜める）攻撃を抑える。
 *
 * NAT・社内 LAN のように同一グローバル IP を多人数で共有する環境でも
 * 正常な利用者が締め出されないよう、抑止力として最低限の値に留める。
 */
export const MAX_OPEN_UPLOADS_PER_IP = 8;

/**
 * アップロードセッションを「同時に開いている」とみなす無活動の許容時間。
 * これを過ぎて part PUT が来ていないセッションは、放棄扱い (UPLOAD_TTL_MS) に
 * なる前でも同時数の勘定から外す。
 *
 * これが無いと、ブラウザを閉じるなどで放棄されたセッションが最大 2 時間
 * (UPLOAD_TTL_MS) 枠を占有し、利用者が自分自身を締め出してしまう。
 */
export const UPLOAD_ACTIVITY_WINDOW_MS = 15 * 60 * 1000;

/**
 * `reports` テーブルの行数上限。これを超えると通報 API は 503 を返す。
 * REPORT_LIMITER が無い構成でも D1 が無制限に膨らまないようにするための最終防波堤
 * （通常は「バンドル × 理由」で集約されるため、ここに達することはまずない）。
 */
export const MAX_REPORT_ROWS = 50_000;

/** GRANT_SECRET に要求する最小の長さ。これ未満なら全リクエストを 500 で止める */
export const MIN_GRANT_SECRET_LENGTH = 16;

export function maxFileSize(env: Env): number {
  const parsed = Number(env.MAX_FILE_SIZE);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_MAX_FILE_SIZE;
}

/** 許可される有効期限の上限 (時間) */
export function maxExpiryHours(env: Env): number {
  const parsed = Number(env.MAX_EXPIRY_HOURS);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_MAX_EXPIRY_HOURS;
}

/** 広告枠（ダミー）を表示するか。広告ネットワークは未接続で、レイアウトのみ */
export function adsEnabled(env: Env): boolean {
  return env.ADS_ENABLED === '1';
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

/**
 * 既定で CORS を許可するオリジン。Capacitor アプリの WebView オリジンだけに絞る。
 * `http://localhost` は「同一マシンで動く任意のアプリ・任意のポート」を意味し、
 * 悪意あるローカルページから API を叩けてしまうため既定からは外している。
 * ローカル開発で必要なら `APP_ORIGINS` で明示的に足す（docs/deploy.md 参照）。
 */
const DEFAULT_APP_ORIGINS = ['capacitor://localhost', 'https://localhost'];

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

/** siteverify の hostname 照合に使う許可ホスト名の集合。未設定なら null（照合スキップ） */
export function turnstileHostnames(env: Env): Set<string> | null {
  const raw = (env.TURNSTILE_HOSTNAMES ?? '')
    .split(',')
    .map((host) => host.trim())
    .filter(Boolean);
  return raw.length > 0 ? new Set(raw) : null;
}

/** 運営者名。未設定ならヘルプの「運営者情報」節を省略する */
export function operatorName(env: Env): string | null {
  return env.OPERATOR_NAME?.trim() || null;
}

/** 運営者の連絡先。未設定ならヘルプの「運営者情報」節を省略する */
export function operatorContact(env: Env): string | null {
  return env.OPERATOR_CONTACT?.trim() || null;
}

/** 既定の通報保持日数 */
export const DEFAULT_REPORT_RETENTION_DAYS = 90;

/** 通報記録を保持する日数。未設定・不正な値なら既定 (90 日) */
export function reportRetentionDays(env: Env): number {
  const parsed = Number(env.REPORT_RETENTION_DAYS);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_REPORT_RETENTION_DAYS;
}

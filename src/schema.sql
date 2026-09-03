-- CryptBox D1 schema
-- サーバーが保持するのは暗号文と一方向ハッシュのみ。
-- 平文のファイル名・鍵・パスワードは保存しない。

-- 1 つの共有リンク = 1 バンドル（1〜N ファイル）
CREATE TABLE IF NOT EXISTS bundles (
  -- SHA-256(shareToken) の hex。生トークンは保存しない
  id               TEXT PRIMARY KEY,
  created_at       INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL,
  max_downloads    INTEGER,               -- NULL = 無制限
  download_count   INTEGER NOT NULL DEFAULT 0,
  -- 進行中のダウンロード数と最終アクティビティ。
  -- 回数上限に達したバンドルは「アクティブ 0」または「アクティビティ途絶」で即削除する
  active_downloads INTEGER NOT NULL DEFAULT 0,
  last_activity_at INTEGER,
  file_count       INTEGER NOT NULL,
  total_plain_size INTEGER NOT NULL,

  -- 鍵導出（KEK 自体はサーバーには存在しない）
  kdf_salt         TEXT NOT NULL,

  -- 認証（サーバーは検証値のハッシュしか持たない）
  auth_hash        TEXT NOT NULL,
  has_password     INTEGER NOT NULL DEFAULT 0,
  pw_salt          TEXT,
  pw_params        TEXT,                  -- JSON: Argon2id パラメータ
  pw_hash          TEXT                   -- SHA-256(pwVerifier)
);

CREATE INDEX IF NOT EXISTS idx_bundles_expires_at ON bundles (expires_at);

-- バンドル内の 1 ファイル。ファイルごとに独立した CEK を持つ
CREATE TABLE IF NOT EXISTS bundle_files (
  bundle_id     TEXT NOT NULL,
  file_index    INTEGER NOT NULL,
  r2_key        TEXT NOT NULL,
  plain_size    INTEGER NOT NULL,
  cipher_size   INTEGER NOT NULL,
  chunk_size    INTEGER NOT NULL,
  total_chunks  INTEGER NOT NULL,
  nonce_prefix  TEXT NOT NULL,
  wrapped_cek   TEXT NOT NULL,            -- KEK でラップした CEK
  wrap_nonce    TEXT NOT NULL,
  meta_cipher   TEXT NOT NULL,            -- ファイル名・MIME も CEK で暗号化
  meta_nonce    TEXT NOT NULL,
  PRIMARY KEY (bundle_id, file_index)
);

-- 進行中のアップロード
CREATE TABLE IF NOT EXISTS uploads (
  -- SHA-256(uploadToken) の hex
  id          TEXT PRIMARY KEY,
  created_at  INTEGER NOT NULL,
  abandon_at  INTEGER NOT NULL,
  chunk_size  INTEGER NOT NULL,
  file_count  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_uploads_abandon_at ON uploads (abandon_at);

CREATE TABLE IF NOT EXISTS upload_files (
  upload_id    TEXT NOT NULL,
  file_index   INTEGER NOT NULL,
  r2_key       TEXT NOT NULL,
  r2_upload_id TEXT NOT NULL,
  plain_size   INTEGER NOT NULL,
  total_chunks INTEGER NOT NULL,
  PRIMARY KEY (upload_id, file_index)
);

CREATE TABLE IF NOT EXISTS upload_parts (
  upload_id   TEXT NOT NULL,
  file_index  INTEGER NOT NULL,
  part_number INTEGER NOT NULL,
  etag        TEXT NOT NULL,
  PRIMARY KEY (upload_id, file_index, part_number)
);

-- 削除レシート: バンドルが消えたとき「いつ・なぜ」を署名付きで記録する。
-- ファイル名・鍵・IP は含まない。保持期間 (RECEIPT_RETENTION_DAYS) を過ぎたら Cron が消す
-- auth_hash はバンドル行からコピーする。/receipt がトークンだけの第三者に
-- レシート（削除時刻・理由・ファイル数・平文合計サイズ）を渡してしまわないよう、
-- authToken 保有者だけに絞るための検証値
CREATE TABLE IF NOT EXISTS deletion_receipts (
  bundle_id         TEXT PRIMARY KEY,
  created_at        INTEGER NOT NULL,
  deleted_at        INTEGER NOT NULL,
  reason            TEXT NOT NULL,          -- 'expired' | 'limit_reached' | 'sender_deleted'
  file_count        INTEGER NOT NULL,
  total_plain_size  INTEGER NOT NULL,
  signature         TEXT NOT NULL,          -- base64url(HMAC-SHA256)
  auth_hash         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_deletion_receipts_deleted_at ON deletion_receipts (deleted_at);

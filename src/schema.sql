-- CryptBox D1 schema
-- サーバーが保持するのは暗号文と一方向ハッシュのみ。平文のファイル名・鍵・パスワードは保存しない。

CREATE TABLE IF NOT EXISTS files (
  -- SHA-256(fileToken) の hex。生トークンは保存しない
  id             TEXT PRIMARY KEY,
  r2_key         TEXT NOT NULL,
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  max_downloads  INTEGER,               -- NULL = 無制限
  download_count INTEGER NOT NULL DEFAULT 0,
  last_claim_at  INTEGER,

  -- 本体レイアウト
  plain_size     INTEGER NOT NULL,
  cipher_size    INTEGER NOT NULL,
  chunk_size     INTEGER NOT NULL,
  total_chunks   INTEGER NOT NULL,
  nonce_prefix   TEXT NOT NULL,         -- base64url 4B

  -- 鍵ラップ (KEK はサーバーには存在しない)
  kdf_salt       TEXT NOT NULL,
  wrapped_cek    TEXT NOT NULL,
  wrap_nonce     TEXT NOT NULL,

  -- ファイル名・MIME タイプも CEK で暗号化して保存する
  meta_cipher    TEXT NOT NULL,
  meta_nonce     TEXT NOT NULL,

  -- 認証 (サーバーは検証値のハッシュしか持たない)
  auth_hash      TEXT NOT NULL,
  has_password   INTEGER NOT NULL DEFAULT 0,
  pw_salt        TEXT,
  pw_params      TEXT,                  -- JSON: Argon2id パラメータ
  pw_hash        TEXT                   -- SHA-256(pwVerifier)
);

CREATE INDEX IF NOT EXISTS idx_files_expires_at ON files (expires_at);

-- 進行中のマルチパートアップロード
CREATE TABLE IF NOT EXISTS uploads (
  -- SHA-256(uploadToken) の hex
  id             TEXT PRIMARY KEY,
  r2_key         TEXT NOT NULL,
  r2_upload_id   TEXT NOT NULL,
  created_at     INTEGER NOT NULL,
  abandon_at     INTEGER NOT NULL,
  plain_size     INTEGER NOT NULL,
  chunk_size     INTEGER NOT NULL,
  total_chunks   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_uploads_abandon_at ON uploads (abandon_at);

CREATE TABLE IF NOT EXISTS upload_parts (
  upload_id      TEXT NOT NULL,
  part_number    INTEGER NOT NULL,
  etag           TEXT NOT NULL,
  PRIMARY KEY (upload_id, part_number)
);

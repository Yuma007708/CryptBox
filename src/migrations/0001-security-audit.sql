-- 0001 security-audit
--
-- 既存の D1 に対して、後から追加された列を足す。
-- src/schema.sql は `CREATE TABLE IF NOT EXISTS` だけで構成しているため、
-- 既に運用中のデータベースには列の追加が反映されない。
--
--   npm run db:migrate
--
-- SQLite の `ALTER TABLE ... ADD COLUMN` は冪等ではない。
-- 既に列がある環境では `duplicate column name` で失敗するが、
-- その場合はそのエラーを無視してよい（既に適用済みという意味）。

-- 配信停止フラグ。削除はまずこの列を 1 にしてから R2 / D1 を消す（fail-closed）
ALTER TABLE bundles ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;

-- 配信停止の理由。物理削除が保留になったとき、cron の再削除が
-- 正しい理由で削除レシートを書けるように保持する
ALTER TABLE bundles ADD COLUMN disabled_reason TEXT;

-- 同一 IP の同時アップロードセッション数を数えるための鍵付きハッシュ。生 IP は保存しない
ALTER TABLE uploads ADD COLUMN ip_hash TEXT;

-- 最後にパートを受け取った時刻。無活動のセッションを同時数の勘定から外すために使う
ALTER TABLE uploads ADD COLUMN last_activity_at INTEGER;

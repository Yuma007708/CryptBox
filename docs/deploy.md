# デプロイ手順

## 1. Cloudflare リソースの作成

```bash
# R2（暗号文の保管先）
npx wrangler r2 bucket create cryptbox-blobs
npx wrangler r2 bucket create cryptbox-blobs-dev   # 任意（プレビュー用）

# D1（メタデータ）
npx wrangler d1 create cryptbox
```

`wrangler d1 create` が出力した `database_id` を `wrangler.jsonc` の
`REPLACE_WITH_YOUR_D1_DATABASE_ID` と差し替えます。

```bash
npm run db:init     # src/schema.sql を本番 D1 に適用
```

## 2. シークレット

```bash
openssl rand -base64 32 | npx wrangler secret put GRANT_SECRET
```

`GRANT_SECRET` はダウンロードグラント（回数を消費した証明）の HMAC 署名鍵です。
**ローテーションすると発行済みのグラントが無効になります**（再度 claim すれば
ダウンロード回数を 1 消費して取り直せます）。

アップロードを絞りたい場合のみ:

```bash
npx wrangler secret put UPLOAD_TOKEN
```

## 3. デプロイ

```bash
npm run deploy      # フロントエンドをビルドして wrangler deploy
```

**コード反映前にスキーマ適用が必要です。** `npm run deploy` は
`build:web` → `db:init`（`src/schema.sql` を本番 D1 に適用）→ `wrangler deploy` の順で
自動的に行うので、通常は個別に `db:init` を叩く必要はありません。`schema.sql` は
`CREATE TABLE IF NOT EXISTS` のみで構成されているため、既存データに対して安全に
繰り返し適用できます（削除レシートの INSERT はバンドル削除と同じ `DB.batch` に
入っているため、`deletion_receipts` テーブルが無いまま新しいコードだけをデプロイすると
削除処理自体が失敗します）。

## 4. TLS 1.3 のみに固定する

Cloudflare ダッシュボード → 対象ゾーン → **SSL/TLS**:

| 設定 | 値 |
| --- | --- |
| SSL/TLS encryption mode | **Full (strict)** |
| Edge Certificates → Minimum TLS Version | **TLS 1.3** |
| Edge Certificates → Always Use HTTPS | **On** |
| Edge Certificates → Automatic HTTPS Rewrites | **On** |
| Edge Certificates → TLS 1.3 | **On** |

API で設定する場合:

```bash
curl -X PATCH "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/settings/min_tls_version" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"value":"1.3"}'
```

アプリ側は `_headers` で HSTS（`max-age=63072000; includeSubDomains; preload`）を
返しています。`hstspreload.org` への登録は任意です。

> 最小 TLS を 1.3 にすると、TLS 1.2 までしか話せない古いクライアントは接続できません。
> 社外配布用途では 1.2 を許容するか、事前に相手先の環境を確認してください。

## 5. R2 のライフサイクルルール（自動削除の二重化）

削除は 3 段構えです。①受信側の完了通知で即時削除、②毎分の Cron が
期限切れ・生存信号の途絶えた回数超過バンドルを削除、③それでも
取りこぼした場合（Cron の失敗、マルチパートの中断）に備えて R2 側にも保険を入れます。

ダッシュボード → R2 → `cryptbox-blobs` → **Settings → Object lifecycle rules**:

| ルール | 設定 |
| --- | --- |
| 未完了のマルチパートアップロードを中止 | 1 日後 |
| オブジェクトの削除 | 31 日後（アプリの最長有効期限 30 日 + 1 日） |

CLI の場合:

```bash
npx wrangler r2 bucket lifecycle add cryptbox-blobs \
  --name expire-blobs --expire-days 31
npx wrangler r2 bucket lifecycle add cryptbox-blobs \
  --name abort-multipart --abort-multipart-days 1
```

## 6. 動作確認

```bash
curl -I https://<your-domain>/            # HSTS と CSP が付いているか
curl -X POST https://<your-domain>/api/uploads \
  -H 'content-type: application/json' \
  -d '{"plainSize":1000,"chunkSize":5242880}'
```

Cron を手動で叩く（ローカル）:

```bash
curl "http://127.0.0.1:8787/cdn-cgi/local/scheduled"
```

## コストの目安

- **R2**: 保存容量に対する課金のみ。**egress（ダウンロード転送量）は無料** なので、
  大容量ファイルの配布に向いています。
- **D1**: 行数・読み書き回数に対する課金。1 ファイル 1 行なので軽微です。
- **Workers**: リクエスト数と CPU 時間。本 Worker は暗号処理をしない
  （ブラウザ側で行う）ため CPU をほとんど使いません。

## 上限・猶予を変える

- `wrangler.jsonc` の `vars.MAX_FILE_SIZE`（バイト）: 1 バンドルの合計サイズ上限。
- `vars.DOWNLOAD_GRACE_MINUTES`（分・既定 15）: 回数上限に達したバンドルを、
  受信クライアントの生存信号が途絶えてから削除するまでの猶予。
  正常系では完了通知により即時削除されるため、これはクラッシュ時の保険です。

R2 マルチパートの上限は 10,000 パートなので、
16 MiB チャンク × 10,000 = 約 156 GiB が構造上の最大値です。

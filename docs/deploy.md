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

### Turnstile（公開ホスト版は必須。セルフホストは任意）

無料公開する場合、送信 API (`POST /api/uploads`) を [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/)
で保護します。**`TURNSTILE_SECRET` を設定しない限り検証はスキップされる**ため、
セルフホストでは何もしなくても動きます。

**手順の順序が重要です**（サイトキーを先に、シークレットを後に）。逆順にすると、
シークレットが有効になった瞬間からサーバーがトークンを要求するのに、
クライアントはまだサイトキーを持たずウィジェットを出せない「片肺」の時間帯ができ、
その間は誰も送信できません。

1. Cloudflare ダッシュボード → **Turnstile** → ウィジェットを追加。
   - ドメイン: 公開ホスト名（例: `cryptbox.example.com`）
   - ウィジェットモード: 任意（アプリ側は `appearance: 'interaction-only'` で明示的にレンダリングするため、
     Managed / Invisible のどちらでも動く）
2. 発行された **サイトキー**（公開値）を `wrangler.jsonc` の `vars.TURNSTILE_SITE_KEY` に書き、
   **`wrangler deploy` を完了させる**（`npm run deploy` でも可）。
3. デプロイが終わってから **シークレット**を Worker に設定する:

```bash
npx wrangler secret put TURNSTILE_SECRET
```

以降、`GET /api/config` が `turnstileSiteKey` を返すようになり、フロントエンドが自動で
ウィジェットを読み込みます。`TURNSTILE_SECRET` を設定した瞬間からサーバー側の検証が有効になります。

> **安全弁**: サーバー側は `TURNSTILE_SECRET` が設定されていても `TURNSTILE_SITE_KEY` が
> 未設定なら検証をスキップします（サイトキーを配っていなければクライアントはそもそも
> トークンを送れないため）。上記の順序を守れなくても送信不能にはなりませんが、
> 検証は無効なままなので早めにサイトキーを設定してください。

> **fail-closed のトレードオフ**: Turnstile 検証は fail-closed（`challenges.cloudflare.com`
> への通信が失敗・タイムアウトした場合も 403 を返す）です。Turnstile 自体が障害を起こすと
> アップロードが全面的に止まります。緊急でアップロードを復旧させたい場合は
> `npx wrangler secret delete TURNSTILE_SECRET` で検証をスキップに戻せます
> （サイトキーが残っていてもクライアント側は動くので、フロントエンドの再デプロイは不要です）。
> 失敗の原因は Worker のログに出る `error-codes`（`console.warn`）で確認できます。

### 通報・無効化（公開ホスト版は必須。セルフホストは任意）

無料公開する場合、受信ページの「このリンクを通報」を経由した通報を D1 の `reports` に記録し、
運営者が中身を見ずにリンク単位でバンドルを即時完全削除できる管理 API を用意しています。
**`ADMIN_TOKEN` を設定しない限り `/api/admin/*` は 404 を返し、存在しないかのように振る舞います。**

```bash
openssl rand -base64 32 | npx wrangler secret put ADMIN_TOKEN
```

運営者名・連絡先（ヘルプページに表示。任意）は `wrangler.jsonc` の `vars.OPERATOR_NAME` /
`vars.OPERATOR_CONTACT` に書きます（シークレットではないので secret put は不要）。

通報を確認する:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://<your-domain>/api/admin/reports?limit=50"
```

`bundleId`（通報のハッシュ）を指定してリンクを無効化する:

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"bundleId":"<reports 一覧の bundleId>"}' \
  "https://<your-domain>/api/admin/takedown"
```

削除に成功すると `{"ok":true,"deleted":true}` が返り、同じ `bundleId` の未処理の通報は
処理済みになって以降 `/api/admin/reports` には出てきません（存在しない `bundleId` の場合は
`deleted:false`）。R2 のオブジェクトと D1 の行はこの時点で完全に削除され、復元できません。

通報 API (`POST /api/files/:token/report`) にも IP あたりのレート制限を掛けたい場合、
`wrangler.jsonc` の `ratelimits` に `REPORT_LIMITER` を追加します（既定で入っています）。
挙動は 6 節の `UPLOAD_LIMITER` と同じです。

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

## 6. レート制限（POST /api/uploads）

IP あたりのアップロード開始回数を [Workers Rate Limiting binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)
で絞っています。`wrangler.jsonc` の `ratelimits` に既定で入っており、**デプロイするだけで有効**です。
この binding は 2025-09-19 に GA（一般提供）になっており、本番ワークロードに使える安定版です
（出典: [Rate Limiting in Workers is now GA](https://developers.cloudflare.com/changelog/post/2025-09-19-ratelimit-workers-ga/)）。

> 無料プランでの利用可否・必要な `wrangler` バージョン・`period` に指定できる値は
> ドキュメント検索で裏取りできなかったため**未確認**です。デプロイ前に
> [Workers Rate Limiting](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)
> の一次情報で確認してください。

```jsonc
"ratelimits": [
  { "name": "UPLOAD_LIMITER", "namespace_id": "1001", "simple": { "limit": 10, "period": 60 } }
]
```

- `limit` / `period` を変えて調整します。デプロイし直せば反映されます。
- binding ごと削除すれば（`ratelimits` ブロックを丸ごと消す）制限なしに戻ります
  （`c.env.UPLOAD_LIMITER` が undefined になり、コード側は自動的にスキップします）。
- この binding は Worker インスタンス単位の近似カウントです。より厳密・大規模な制限や、
  `/api/uploads` 以外のパスも含めた防御が要る場合はあわせて
  ダッシュボードの **Security → WAF → Rate limiting rules** も検討してください
  （対象パス `/api/uploads`、しきい値・期間は上と揃える、アクションは Block や
  Managed Challenge）。WAF のレート制限は Cloudflare のエッジで Worker を呼ぶ前に効くため、
  より安価に大量リクエストを弾けます。
- **この binding が絞るのはセッション作成回数（`POST /api/uploads`）だけです。**
  チャンクの PUT（`PUT /api/uploads/:token/files/:file/parts/:chunk`）や、
  ダウンロード側の blob GET は絞りません。転送量そのもの（帯域・データ量）を制限したい場合は
  `MAX_FILE_SIZE`（1 バンドルの合計サイズ上限）と、上記の WAF Rate limiting rules
  （対象パスを転送系エンドポイントまで広げる）を別途設計してください。

## 7. 動作確認

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

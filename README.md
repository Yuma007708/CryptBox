# CryptBox

大容量ファイルを **端末内で暗号化してから** 送る、ギガファイル便ライクな転送サービス。
Cloudflare Workers + R2 + D1 の上で動きます。アカウント登録は不要です。

サーバー（および Cloudflare）が保持するのは **暗号文と一方向ハッシュだけ** です。
復号鍵は URL の `#` より後ろ（フラグメント）に載るため、HTTP リクエストに含まれず
サーバーには到達しません。

```
https://example.com/d/<43文字のトークン>#<復号鍵>
                     ~~~~~~~~~~~~~~~~~~  ~~~~~~~~
                     サーバーに届く       サーバーに届かない
```

## 要件と実装の対応

| やりたいこと | 実装 |
| --- | --- |
| 通信：TLS 1.3 | Cloudflare 側で最小 TLS を 1.3 に設定（[docs/deploy.md](docs/deploy.md)）＋ HSTS preload |
| ファイル：AES-256-GCM | ブラウザの WebCrypto で 16 MiB チャンクごとに暗号化 |
| パスワード：Argon2id | `hash-wasm` で m=64 MiB / t=3 / p=1（OWASP 推奨）。ブラウザ内で実行 |
| ダウンロード URL | 256 bit（base64url 43 文字）のランダムトークン。DB には SHA-256 のみ保存 |
| 有効期限 | 1 時間 / 24 時間 / 3 日 / 7 日（公開ホスト版の上限。`MAX_EXPIRY_HOURS` でセルフホストは変更可） |
| ダウンロード回数制限 | 1 / 5 / 20 / 100 / 無制限。D1 上で原子的にカウント |
| パスワード付きファイル | リンク＋パスワードの二要素。どちらか一方だけでは復号不可 |
| 複数ファイル | 1 リンクに最大 50 ファイル・合計 5 GiB まで（公開ホスト版の上限。`MAX_FILE_SIZE` でセルフホストは変更可）。受信側で個別／一括ダウンロード |
| 自動削除 | 期限切れ・回数到達で **R2 + D1 から完全削除**（下記）。リンクは即時無効化 |
| 画質の劣化ゼロ | 再エンコードなし。詳細は下記 |

## 完全削除のしくみ

「消えたはず」を確実にするため、削除は三重にしています。

| きっかけ | 挙動 |
| --- | --- |
| **回数上限の最後の 1 回が完了** | 受信ページが完了通知 (finish) を送り、**その瞬間に R2 + D1 から削除** |
| 受信ページが黙って消えた（クラッシュ等） | ダウンロード中は毎分の生存信号 (ping) を送っており、**途絶から 15 分**（`DOWNLOAD_GRACE_MINUTES` で変更可）で Cron が削除 |
| **有効期限が切れた** | 毎分の Cron が削除。期限切れリンクにアクセスがあれば **その場でも削除** |

- 上限に達した時点で `/info` と `/claim` は 410 を返すため、**リンクの無効化は即時**です
  （削除が猶予中でも、新しいダウンロードは開始できません）。
- タブを閉じた場合も `sendBeacon` で完了通知が飛ぶため、通常は即時削除になります。
- ダウンロード進行中に消さないよう「アクティブなダウンロード数」を数えており、
  最後の 1 人が終わるまでは削除を待ちます。
- 送信者は送信履歴の「今すぐ削除」で、期限前でも任意のタイミングで完全削除できます。
- さらに保険として R2 のライフサイクルルール（[docs/deploy.md](docs/deploy.md)）を推奨します。

### 削除レシート

バンドルが削除される瞬間、**いつ・なぜ消えたか**を署名付きで D1 に記録します
（`expired` = 期限切れ / `limit_reached` = ダウンロード上限到達 / `sender_deleted` = 送信者が削除）。
送信履歴の「削除証明」、受信ページの削除後表示、`POST /api/files/:token/receipt` から確認できます。

- 記録するのは **トークンのハッシュ・作成/削除時刻・理由・ファイル数・合計サイズ** だけです。
  ファイル名・鍵・IP アドレスは含みません（詳細は [docs/security.md](docs/security.md)）。
- レシートは `GRANT_SECRET` から HKDF-SHA256 で分離した鍵で HMAC-SHA256 署名しており、
  `POST /api/receipts/verify` で（DB を見ずに）署名だけを再検証できます。ただし
  `GRANT_SECRET` をローテーションすると、それ以前に発行済みのレシートは検証できなくなります。
- 保持期間は既定 90 日（`RECEIPT_RETENTION_DAYS` で変更可）。期限を過ぎると Cron が消します。
- `POST /api/files/:token/receipt` は他の API と同じく authToken（共有リンクの鍵から導出）が
  必須です。トークンのパス部分だけを知っていても取得できません。

## なぜ「劣化ゼロ」なのか

サーバーはファイルを **暗号化された不透明なバイト列としてしか見られません**。
中身が JPEG なのか動画なのかを知る術がないので、リサイズ・再圧縮・トランスコードは
**原理的に起こり得ません**。受信側は AES-GCM の認証タグ込みで復号するため、
1 バイトでも変化していれば復号が失敗します（＝黙って劣化することがない）。

E2E テストでも、5 MiB 超のファイルをアップロード → ダウンロードして
SHA-256 が完全一致することを検証しています。

> Cloudflare の Polish / Mirage / Image Resizing といった画像最適化機能は
> R2 のオブジェクトにも Worker のレスポンスにも適用していません
> （そもそも `application/octet-stream` の暗号文です）。

## 画面

| 画面 | 内容 |
| --- | --- |
| ファイルを送る (`/`) | ドラッグ＆ドロップ、選択中のファイル一覧、オプション設定（有効期限・ダウンロード回数・パスワード保護）、最近の送信 |
| 送信履歴 (`/history`) | 発行済みリンクの一覧。リンクのコピーと、サーバーからの即時削除 |
| 設定 (`/settings`) | テーマ（ライト／ダーク／OS 追従）、送信時の既定値、履歴の保存可否 |
| ヘルプ (`/help`) | しくみと注意点 |
| 受信 (`/d/<token>#<鍵>`) | ファイル一覧、パスワード入力、復号ダウンロード |

送信履歴と設定は **この端末の localStorage にだけ** 保存されます。サーバーには残りません。
履歴には復号鍵を含むリンクが入るため、共有端末では設定からオフにできます。

## スマホアプリ版（iOS / Android）

Web 版のフロントエンドを Capacitor で包んだアプリ版があります。
写真・動画をネイティブピッカーで**無変換のまま**取り込み、復号したファイルは
「ファイル」アプリ（iOS）/ `Documents/CryptBox`（Android）に保存します。
アプリはコードを同梱するので、Web 版にある「配信サーバーが改竄されたら鍵を盗まれ得る」
という弱点がなくなります。

```bash
VITE_API_BASE=https://cryptbox.example.com npm run cap:sync
npm run android   # Android Studio を開く
npm run ios       # Xcode を開く（macOS）
```

CI が push ごとにデバッグ APK を Artifacts に置きます。詳細は [docs/mobile.md](docs/mobile.md)。

## 暗号設計

```
linkSecret  = 32 バイトの乱数                    ← URL の #（サーバーに送られない）
pwKey       = Argon2id(password, pwSalt)         ← パスワード指定時のみ
KEK         = HKDF-SHA256(linkSecret ‖ pwKey, salt=kdfSalt, info="cryptbox/v1/kek")
CEK[i]      = 32 バイトの乱数                    ← ファイルごとに独立した鍵
wrappedCEK  = AES-256-GCM(KEK, CEK[i])           ← これだけがサーバーに保存される

authToken   = HKDF(linkSecret, info="…/auth")    ← サーバーは SHA-256 だけを保持
pwVerifier  = HKDF(pwKey,      info="…/verify")  ← 同上
```

1 リンク（バンドル）に複数ファイルを入れても、**ファイルごとに別の CEK** を使います。
同じ鍵で nonce が衝突する余地をなくすためです。KEK はバンドルで 1 つなので、
パスワード入力（Argon2id）は何ファイルあっても 1 回で済みます。

本体は 16 MiB の平文チャンクごとに独立して暗号化します。

- nonce = `noncePrefix(4B) ‖ chunkIndex(8B)` — 同じ nonce が二度使われない
- AAD = `version(1B) ‖ chunkIndex(8B) ‖ totalChunks(8B)` — 並べ替えと切り詰めを検知

サーバーが**知らない**もの: 復号鍵、パスワード、ファイル名、MIME タイプ、平文の中身。
（ファイル名も CEK で暗号化して保存しています。）

### パスワードの扱い

パスワードは 2 段階で効きます。

1. **ローカル**: Argon2id → KEK。パスワードが違えば AES-GCM の認証に失敗するので、
   サーバーに問い合わせる前に判定できる＝**誤入力でダウンロード回数を消費しません**。
2. **サーバー**: `SHA-256(pwVerifier)` と照合。第三者がリンクだけを手に入れても
   ダウンロード回数を減らせません。

## 大容量ファイルの扱い

| | 方式 |
| --- | --- |
| アップロード | 16 MiB チャンクを 3 並列で送信 → R2 マルチパートアップロード（1 ファイルあたり最大 10,000 パート ≒ 156 GiB）。失敗したチャンクだけ指数バックオフで再送 |
| ダウンロード | 1 本のレスポンスを読みながらチャンク境界で復号。切断されたら **最後に復号し終えた位置から Range で再開** |
| 保存先 | ① File System Access API（Chromium：直接ファイルへ書き込み） → ② Service Worker ストリーム（Firefox / Safari） → ③ Blob（最終手段） |

①②はメモリにファイル全体を載せません。

## 構成

```
shared/format.ts     暗号フォーマットの定義（Worker とブラウザで共有）
src/                 Cloudflare Worker（Hono）
  index.ts           API・アセット配信・Cron による自動削除
  schema.sql         D1 スキーマ（bundles / bundle_files / uploads …）
web/                 フロントエンド（Vite / TypeScript、フレームワークなし）
  src/crypto.ts      鍵導出・暗号化
  src/upload.ts      複数ファイルのチャンク分割アップロード
  src/download.ts    ストリーム復号（再開つき）
  src/saver.ts       保存方式のフォールバック
  src/history.ts     送信履歴（localStorage）
  src/settings.ts    設定とテーマ
  src/views/         画面（送る / 履歴 / 設定 / ヘルプ / 受信）
  public/sw.js       ストリーム保存用 Service Worker
test/                Vitest（Worker 結合テスト / 暗号ユニットテスト）
docs/                デプロイ手順・脅威モデル
```

## API

| メソッド | パス | 用途 |
| --- | --- | --- |
| GET | `/api/config` | このホストの上限値（`maxFileSize` / `maxExpiryHours`）を公開 |
| POST | `/api/uploads` | セッション作成（ファイル数とサイズを申告） |
| PUT | `/api/uploads/:token/files/:file/parts/:chunk` | 暗号化済みチャンクの送信 |
| POST | `/api/uploads/:token/complete` | マルチパート確定 + 共有トークン発行 |
| DELETE | `/api/uploads/:token` | 中断（R2 のマルチパートも中止） |
| POST | `/api/files/:token/info` | メタデータ取得（要 authToken） |
| POST | `/api/files/:token/claim` | ダウンロード回数を 1 消費してグラント取得 |
| POST | `/api/files/:token/ping` | ダウンロード中の生存信号（要グラント） |
| POST | `/api/files/:token/finish` | 完了通知。回数上限到達ならこの時点で完全削除（要グラント） |
| GET | `/api/files/:token/files/:file/blob` | 暗号文の取得（Range 対応） |
| DELETE | `/api/files/:token` | 即時削除 |
| POST | `/api/files/:token/receipt` | 削除レシートの取得（authToken 必須） |
| POST | `/api/receipts/verify` | 削除レシートの署名検証（DB は見ない） |

## セットアップ

```bash
npm install

# 1. R2 バケットと D1 データベースを作る
npx wrangler r2 bucket create cryptbox-blobs
npx wrangler d1 create cryptbox          # 出力された database_id を wrangler.jsonc に書く

# 2. スキーマを流す
npm run db:init

# 3. グラント署名用のシークレットを登録
openssl rand -base64 32 | npx wrangler secret put GRANT_SECRET

# 4. デプロイ（コード反映前にスキーマ適用が必要。npm run deploy は自動で行う）
npm run deploy
```

デプロイ後に **TLS 1.3 の設定と R2 のライフサイクルルール** を入れてください
→ [docs/deploy.md](docs/deploy.md)

### ローカル開発

```bash
cp .dev.vars.example .dev.vars   # GRANT_SECRET を適当な値に
npm run db:init:local
npm run dev                      # http://127.0.0.1:8787
```

### テスト

```bash
npm test        # Worker 結合テスト + 暗号テスト + ネイティブ読み書き（50 件）
npm run typecheck
```

## 運用上の注意

- **リンクを失うと復元できません。** 鍵はサーバーにないので、運営者でも復号できません。
- ダウンロードは「グラント」を発行した時点で 1 回消費します。グラントの署名は 12 時間有効で、
  その間は同じ回数のまま再開・レンジ取得ができます（ただし回数上限に達したバンドルは、
  完了通知または生存信号の途絶で先に削除されます）。
- 自動削除は毎分の Cron ＋ R2 のライフサイクルルールの二重化を推奨します。
- `UPLOAD_TOKEN` を設定すると、アップロード API に Bearer 認証を要求できます
  （社内利用など、投稿を絞りたい場合）。
- 公開ホスト版の既定値は **1 リンク合計 5 GiB・有効期限は最長 7 日**（保存コストと濫用対策のため）。
  セルフホストではこれらを `wrangler.jsonc` の `vars`（または `.dev.vars`）で変更できます。
  - `MAX_FILE_SIZE`（バイト）: 1 リンクの合計サイズ上限。既定 5 GiB
  - `MAX_EXPIRY_HOURS`（時間）: 有効期限の上限。既定 168（7 日）。これを超える `expiresIn` は
    サーバーが 400 で拒否します
  - `ADS_ENABLED`: `"1"` で広告枠（ダミー）を表示。既定は無効。
    広告ネットワークは未接続のプレースホルダーのみ
  - クライアントの表示（送信ページの上限文言）は `GET /api/config` で取得した値に追従するため、
    サーバー側の変更だけで反映されます（フロントの再ビルドは不要）

## 現時点で入っていないもの

- アカウント機能（サインイン・受信トレイ・サーバー保存の履歴）。
  本アプリは匿名リンク方式で、送信履歴は端末内にのみ保持します
- レート制限（トークンは 256 bit なので総当たりは非現実的ですが、
  アップロード濫用対策には Cloudflare の Rate Limiting ルールの併用を推奨）
- 受信側での ZIP 一括保存（現状は 1 リンクから個別に保存します）
- ウイルススキャン（サーバー側で中身を見られないため、原理的に不可）
- 広告ネットワークとの接続（広告枠は `ADS_ENABLED=1` で表示。
  現状はネットワーク未接続のプレースホルダーのみ）

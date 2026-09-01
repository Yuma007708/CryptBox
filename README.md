# CryptBox

大容量ファイルを **端末内で暗号化してから** 送る、ギガファイル便ライクな転送サービス。
Cloudflare Workers + R2 + D1 の上で動きます。

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
| 有効期限 | 1 時間 / 24 時間 / 7 日 / 30 日 |
| ダウンロード回数制限 | 1 / 5 / 20 / 100 / 無制限。D1 上で原子的にカウント |
| パスワード付きファイル | リンク＋パスワードの二要素。どちらか一方だけでは復号不可 |
| 自動削除 | Cron Trigger（10 分間隔）で期限切れ・回数超過を R2 ごと削除 |
| 画質の劣化ゼロ | 再エンコードなし。詳細は下記 |

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

## 暗号設計

```
linkSecret  = 32 バイトの乱数                    ← URL の #（サーバーに送られない）
pwKey       = Argon2id(password, pwSalt)         ← パスワード指定時のみ
KEK         = HKDF-SHA256(linkSecret ‖ pwKey, salt=kdfSalt, info="cryptbox/v1/kek")
CEK         = 32 バイトの乱数                    ← ファイル本体の鍵
wrappedCEK  = AES-256-GCM(KEK, CEK)              ← これだけがサーバーに保存される

authToken   = HKDF(linkSecret, info="…/auth")    ← サーバーは SHA-256 だけを保持
pwVerifier  = HKDF(pwKey,      info="…/verify")  ← 同上
```

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
| アップロード | 16 MiB チャンクを 3 並列で送信 → R2 マルチパートアップロード（最大 10,000 パート ≒ 156 GiB）。失敗したチャンクだけ指数バックオフで再送 |
| ダウンロード | 1 本のレスポンスを読みながらチャンク境界で復号。切断されたら **最後に復号し終えた位置から Range で再開** |
| 保存先 | ① File System Access API（Chromium：直接ファイルへ書き込み） → ② Service Worker ストリーム（Firefox / Safari） → ③ Blob（最終手段） |

①②はメモリにファイル全体を載せません。

## 構成

```
shared/format.ts   暗号フォーマットの定義（Worker とブラウザで共有）
src/               Cloudflare Worker（Hono）
  index.ts         API・アセット配信・Cron による自動削除
  schema.sql       D1 スキーマ
web/               フロントエンド（Vite / TypeScript、フレームワークなし）
  src/crypto.ts    鍵導出・暗号化
  src/upload.ts    チャンク分割アップロード
  src/download.ts  ストリーム復号（再開つき）
  src/saver.ts     保存方式のフォールバック
  public/sw.js     ストリーム保存用 Service Worker
test/              Vitest（Worker 結合テスト / 暗号ユニットテスト）
docs/              デプロイ手順・脅威モデル
```

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

# 4. デプロイ
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
npm test        # Worker 結合テスト + 暗号テスト（31 件）
npm run typecheck
```

## 運用上の注意

- **リンクを失うと復元できません。** 鍵はサーバーにないので、運営者でも復号できません。
- ダウンロードは「グラント」を発行した時点で 1 回消費します。グラントは 12 時間有効で、
  その間は同じ回数のまま再開・レンジ取得ができます。
- 自動削除は Cron（10 分間隔）＋ R2 のライフサイクルルールの二重化を推奨します。
- `UPLOAD_TOKEN` を設定すると、アップロード API に Bearer 認証を要求できます
  （社内利用など、投稿を絞りたい場合）。

## 現時点で入っていないもの

- レート制限（トークンは 256 bit なので総当たりは非現実的ですが、
  アップロード濫用対策には Cloudflare の Rate Limiting ルールの併用を推奨）
- 複数ファイルの一括送信（ZIP 化）
- ウイルススキャン（サーバー側で中身を見られないため、原理的に不可）

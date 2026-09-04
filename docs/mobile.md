# スマホアプリ版（iOS / Android）

Web 版のフロントエンドを **Capacitor** でそのまま包み、スマホ特有の部分だけ
ネイティブで補っています。暗号処理（AES-256-GCM / Argon2id / HKDF）は
Web 版と同じコードが WebView 内で動きます。

## Web 版との違い

| 項目 | Web 版 | アプリ版 |
| --- | --- | --- |
| ファイル選択 | `<input type="file">` | ネイティブピッカー。**写真・動画は `skipTranscoding` で元データのまま**（iOS は既定だと HEIC→JPEG などに変換される） |
| 元ファイルの読み出し | `File.slice()` | WebView のローカルファイルサーバー経由。iOS は Range で部分読み、Android は逐次ストリーム |
| 復号したファイルの保存 | File System Access API / Service Worker | `Filesystem` プラグインで Documents に追記。iOS は「ファイル」アプリの「このiPhone内 › CryptBox」、Android は `Documents/CryptBox` |
| 転送中のスリープ | ブラウザ任せ | `keep-awake` で画面消灯を抑止 |
| 共有リンクを開く | ブラウザ | Universal Links / App Links でアプリが開く（要ドメイン設定） |
| 通信先 | 同一オリジン | `VITE_API_BASE` で指定した公開 URL。Worker 側が CORS を許可 |
| 配布コード | サーバーが毎回配信 | アプリに同梱。**サーバーが改竄されても鍵を盗む JS を配れない** |

最後の行が、セキュリティ面でアプリ版の一番の意味です。

## ディレクトリ

```
capacitor.config.ts       appId / appName / webDir
android/                  Android Studio プロジェクト（生成物。コミット対象）
ios/App/                  Xcode プロジェクト（生成物。コミット対象）
assets/                   アイコン・スプラッシュの元画像
web/src/platform.ts       ネイティブ判定
web/src/config.ts         API_BASE / PUBLIC_ORIGIN
web/src/filesource.ts     ファイル読み出しの抽象（File / ネイティブパス）
web/src/native.ts         プラグインのラッパー（ピッカー・保存・共有・ディープリンク）
```

## ビルド手順

### 共通

```bash
npm install

# アプリが通信する公開 URL（デプロイ済みの Worker）を指定してビルドし、
# ネイティブプロジェクトへ同期する
VITE_API_BASE=https://cryptbox.example.com \
VITE_PUBLIC_ORIGIN=https://cryptbox.example.com \
npm run cap:sync
```

`VITE_API_BASE` を変えたときは、もう一度 `npm run cap:sync` を実行してください
（WebView に読み込まれる `index.html` の CSP にも焼き込まれます）。

### Android

- 必要なもの: Android Studio（SDK / JDK 21 同梱）
- `npm run android` で Android Studio が開きます。実機またはエミュレータで ▶
- コマンドラインでデバッグ APK を作る場合:

```bash
cd android && ./gradlew assembleDebug
# → android/app/build/outputs/apk/debug/app-debug.apk
```

GitHub Actions の `android` ジョブが **push / PR ごとにデバッグ APK を作って Artifacts に置きます**。
Settings → Variables に `CRYPTBOX_API_BASE` を設定すると、その URL 向けにビルドされます。

リリース署名は `android/app/build.gradle` の `signingConfigs` に keystore を設定してください
（Google Play へは AAB: `./gradlew bundleRelease`）。

### iOS

- 必要なもの: macOS + Xcode（CocoaPods は不要。Capacitor 8 は Swift Package Manager で
  依存を解決するため、初回に Xcode がパッケージを取得します）
- `npm run ios` で Xcode が開きます。Signing & Capabilities で Team を選び、実機で ▶
- CI の `ios` ジョブ（手動起動）は `App.xcodeproj` をシミュレータ向けに署名なしでビルドし、
  コンパイルが通ることを確認します

`ios/App/App/Info.plist` には次を設定済みです:

- `UIFileSharingEnabled` / `LSSupportsOpeningDocumentsInPlace` … 保存したファイルが「ファイル」アプリに出る
- `NSPhotoLibraryUsageDescription` … 写真・動画ピッカーの説明文

## 共有リンクでアプリを開く（Universal Links / App Links）

`https://<your-domain>/d/<token>#<key>` をタップしたときにブラウザではなくアプリを開く設定です。
フラグメント（`#` 以降の鍵）はどちらの仕組みでもアプリに渡されます。

1. `docs/well-known/` の 2 ファイルを編集する
   - `apple-app-site-association`: `TEAMID` を Apple Developer の Team ID に
   - `assetlinks.json`: 署名証明書の SHA-256 フィンガープリントに
2. 編集したものを `web/public/.well-known/` に置いて Web 版をデプロイする
   （`web/public/_headers` に `Content-Type: application/json` を追加すること）
3. iOS: Xcode の Signing & Capabilities → Associated Domains に `applinks:<your-domain>` を追加
4. Android: `AndroidManifest.xml` 内のコメントアウトされた `intent-filter` を有効化し、ホストを書く

## Turnstile（濫用対策）について

Web 版で `TURNSTILE_SITE_KEY` を設定していると、アプリ版の WebView（`capacitor://localhost` /
`https://localhost`）でも同じフロントエンドコードが Turnstile を読み込もうとします。
**この環境で実際に動くかは未検証です。** Turnstile はダッシュボードでウィジェットごとに
許可ドメインを設定する仕組みのため、`capacitor://localhost` や `https://localhost` を
そのドメイン一覧に追加する必要がある可能性があります（未確認）。うまく通らない場合は、
アプリ版だけ `APP_ORIGINS` 相当の別ルートで Turnstile を迂回する対応が要るかもしれません。
深追いはしていないので、実機で問題が出たら別途調査してください。

## 通信（CORS と TLS）

アプリは `capacitor://localhost`（iOS）/ `https://localhost`（Android）というオリジンから
API を呼ぶため、Worker はこの 2 つを既定で CORS 許可しています。
別のホスト名を `capacitor.config.ts` の `server.hostname` で指定した場合は、
Worker の環境変数 `APP_ORIGINS` にそのオリジンを追加してください。

TLS 1.3 の要件は Cloudflare 側の設定で満たします（`docs/deploy.md`）。
iOS の App Transport Security も既定で TLS を要求します。

## ストア公開の前に

- `capacitor.config.ts` の `appId` を自分の逆ドメイン（例: `jp.example.cryptbox`）に変更し、
  `android/app/build.gradle` の `applicationId` と Xcode の Bundle Identifier も合わせる
- アイコンを差し替える場合は `assets/logo.svg` を編集して `npm run assets`
- App Store の「暗号化の輸出コンプライアンス」質問には「標準的な暗号化（AES など）を使用」と回答する
  （`ITSAppUsesNonExemptEncryption` を `false` にすると毎回の質問を省略できますが、
  該当するか確認のうえ設定してください）

## 既知の制約

- **バックグラウンド転送は非対応**。アプリを閉じたりロックしたりすると転送は中断します
  （画面消灯は keep-awake で抑止しています）。切断時はチャンク単位で再送・再開します
- Android の逐次読み出しは 1 ファイルを先頭から順に読むため、
  途中チャンクの再送が必要になった場合はそのチャンクの暗号文をメモリに保持して再送します
- 受信側の保存は base64 でネイティブへ渡すため、PC 版よりやや遅くなります（数 GB 級でも動作しますが時間はかかります）
- 「共有シートから CryptBox へ送る」（他アプリ → CryptBox）は未実装です。
  iOS は Share Extension が必要で、ネイティブ実装になります

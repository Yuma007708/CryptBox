import type { CapacitorConfig } from '@capacitor/cli';

/**
 * Capacitor（iOS / Android アプリ）の設定。
 * appId はストア登録時に自分の逆ドメインへ変更する。
 */
const config: CapacitorConfig = {
  appId: 'com.cryptbox.app',
  appName: 'CryptBox',
  webDir: 'web/dist',
  ios: {
    // ノッチやホームバー領域まで WebView を広げ、CSS の safe-area で余白を取る
    contentInset: 'automatic',
    scheme: 'capacitor',
  },
  android: {
    allowMixedContent: false,
    // 復号したファイルを Documents に書くため。Android 11+ は自分で作ったファイルのみ扱える
    useLegacyBridge: false,
  },
  plugins: {
    StatusBar: {
      overlaysWebView: true,
    },
  },
};

export default config;

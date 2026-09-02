/**
 * 環境ごとの接続先。
 *
 * Web 版は同一オリジンなので空文字（相対パス）でよい。
 * アプリ版は capacitor://localhost 等から起動するため、API の絶対 URL と、
 * 共有リンクに使う公開オリジンをビルド時に渡す:
 *
 *   VITE_API_BASE=https://cryptbox.example.com \
 *   VITE_PUBLIC_ORIGIN=https://cryptbox.example.com \
 *   npm run build:native
 */
const env = import.meta.env as Record<string, string | undefined>;

/** API のベース URL（末尾スラッシュなし）。空なら相対パス */
export const API_BASE: string = (env.VITE_API_BASE ?? '').replace(/\/+$/, '');

/** 共有リンクに使う公開オリジン */
export const PUBLIC_ORIGIN: string =
  (env.VITE_PUBLIC_ORIGIN ?? '').replace(/\/+$/, '') || API_BASE || location.origin;

export function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}

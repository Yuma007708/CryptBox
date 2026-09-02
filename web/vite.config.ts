import { defineConfig, type Plugin } from 'vite';

/**
 * アプリ版 (VITE_TARGET=native) では index.html に CSP の meta を差し込む。
 * Web 版は _headers で CSP を返しているので不要。
 * アプリは capacitor://localhost から起動するため、API の絶対 URL を connect-src に含める。
 */
function nativeCsp(apiBase: string): Plugin {
  return {
    name: 'cryptbox-native-csp',
    transformIndexHtml(html) {
      const connect = ["'self'", apiBase].filter(Boolean).join(' ');
      const csp = [
        "default-src 'self'",
        "script-src 'self' 'wasm-unsafe-eval'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        `connect-src ${connect}`,
        "worker-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
      ].join('; ');
      return html.replace(
        '<meta charset="utf-8" />',
        `<meta charset="utf-8" />\n    <meta http-equiv="Content-Security-Policy" content="${csp}" />`,
      );
    },
  };
}

export default defineConfig(({ mode }) => {
  const env = process.env;
  const native = env.VITE_TARGET === 'native';
  return {
    root: import.meta.dirname,
    mode,
    build: {
      outDir: 'dist',
      emptyOutDir: true,
      target: 'es2022',
    },
    plugins: native ? [nativeCsp(env.VITE_API_BASE ?? '')] : [],
    server: {
      proxy: {
        '/api': 'http://127.0.0.1:8787',
      },
    },
  };
});

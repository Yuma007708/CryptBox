/**
 * Cloudflare Turnstile の見えないウィジェット（`appearance: 'interaction-only'`）。
 * `GET /api/config` の `turnstileSiteKey` がある場合のみ呼び出す。
 * トークンは 1 回使い切りなので、取得のたびに次のトークンに備えてリセットする。
 */

interface TurnstileRenderOptions {
  sitekey: string;
  appearance: 'always' | 'execute' | 'interaction-only';
  callback: (token: string) => void;
  'error-callback': () => void;
}

interface TurnstileApi {
  render(container: HTMLElement, options: TurnstileRenderOptions): string;
  reset(widgetId: string): void;
  remove(widgetId: string): void;
}

declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

const SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';

let scriptPromise: Promise<TurnstileApi> | null = null;

function loadScript(): Promise<TurnstileApi> {
  scriptPromise ??= new Promise<TurnstileApi>((resolve, reject) => {
    if (window.turnstile) {
      resolve(window.turnstile);
      return;
    }
    const script = document.createElement('script');
    script.src = SCRIPT_URL;
    script.async = true;
    script.onload = () => {
      if (window.turnstile) resolve(window.turnstile);
      else reject(new Error('Turnstile の読み込みに失敗しました'));
    };
    script.onerror = () => reject(new Error('Turnstile の読み込みに失敗しました'));
    document.head.append(script);
  });
  return scriptPromise;
}

export interface TurnstileWidget {
  /** 現在のトークンを取得し、次回に備えて自動でリセットする */
  getToken(): Promise<string>;
}

export async function createTurnstileWidget(
  container: HTMLElement,
  siteKey: string,
): Promise<TurnstileWidget> {
  const turnstile = await loadScript();

  let resolveToken: ((token: string) => void) | null = null;
  let rejectToken: ((error: Error) => void) | null = null;
  let tokenPromise = new Promise<string>((resolve, reject) => {
    resolveToken = resolve;
    rejectToken = reject;
  });

  const widgetId = turnstile.render(container, {
    sitekey: siteKey,
    appearance: 'interaction-only',
    callback: (token) => resolveToken?.(token),
    'error-callback': () => rejectToken?.(new Error('Turnstile の検証に失敗しました')),
  });

  return {
    async getToken(): Promise<string> {
      const token = await tokenPromise;
      tokenPromise = new Promise<string>((resolve, reject) => {
        resolveToken = resolve;
        rejectToken = reject;
      });
      turnstile.reset(widgetId);
      return token;
    },
  };
}

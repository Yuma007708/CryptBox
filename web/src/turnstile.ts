/**
 * Cloudflare Turnstile の見えないウィジェット（`appearance: 'interaction-only'`）。
 * `GET /api/config` の `turnstileSiteKey` がある場合のみ呼び出す。
 * トークンは 1 回使い切りなので、取得のたびに次のトークンに備えてリセットする。
 */

interface TurnstileRenderOptions {
  sitekey: string;
  appearance: 'always' | 'execute' | 'interaction-only';
  /** siteverify 応答に載る用途ラベル。サーバー側で `action === 'upload'` を検証する */
  action: string;
  callback: (token: string) => void;
  'error-callback': () => void;
  'expired-callback': () => void;
  'timeout-callback': () => void;
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
  /**
   * ウィジェットを DOM から撤去する。
   * 復号鍵を画面に出す前に、外部 script 由来の DOM を必ず消すために呼ぶ。
   */
  remove(): void;
}

/** getToken() が待つ上限（ミリ秒）。Turnstile の自動リフレッシュ・初回発行を待つのに十分な余裕を持たせる */
const TOKEN_WAIT_TIMEOUT_MS = 15_000;

interface Waiter {
  resolve: (token: string) => void;
  reject: (error: Error) => void;
}

export async function createTurnstileWidget(
  container: HTMLElement,
  siteKey: string,
): Promise<TurnstileWidget> {
  const turnstile = await loadScript();

  // Turnstile は `interaction-only` でも約 300 秒ごとにトークンを自動リフレッシュし、
  // そのたびに callback を呼び直す。1 回しか resolve しない Promise で保持すると
  // 最初のトークンしか使えず、5 分後の送信が必ず失敗する。
  // そのため「最新のトークン」と「待っている呼び出し」を分けて管理する。
  let latest: string | null = null;
  let waiters: Waiter[] = [];

  const settleWaiters = (settle: (waiter: Waiter) => void) => {
    const pending = waiters;
    waiters = [];
    for (const waiter of pending) settle(waiter);
  };

  let removed = false;

  const widgetId = turnstile.render(container, {
    sitekey: siteKey,
    appearance: 'interaction-only',
    action: 'upload',
    callback: (token) => {
      latest = token;
      settleWaiters((waiter) => waiter.resolve(token));
    },
    'error-callback': () => {
      settleWaiters((waiter) => waiter.reject(new Error('Turnstile の検証に失敗しました')));
    },
    'expired-callback': () => {
      latest = null;
      if (!removed) turnstile.reset(widgetId);
    },
    'timeout-callback': () => {
      latest = null;
      if (!removed) turnstile.reset(widgetId);
    },
  });

  function waitForToken(): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const waiter: Waiter = {
        resolve: (token) => {
          clearTimeout(timer);
          resolve(token);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      };
      const timer = setTimeout(() => {
        waiters = waiters.filter((entry) => entry !== waiter);
        reject(
          new Error('認証の準備がタイムアウトしました。しばらくしてから再度お試しください'),
        );
      }, TOKEN_WAIT_TIMEOUT_MS);
      waiters.push(waiter);
    });
  }

  return {
    async getToken(): Promise<string> {
      if (removed) throw new Error('認証ウィジェットは既に閉じられています');
      try {
        if (latest !== null) {
          const token = latest;
          latest = null;
          return token;
        }
        return await waitForToken();
      } finally {
        // 成功・失敗どちらでもリセットし、次回に備えて待ち合わせを作り直す
        if (!removed) turnstile.reset(widgetId);
      }
    },
    remove(): void {
      if (removed) return;
      removed = true;
      latest = null;
      settleWaiters((waiter) =>
        waiter.reject(new Error('認証ウィジェットが閉じられました')),
      );
      turnstile.remove(widgetId);
      container.replaceChildren();
    },
  };
}

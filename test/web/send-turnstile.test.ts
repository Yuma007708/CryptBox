import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Turnstile widget の初期化が失敗した場合、送信 UI に
 * エラーメッセージと「再試行」ボタンを出し、再試行で widget 作成をやり直せることを確認する。
 */

const getServerConfig = vi.fn();
const createTurnstileWidget = vi.fn();

vi.mock('../../web/src/server-config.js', () => ({ getServerConfig }));
vi.mock('../../web/src/turnstile.js', () => ({ createTurnstileWidget }));

describe('renderSend: Turnstile 初期化失敗時', () => {
  beforeEach(() => {
    vi.resetModules();
    getServerConfig.mockReset();
    createTurnstileWidget.mockReset();
    document.body.innerHTML = '';
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('初期化失敗時にエラーメッセージと再試行ボタンを表示し、再試行で再作成できる', async () => {
    getServerConfig.mockResolvedValue({
      maxFileSize: 1024,
      maxExpiryHours: 24,
      turnstileSiteKey: 'site-key',
    });
    createTurnstileWidget.mockRejectedValueOnce(new Error('boom'));

    const { renderSend } = await import('../../web/src/views/send.js');
    const view = document.createElement('div');
    document.body.append(view);
    renderSend(view);

    // getServerConfig().then(...) の解決を待つ
    await vi.waitFor(() => {
      expect(view.textContent).toContain('認証の読み込みに失敗しました');
    });
    expect(view.textContent).toContain('広告ブロッカー');

    const retryButton = Array.from(view.querySelectorAll('button')).find((btn) =>
      btn.textContent?.includes('再試行'),
    );
    expect(retryButton).toBeTruthy();

    createTurnstileWidget.mockResolvedValueOnce({ getToken: vi.fn() });
    retryButton!.click();

    await vi.waitFor(() => {
      expect(createTurnstileWidget).toHaveBeenCalledTimes(2);
    });
    await vi.waitFor(() => {
      const errorBox = Array.from(view.querySelectorAll('.alert')).find((el) =>
        el.textContent?.includes('認証の読み込みに失敗しました'),
      );
      expect(errorBox).toBeTruthy();
      expect((errorBox as HTMLElement).hidden).toBe(true);
    });
  });
});

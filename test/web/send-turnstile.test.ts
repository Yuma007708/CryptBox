import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * 送信画面における Turnstile ウィジェットのライフサイクル。
 *
 * ウィジェットは右カラムに常駐させず、送信ボタンを押したときに初めて生成し、
 * トークンを取り出したら `remove()` して DOM から撤去する。
 * 完了画面（共有リンク＝復号鍵を表示する画面）に外部 script 由来の DOM を残さないため。
 */

const getServerConfig = vi.fn();
const createTurnstileWidget = vi.fn();
const uploadBundle = vi.fn();

vi.mock('../../web/src/server-config.js', () => ({ getServerConfig }));
vi.mock('../../web/src/turnstile.js', () => ({ createTurnstileWidget }));
vi.mock('../../web/src/upload.js', () => ({ uploadBundle }));

const CONFIG = {
  maxFileSize: 1024 * 1024,
  maxExpiryHours: 24,
  adsEnabled: false,
  turnstileSiteKey: 'site-key' as string | null,
  operatorName: null,
  operatorContact: null,
};

async function mountSend(): Promise<HTMLElement> {
  const { renderSend } = await import('../../web/src/views/send.js');
  const view = document.createElement('div');
  document.body.append(view);
  renderSend(view);
  return view;
}

/** dropzone に File を落として選択状態にする */
function dropFile(view: HTMLElement): void {
  const dropzone = view.querySelector('.dropzone')!;
  const event = new Event('drop', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'dataTransfer', {
    value: { files: [new File(['hello'], 'a.txt', { type: 'text/plain' })] },
  });
  dropzone.dispatchEvent(event);
}

function buttonWithText(view: HTMLElement, text: string): HTMLButtonElement | undefined {
  return Array.from(view.querySelectorAll('button')).find((btn) => btn.textContent?.includes(text));
}

function turnstileContainer(view: HTMLElement): HTMLElement {
  return view.querySelector('.turnstile-container')!;
}

describe('renderSend: Turnstile ウィジェットのライフサイクル', () => {
  beforeEach(() => {
    vi.resetModules();
    getServerConfig.mockReset();
    createTurnstileWidget.mockReset();
    uploadBundle.mockReset();
    getServerConfig.mockResolvedValue({ ...CONFIG });
    window.localStorage?.clear();
    document.body.innerHTML = '';
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('送信前はウィジェットを生成しない（コンテナは空のまま）', async () => {
    const view = await mountSend();

    // getServerConfig().then(...) の解決を待つ
    await vi.waitFor(() => {
      expect(getServerConfig).toHaveBeenCalled();
    });
    await Promise.resolve();

    expect(createTurnstileWidget).not.toHaveBeenCalled();
    expect(turnstileContainer(view).children.length).toBe(0);
  });

  it('送信時に生成し、トークン取得後に remove してコンテナを空にする', async () => {
    const remove = vi.fn();
    const getToken = vi.fn().mockResolvedValue('token-1');
    createTurnstileWidget.mockImplementation(async (container: HTMLElement) => {
      container.append(document.createElement('iframe'));
      return { getToken, remove };
    });
    uploadBundle.mockResolvedValue({
      token: 'tok',
      linkSecret: 'sec',
      url: 'https://example.test/d/tok#sec',
      expiresAt: Date.now() + 3600_000,
      maxDownloads: 1,
    });

    const view = await mountSend();
    dropFile(view);
    buttonWithText(view, '暗号化して送信する')!.click();

    await vi.waitFor(() => {
      expect(uploadBundle).toHaveBeenCalled();
    });

    expect(createTurnstileWidget).toHaveBeenCalledTimes(1);
    expect(uploadBundle.mock.calls[0]![0].turnstileToken).toBe('token-1');
    expect(remove).toHaveBeenCalledTimes(1);

    // 完了画面（共有リンクを表示する画面）に到達した時点でウィジェットは残っていない
    await vi.waitFor(() => {
      expect(view.textContent).toContain('共有リンクができました');
    });
    expect(turnstileContainer(view).children.length).toBe(0);
  });

  it('ウィジェット生成に失敗したらエラーを表示し、アップロードしない', async () => {
    createTurnstileWidget.mockRejectedValue(new Error('boom'));
    vi.spyOn(console, 'error').mockImplementation(() => {});

    const view = await mountSend();
    dropFile(view);
    buttonWithText(view, '暗号化して送信する')!.click();

    await vi.waitFor(() => {
      expect(view.textContent).toContain('認証の読み込みに失敗しました');
    });
    expect(view.textContent).toContain('広告ブロッカー');
    expect(uploadBundle).not.toHaveBeenCalled();
    expect(turnstileContainer(view).children.length).toBe(0);
    // 失敗後は選択状態に戻り、もう一度押せば再試行できる
    expect(buttonWithText(view, '暗号化して送信する')).toBeTruthy();
  });

  it('トークン取得に失敗しても remove してコンテナを空にする', async () => {
    const remove = vi.fn();
    createTurnstileWidget.mockImplementation(async (container: HTMLElement) => {
      container.append(document.createElement('iframe'));
      return { getToken: vi.fn().mockRejectedValue(new Error('認証に失敗しました')), remove };
    });

    const view = await mountSend();
    dropFile(view);
    buttonWithText(view, '暗号化して送信する')!.click();

    await vi.waitFor(() => {
      expect(remove).toHaveBeenCalledTimes(1);
    });
    expect(uploadBundle).not.toHaveBeenCalled();
    expect(turnstileContainer(view).children.length).toBe(0);
  });

  it('サイトキーが無ければ（Turnstile 無効）ウィジェットを作らずトークン無しで送る', async () => {
    getServerConfig.mockResolvedValue({ ...CONFIG, turnstileSiteKey: null });
    uploadBundle.mockResolvedValue({
      token: 'tok',
      linkSecret: 'sec',
      url: 'https://example.test/d/tok#sec',
      expiresAt: Date.now() + 3600_000,
      maxDownloads: 1,
    });

    const view = await mountSend();
    dropFile(view);
    buttonWithText(view, '暗号化して送信する')!.click();

    await vi.waitFor(() => {
      expect(uploadBundle).toHaveBeenCalled();
    });
    expect(createTurnstileWidget).not.toHaveBeenCalled();
    expect(uploadBundle.mock.calls[0]![0].turnstileToken).toBeUndefined();
  });
});

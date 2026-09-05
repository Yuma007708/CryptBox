import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { createTurnstileWidget as CreateTurnstileWidget } from '../../web/src/turnstile.js';

// turnstile.ts はスクリプト読み込み結果をモジュールスコープでキャッシュするため、
// テストごとに window.turnstile を差し替えて分離できるようモジュールを毎回リセットする。
let createTurnstileWidget: typeof CreateTurnstileWidget;
beforeEach(async () => {
  vi.resetModules();
  ({ createTurnstileWidget } = await import('../../web/src/turnstile.js'));
});

/**
 * happy-dom 環境。`window.turnstile` を最初から用意しておくことで
 * `loadScript()` の script タグ読み込みをバイパスし、コールバックの挙動だけを検証する。
 */

interface FakeRenderOptions {
  sitekey: string;
  appearance: string;
  action?: string;
  callback: (token: string) => void;
  'error-callback': () => void;
  'expired-callback'?: () => void;
  'timeout-callback'?: () => void;
}

function installFakeTurnstile() {
  const resetSpy = vi.fn();
  let captured: FakeRenderOptions | null = null;
  const api = {
    render: vi.fn((container: HTMLElement, options: FakeRenderOptions) => {
      captured = options;
      // 実物の Turnstile は iframe を差し込む。remove() で消えることを検証するため模倣する。
      container.append(document.createElement('iframe'));
      return 'widget-1';
    }),
    reset: resetSpy,
    remove: vi.fn(),
  };
  (window as unknown as { turnstile: typeof api }).turnstile = api;
  return {
    api,
    resetSpy,
    options: () => captured!,
    fireToken: (token: string) => captured!.callback(token),
    fireError: () => captured!['error-callback'](),
    fireExpired: () => captured!['expired-callback']?.(),
    fireTimeout: () => captured!['timeout-callback']?.(),
  };
}

describe('createTurnstileWidget', () => {
  afterEach(() => {
    delete (window as unknown as { turnstile?: unknown }).turnstile;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('callback で来たトークンを getToken() で取得でき、reset を呼ぶ', async () => {
    const fake = installFakeTurnstile();
    const widget = await createTurnstileWidget(document.createElement('div'), 'site-key');

    fake.fireToken('token-1');
    const token = await widget.getToken();

    expect(token).toBe('token-1');
    expect(fake.resetSpy).toHaveBeenCalledWith('widget-1');
  });

  it('自動リフレッシュで来た新しいトークンを最新値として使う（消費せず古いトークンで固まらない）', async () => {
    const fake = installFakeTurnstile();
    const widget = await createTurnstileWidget(document.createElement('div'), 'site-key');

    // ページを開いた直後の初回トークン
    fake.fireToken('token-1');
    // getToken() を呼ばないまま、Turnstile が 300 秒後に自動リフレッシュ
    fake.fireToken('token-2');

    const token = await widget.getToken();
    expect(token).toBe('token-2');
  });

  it('まだトークンが無ければ callback が来るまで待機する', async () => {
    const fake = installFakeTurnstile();
    const widget = await createTurnstileWidget(document.createElement('div'), 'site-key');

    const pending = widget.getToken();
    fake.fireToken('token-later');

    await expect(pending).resolves.toBe('token-later');
  });

  it('15 秒待っても来なければ日本語のエラーで reject する', async () => {
    vi.useFakeTimers();
    installFakeTurnstile();
    const widget = await createTurnstileWidget(document.createElement('div'), 'site-key');

    const pending = widget.getToken();
    const assertion = expect(pending).rejects.toThrow(/秒|タイムアウト|時間をおいて/);
    await vi.advanceTimersByTimeAsync(15_000);
    await assertion;
  });

  it('error-callback の後も、次に有効なトークンが来れば getToken() が使える（reject 済み Promise が残らない）', async () => {
    const fake = installFakeTurnstile();
    const widget = await createTurnstileWidget(document.createElement('div'), 'site-key');

    const failing = widget.getToken();
    fake.fireError();
    await expect(failing).rejects.toThrow();

    const succeeding = widget.getToken();
    fake.fireToken('token-recovered');
    await expect(succeeding).resolves.toBe('token-recovered');
  });

  it("render に action:'upload' を渡す（サーバー側で siteverify の action を検証するため）", async () => {
    const fake = installFakeTurnstile();
    await createTurnstileWidget(document.createElement('div'), 'site-key');

    expect(fake.options().action).toBe('upload');
    expect(fake.options().sitekey).toBe('site-key');
  });

  it('remove() で turnstile.remove が呼ばれ、コンテナが空になる', async () => {
    const fake = installFakeTurnstile();
    const container = document.createElement('div');
    const widget = await createTurnstileWidget(container, 'site-key');
    expect(container.children.length).toBe(1);

    widget.remove();

    expect(fake.api.remove).toHaveBeenCalledWith('widget-1');
    expect(container.children.length).toBe(0);
  });

  it('remove() は二重呼び出しでも 1 度しか撤去せず、以後 reset も呼ばない', async () => {
    const fake = installFakeTurnstile();
    const widget = await createTurnstileWidget(document.createElement('div'), 'site-key');

    widget.remove();
    widget.remove();
    expect(fake.api.remove).toHaveBeenCalledTimes(1);

    fake.resetSpy.mockClear();
    await expect(widget.getToken()).rejects.toThrow();
    expect(fake.resetSpy).not.toHaveBeenCalled();
  });

  it('expired-callback / timeout-callback は latest をクリアし widget を reset する', async () => {
    const fake = installFakeTurnstile();
    const widget = await createTurnstileWidget(document.createElement('div'), 'site-key');

    fake.fireToken('token-1');
    fake.fireExpired();
    fake.resetSpy.mockClear();

    // 期限切れ後は待機に入るはず（古い latest を使い回さない）
    const pending = widget.getToken();
    fake.fireToken('token-fresh');
    await expect(pending).resolves.toBe('token-fresh');
    expect(fake.resetSpy).toHaveBeenCalledWith('widget-1');
  });
});

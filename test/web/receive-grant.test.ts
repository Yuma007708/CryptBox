import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../web/src/api.js';
import { toBase64Url } from '../../shared/format.js';

/**
 * `ensureGrant`（web/src/views/receive.ts）は、グラントの残り時間が短くなったら
 * 新しい `/refresh` エンドポイント（回数を消費しない）で延長する。
 * 従来のように `claim`（回数を 1 消費）をやり直してはいけない。
 * refresh が失敗（403/404 = グラント無効・リンク失効）した場合も claim へは
 * フォールバックせず、エラーとして扱う。
 */

const claimMock = vi.fn();
const refreshGrantMock = vi.fn();
const decryptedStreamMock = vi.fn();
const fetchInfoMock = vi.fn();
const openBundleMock = vi.fn();
const finishDownloadMock = vi.fn();
const pingDownloadMock = vi.fn();
const createSaverMock = vi.fn();

class WrongPasswordStub extends Error {}

vi.mock('../../web/src/download.js', () => ({
  claim: claimMock,
  refreshGrant: refreshGrantMock,
  decryptedStream: decryptedStreamMock,
  fetchInfo: fetchInfoMock,
  finishDownload: finishDownloadMock,
  finishDownloadBeacon: vi.fn(),
  openBundle: openBundleMock,
  pingDownload: pingDownloadMock,
  reportBundle: vi.fn(),
  WrongPassword: WrongPasswordStub,
}));

vi.mock('../../web/src/saver.js', () => ({
  createSaver: createSaverMock,
  prepareServiceWorker: vi.fn().mockResolvedValue(null),
}));

// adSlot() が叩く /api/config への実ネットワーク呼び出しを避ける（本テストの関心事ではない）
vi.mock('../../web/src/server-config.js', () => ({
  getServerConfig: vi.fn().mockResolvedValue({
    maxFileSize: 1024,
    maxExpiryHours: 24,
    adsEnabled: false,
    turnstileSiteKey: null,
    operatorName: null,
    operatorContact: null,
  }),
}));

const SECRET = toBase64Url(new Uint8Array(32).fill(7));

function makeInfo(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    createdAt: Date.now(),
    expiresAt: Date.now() + 3600_000,
    maxDownloads: 2,
    remainingDownloads: 2,
    totalPlainSize: 10,
    kdfSalt: toBase64Url(new Uint8Array(16)),
    hasPassword: false,
    pwSalt: null,
    pwParams: null,
    files: [
      { index: 0, plainSize: 5, cipherSize: 21, chunkSize: 5, totalChunks: 1, noncePrefix: 'AAAA', wrappedCek: 'AAAA', wrapNonce: 'AAAA', metaCipher: 'AAAA', metaNonce: 'AAAA' },
      { index: 1, plainSize: 5, cipherSize: 21, chunkSize: 5, totalChunks: 1, noncePrefix: 'AAAA', wrappedCek: 'AAAA', wrapNonce: 'AAAA', metaCipher: 'AAAA', metaNonce: 'AAAA' },
    ],
    ...overrides,
  };
}

function makeOpened(info: ReturnType<typeof makeInfo>) {
  return {
    pwVerifier: null,
    files: info.files.map((remote, i) => ({
      remote,
      meta: { name: `file-${i}.txt`, type: 'text/plain', size: remote.plainSize },
      cek: {} as CryptoKey,
    })),
  };
}

function emptyStream(): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      controller.close();
    },
  });
}

async function mountReceive(token: string): Promise<HTMLElement> {
  window.location.hash = `#${SECRET}`;
  const { renderReceive } = await import('../../web/src/views/receive.js');
  const root = document.createElement('div');
  document.body.append(root);
  renderReceive(root, token);
  return root;
}

function downloadButtons(root: HTMLElement): HTMLButtonElement[] {
  return Array.from(root.querySelectorAll('.icon-button'));
}

describe('receive: ensureGrant の自動延長', () => {
  beforeEach(() => {
    claimMock.mockReset();
    refreshGrantMock.mockReset();
    decryptedStreamMock.mockReset().mockReturnValue(emptyStream());
    fetchInfoMock.mockReset();
    openBundleMock.mockReset();
    finishDownloadMock.mockReset().mockResolvedValue({ deleted: false });
    pingDownloadMock.mockReset().mockResolvedValue(undefined);
    createSaverMock.mockReset().mockResolvedValue({
      method: 'blob',
      description: 'test',
      writable: new WritableStream<Uint8Array>({ write: () => undefined }),
      finish: vi.fn().mockResolvedValue(undefined),
      abort: vi.fn().mockResolvedValue(undefined),
    });
    document.body.innerHTML = '';
    window.location.hash = '';
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('残り時間が短くなったら claim ではなく refresh でグラントを延長する', async () => {
    const info = makeInfo();
    fetchInfoMock.mockResolvedValue(info);
    openBundleMock.mockResolvedValue(makeOpened(info));
    // 発行直後から残り 5 分（<10 分)。2 回目の ensureGrant で refresh が呼ばれる
    claimMock.mockResolvedValue({
      grant: 'grant-1',
      grantExpiresAt: Date.now() + 5 * 60_000,
      remainingDownloads: 2,
    });
    refreshGrantMock.mockResolvedValue({ grant: 'grant-2', expiresAt: Date.now() + 3600_000 });

    const root = await mountReceive('tok');
    await vi.waitFor(() => expect(downloadButtons(root).length).toBe(2));

    const buttons = downloadButtons(root);
    buttons[0]!.click();
    await vi.waitFor(() => expect(claimMock).toHaveBeenCalledTimes(1));
    await vi.waitFor(() => expect(decryptedStreamMock).toHaveBeenCalledTimes(1));
    expect(decryptedStreamMock.mock.calls[0]![0].grant).toBe('grant-1');

    buttons[1]!.click();
    await vi.waitFor(() => expect(refreshGrantMock).toHaveBeenCalledTimes(1));
    expect(claimMock).toHaveBeenCalledTimes(1); // claim はやり直されない（回数を消費しない）
    expect(refreshGrantMock).toHaveBeenCalledWith('tok', expect.any(Uint8Array), 'grant-1');

    await vi.waitFor(() => expect(decryptedStreamMock).toHaveBeenCalledTimes(2));
    expect(decryptedStreamMock.mock.calls[1]![0].grant).toBe('grant-2');
  });

  it('refresh が 403 で失敗したら claim にフォールバックせずエラーにする', async () => {
    const info = makeInfo();
    fetchInfoMock.mockResolvedValue(info);
    openBundleMock.mockResolvedValue(makeOpened(info));
    claimMock.mockResolvedValue({
      grant: 'grant-1',
      grantExpiresAt: Date.now() + 5 * 60_000,
      remainingDownloads: 2,
    });
    refreshGrantMock.mockRejectedValue(new ApiError('グラントが無効です', 403));

    const root = await mountReceive('tok');
    await vi.waitFor(() => expect(downloadButtons(root).length).toBe(2));
    const buttons = downloadButtons(root);

    buttons[0]!.click();
    await vi.waitFor(() => expect(claimMock).toHaveBeenCalledTimes(1));
    await vi.waitFor(() => expect(decryptedStreamMock).toHaveBeenCalledTimes(1));

    buttons[1]!.click();
    await vi.waitFor(() => expect(refreshGrantMock).toHaveBeenCalledTimes(1));

    expect(claimMock).toHaveBeenCalledTimes(1);
    // decryptedStream は 2 回目には到達しない（refresh 失敗でエラーになる）
    expect(decryptedStreamMock).toHaveBeenCalledTimes(1);

    await vi.waitFor(() => {
      expect(root.textContent).toContain('リンクの有効期限が切れました。ページを開き直してください');
    });
  });
});

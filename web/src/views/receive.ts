import { clear, h } from '../dom.js';
import { brandMark, extensionLabel, icon } from '../icons.js';
import { formatBytes, formatDateTime, formatDuration } from '../format.js';
import { deriveAuthToken } from '../crypto.js';
import {
  claim,
  decryptedStream,
  fetchInfo,
  finishDownload,
  finishDownloadBeacon,
  openBundle,
  pingDownload,
  reportBundle,
  WrongPassword,
  type BundleInfo,
  type Claim,
  type OpenedBundle,
  type OpenedFile,
  type ReportReason,
} from '../download.js';
import { createSaver, prepareServiceWorker, type Saver } from '../saver.js';
import { keepAwake, shareFile } from '../native.js';
import { isNative } from '../platform.js';
import { fromBase64Url } from '../../../shared/format.js';
import type { DeletionReceipt } from '../../../shared/receipt.js';
import { renderReceiptCard } from '../receipt-ui.js';
import { ApiError } from '../api.js';
import { createTracker, describeError } from '../ui.js';

export function renderReceive(root: HTMLElement, token: string): void {
  const alert = h('div', { class: 'alert', hidden: true });
  const body = h('div', {});

  const inner = h(
    'div',
    { class: 'receive-inner' },
    h(
      'div',
      { class: 'receive-brand' },
      brandMark(30),
      h('span', { class: 'brand-name' }, 'Crypt', h('em', {}, 'Box')),
    ),
    h('p', { class: 'receive-tagline' }, '暗号化して、安全に送る。'),
    alert,
    body,
  );
  root.append(h('div', { class: 'receive' }, inner));

  const showError = (message: string) => {
    clear(alert);
    alert.append(icon('shield', 'icon-sm'), h('span', {}, message));
    alert.hidden = false;
  };
  const clearError = () => {
    alert.hidden = true;
  };

  const rawSecret = location.hash.replace(/^#/, '');
  if (!rawSecret) {
    showError('URL に復号鍵（# より後ろ）が含まれていません。共有されたリンクをそのまま開いてください。');
    return;
  }

  let linkSecret: Uint8Array;
  try {
    linkSecret = fromBase64Url(rawSecret);
  } catch {
    showError('復号鍵の形式が不正です。');
    return;
  }

  body.append(
    h(
      'div',
      { class: 'card' },
      h('div', { class: 'empty' }, h('div', { class: 'spinner' }), h('p', {}, 'ファイル情報を取得しています…')),
    ),
  );

  void prepareServiceWorker();
  void load();

  async function load(): Promise<void> {
    let info: BundleInfo;
    let authToken: Uint8Array;
    try {
      authToken = await deriveAuthToken(linkSecret);
      info = await fetchInfo(token, authToken);
    } catch (error) {
      clear(body);
      showError(describeError(error));
      if (error instanceof ApiError && error.receipt) {
        body.append(renderReceiptCard(error.receipt));
      }
      return;
    }

    if (info.hasPassword) {
      renderPasswordPrompt(info, authToken);
    } else {
      try {
        const opened = await openBundle(info, linkSecret, '');
        renderFiles(info, authToken, opened);
      } catch (error) {
        clear(body);
        showError(describeError(error));
      }
    }
  }

  function remainingText(remaining: number | null): string {
    return remaining === null ? '無制限' : `${remaining} 回`;
  }

  /** @param remainingCell 残り回数の表示セル。完了後に更新するため呼び出し側が保持できる */
  function summaryOf(info: BundleInfo, remainingCell?: HTMLElement): HTMLElement {
    return h(
      'dl',
      { class: 'summary' },
      h('dt', {}, '合計サイズ'),
      h('dd', {}, formatBytes(info.totalPlainSize)),
      h('dt', {}, '有効期限'),
      h(
        'dd',
        {},
        `${formatDateTime(info.expiresAt)}（残り ${formatDuration((info.expiresAt - Date.now()) / 1000)}）`,
      ),
      h('dt', {}, '残りダウンロード'),
      remainingCell ?? h('dd', {}, remainingText(info.remainingDownloads)),
    );
  }

  const REPORT_REASONS: Array<{ value: ReportReason; label: string }> = [
    { value: 'malware', label: 'マルウェア・不正なプログラム' },
    { value: 'illegal', label: '違法なコンテンツ' },
    { value: 'copyright', label: '著作権など他者の権利の侵害' },
    { value: 'other', label: 'その他' },
  ];

  /**
   * このリンクを通報する UI。復号鍵（location.hash）は読まない。
   * トークンはパス由来なので、鍵を持っていない人でも通報できる。
   */
  function reportSection(): HTMLElement {
    const openLink = h('button', { type: 'button', class: 'link' }, 'このリンクを通報');
    const form = h('div', { class: 'report-form', hidden: true });
    const container = h('div', { class: 'report-section' }, openLink, form);

    openLink.addEventListener('click', () => {
      openLink.hidden = true;
      form.hidden = false;
      renderForm();
    });

    function renderForm(): void {
      clear(form);

      const reasonSelect = h('select', { aria: { label: '通報の理由' } });
      for (const reason of REPORT_REASONS) {
        reasonSelect.append(h('option', { value: reason.value }, reason.label));
      }

      const detail = h('textarea', {
        placeholder: '詳細（任意、500 文字まで）',
        aria: { label: '通報の詳細（任意）' },
      }) as HTMLTextAreaElement;
      detail.maxLength = 500;
      detail.rows = 3;

      const submit = h('button', { type: 'button', class: 'primary' }, '通報する');
      const cancel = h('button', { type: 'button', class: 'link' }, 'キャンセル');
      const status = h('p', { class: 'hint', hidden: true });

      cancel.addEventListener('click', () => {
        form.hidden = true;
        openLink.hidden = false;
      });

      submit.addEventListener('click', () => {
        void (async () => {
          submit.disabled = true;
          status.hidden = true;
          try {
            await reportBundle(token, reasonSelect.value as ReportReason, detail.value.trim());
            clear(form);
            form.append(
              h('p', { class: 'hint' }, '通報を受け付けました。内容は運営者が確認します。'),
            );
          } catch {
            status.hidden = false;
            status.textContent = '通報の送信に失敗しました。時間をおいて再度お試しください。';
            submit.disabled = false;
          }
        })();
      });

      form.append(
        h('div', { class: 'report-row' }, reasonSelect),
        h('div', { class: 'report-row' }, detail),
        status,
        h('div', { class: 'card-actions' }, cancel, submit),
      );
    }

    return container;
  }

  function renderPasswordPrompt(info: BundleInfo, authToken: Uint8Array): void {
    clear(body);
    const input = h('input', { type: 'password', autocomplete: 'current-password' });
    const button = h('button', { type: 'button', class: 'primary' });
    button.append(icon('lock', 'icon-sm'), h('span', {}, 'パスワードを確認'));

    const submit = async () => {
      clearError();
      button.disabled = true;
      const label = button.querySelector('span')!;
      label.textContent = 'Argon2id で鍵を導出中…';
      try {
        const opened = await openBundle(info, linkSecret, input.value);
        renderFiles(info, authToken, opened);
      } catch (error) {
        showError(error instanceof WrongPassword ? 'パスワードが違います' : describeError(error));
        button.disabled = false;
        label.textContent = 'パスワードを確認';
      }
    };

    button.addEventListener('click', () => void submit());
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') void submit();
    });

    body.append(
      h(
        'div',
        { class: 'card' },
        h(
          'div',
          { class: 'card-head' },
          h('h2', { class: 'card-title' }, 'パスワードで保護されています'),
          h('span', { class: 'badge' }, icon('lock', 'icon-sm'), 'Argon2id'),
        ),
        h('p', { class: 'hint' }, '送信者から共有されたパスワードを入力してください。'),
        h('div', { class: 'password-row' }, input),
        h('div', { class: 'card-actions' }, h('span', {}), button),
        summaryOf(info),
      ),
    );
    input.focus();
  }

  function renderFiles(info: BundleInfo, authToken: Uint8Array, opened: OpenedBundle): void {
    clear(body);
    let grant: Claim | null = null;
    let busy = false;
    let finished = false;
    let deleted = false;
    let lastPingAt = 0;
    let pingTimer: ReturnType<typeof setInterval> | null = null;
    const completed = new Set<number>();
    const fileButtons: HTMLButtonElement[] = [];
    const summaryRemaining = h('dd', {}, remainingText(info.remainingDownloads));

    const ensureGrant = async (): Promise<Claim> => {
      if (grant && grant.grantExpiresAt > Date.now() + 60_000) return grant;
      grant = await claim(token, authToken, opened.pwVerifier);
      // ページを開いている間は生存信号を送り続ける。
      // 回数上限に達したバンドルは、この信号が途絶えるとサーバー側で削除される
      pingTimer ??= setInterval(() => void sendPing(), 60_000);
      return grant;
    };

    const sendPing = async (): Promise<void> => {
      if (!grant || finished) return;
      lastPingAt = Date.now();
      await pingDownload(token, grant.grant).catch(() => undefined);
    };

    /** すべて完了 or ページ離脱で 1 回だけ呼ぶ。上限到達ならこの瞬間に完全削除される */
    const sendFinish = async (): Promise<void> => {
      if (!grant || finished) return;
      finished = true;
      if (pingTimer) clearInterval(pingTimer);
      try {
        const result = await finishDownload(token, grant.grant);
        if (result.deleted) markDeleted(result.receipt ?? null);
      } catch {
        /* 削除は Cron が猶予時間後に引き継ぐ */
      }
    };

    const markDeleted = (receipt: DeletionReceipt | null): void => {
      deleted = true;
      for (const button of fileButtons) button.disabled = true;
      downloadAll.disabled = true;
      remaining.textContent =
        'ダウンロード上限に達したため、このリンクのデータはサーバーから完全に削除されました。';
      summaryRemaining.textContent = '0 回';
      if (receipt) body.append(renderReceiptCard(receipt));
    };

    window.addEventListener('pagehide', () => {
      if (grant && !finished) {
        finished = true;
        finishDownloadBeacon(token, grant.grant);
      }
    });

    const rows = h('div', {});
    const controls: Array<{ file: OpenedFile; run: (allowPicker: boolean) => Promise<void> }> = [];

    for (const entry of opened.files) {
      const bar = h('div', { class: 'progress-bar' });
      const progress = h('div', { class: 'progress', hidden: true }, bar);
      const detail = h('p', { class: 'progress-detail', hidden: true });
      const savedNote = h('div', { class: 'saved-note', hidden: true });
      const status = h('span', { class: 'file-size' }, formatBytes(entry.meta.size));

      const button = h('button', {
        type: 'button',
        class: 'icon-button',
        title: `${entry.meta.name} をダウンロード`,
      });
      button.append(icon('download', 'icon-sm'));

      const run = async (allowPicker: boolean): Promise<void> => {
        if (busy) return;
        clearError();

        let saver: Saver;
        try {
          saver = await createSaver(entry.meta.name, entry.meta.size, { allowPicker });
        } catch (error) {
          if (error instanceof DOMException && error.name === 'AbortError') return;
          showError(describeError(error));
          return;
        }

        busy = true;
        button.disabled = true;
        progress.hidden = false;
        detail.hidden = false;
        bar.style.width = '0%';
        const track = createTracker(entry.meta.size);
        const controller = new AbortController();
        await keepAwake(true);

        try {
          const granted = await ensureGrant();
          const stream = decryptedStream({
            token,
            grant: granted.grant,
            file: entry.remote,
            cek: entry.cek,
            signal: controller.signal,
            onProgress: (done) => {
              const state = track(done);
              bar.style.width = `${(state.ratio * 100).toFixed(1)}%`;
              detail.textContent = state.text;
              if (Date.now() - lastPingAt > 60_000) void sendPing();
            },
            onRetry: (attempt) => {
              detail.textContent = `接続が切れました。再開しています…（${attempt} 回目）`;
            },
          });

          await stream.pipeTo(saver.writable);
          await saver.finish();

          progress.hidden = true;
          detail.hidden = true;
          clear(status);
          status.append(icon('check', 'icon-sm'));
          status.append(document.createTextNode(' 完了'));
          clear(button);
          button.append(icon('check', 'icon-sm'));
          if (granted.remainingDownloads !== null) {
            remaining.textContent = `残りダウンロード: ${granted.remainingDownloads} 回`;
            summaryRemaining.textContent = remainingText(granted.remainingDownloads);
          }
          if (isNative && saver.savedUri) {
            const uri = saver.savedUri;
            clear(savedNote);
            savedNote.append(
              h('span', {}, `保存先: ${saver.location ?? ''}`),
              h(
                'button',
                {
                  type: 'button',
                  class: 'link',
                  on: { click: () => void shareFile(uri, entry.meta.name).catch(() => undefined) },
                },
                '共有 / 他のアプリで開く',
              ),
            );
            savedNote.hidden = false;
          }
          completed.add(entry.remote.index);
          if (completed.size === opened.files.length) await sendFinish();
        } catch (error) {
          controller.abort();
          await saver.abort(error);
          progress.hidden = true;
          detail.hidden = true;
          button.disabled = false;
          showError(describeError(error));
        } finally {
          busy = false;
          await keepAwake(false);
        }
      };

      button.addEventListener('click', () => void run(true));
      fileButtons.push(button);
      controls.push({ file: entry, run });

      rows.append(
        h(
          'div',
          { class: 'file-row' },
          h('span', { class: 'file-badge' }, extensionLabel(entry.meta.name)),
          h(
            'div',
            { class: 'file-main' },
            h('div', { class: 'file-name' }, entry.meta.name),
            progress,
            detail,
            savedNote,
          ),
          status,
          button,
        ),
      );
    }

    const remaining = h(
      'p',
      { class: 'hint' },
      info.remainingDownloads === null
        ? '残りダウンロード: 無制限'
        : `残りダウンロード: ${info.remainingDownloads} 回`,
    );

    const downloadAll = h('button', { type: 'button', class: 'primary' });
    downloadAll.append(
      icon('download', 'icon-sm'),
      h('span', {}, opened.files.length === 1 ? 'ダウンロード' : 'すべてダウンロード'),
    );
    downloadAll.addEventListener('click', () => {
      void (async () => {
        downloadAll.disabled = true;
        // 2 件目以降はユーザー操作から離れるため、保存ダイアログは使わない
        for (const [index, control] of controls.entries()) {
          await control.run(controls.length === 1 || index === 0);
        }
        // 最後のファイル完了時に削除済みへ遷移していたら、再有効化しない
        if (!deleted) downloadAll.disabled = false;
      })();
    });

    body.append(
      h(
        'div',
        { class: 'card' },
        h(
          'div',
          { class: 'card-head' },
          h(
            'h2',
            { class: 'card-title' },
            opened.files.length === 1
              ? '受信したファイル'
              : `受信したファイル (${opened.files.length})`,
          ),
          h('span', { class: 'badge' }, icon('shield', 'icon-sm'), '暗号化済み'),
        ),
        rows,
        h('div', { class: 'card-actions' }, remaining, downloadAll),
      ),
      h(
        'div',
        { class: 'card' },
        h('div', { class: 'card-head' }, h('h2', { class: 'card-title' }, 'このリンクについて')),
        summaryOf(info, summaryRemaining),
        h(
          'p',
          { class: 'hint' },
          '復号はこのブラウザ内で行われます。サーバーは鍵もファイル名も持っていません。',
        ),
        reportSection(),
      ),
    );
  }
}

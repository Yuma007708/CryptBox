import { clear, h } from '../dom.js';
import { extensionLabel, icon } from '../icons.js';
import { formatBytes, formatDateTime, formatDuration, relativeTime } from '../format.js';
import { activeHistory, historyUrl, removeHistory, type HistoryEntry } from '../history.js';
import { deleteBundle, fetchReceipt } from '../download.js';
import { deriveAuthToken } from '../crypto.js';
import { fromBase64Url } from '../../../shared/format.js';
import type { DeletionReceipt } from '../../../shared/receipt.js';
import { renderNotDeletedHint, renderReceiptCard } from '../receipt-ui.js';
import { copyToClipboard, describeError, navigate } from '../ui.js';

export function renderHistory(view: HTMLElement): void {
  const alert = h('div', { class: 'alert', hidden: true });
  const list = h('div', { class: 'card' });
  const receiptPanel = h('div', { hidden: true });

  view.append(
    h('h1', { class: 'view-title' }, '送信履歴'),
    h(
      'p',
      { class: 'view-lead' },
      '履歴はこの端末のブラウザにだけ保存されます。サーバーには残りません。',
    ),
    alert,
    list,
    receiptPanel,
  );

  const showError = (message: string) => {
    clear(alert);
    alert.append(icon('shield', 'icon-sm'), h('span', {}, message));
    alert.hidden = false;
  };

  const showReceipt = (receipt: DeletionReceipt) => {
    clear(receiptPanel);
    receiptPanel.append(renderReceiptCard(receipt));
    receiptPanel.hidden = false;
  };

  async function checkReceipt(entry: HistoryEntry): Promise<void> {
    clear(receiptPanel);
    receiptPanel.hidden = false;
    receiptPanel.append(
      h('div', { class: 'card' }, h('div', { class: 'empty' }, h('div', { class: 'spinner' }), h('p', {}, '確認しています…'))),
    );
    try {
      const authToken = await deriveAuthToken(fromBase64Url(entry.linkSecret));
      const result = await fetchReceipt(entry.token, authToken);
      clear(receiptPanel);
      if (result.deleted && result.receipt) {
        receiptPanel.append(renderReceiptCard(result.receipt));
      } else {
        receiptPanel.append(renderNotDeletedHint(entry.expiresAt));
      }
    } catch (error) {
      clear(receiptPanel);
      showError(`削除証明の確認に失敗しました: ${describeError(error)}`);
      receiptPanel.hidden = true;
    }
  }

  async function remove(entry: HistoryEntry): Promise<void> {
    if (!confirm('この共有リンクをサーバーからも削除します。よろしいですか？')) return;
    try {
      const authToken = await deriveAuthToken(fromBase64Url(entry.linkSecret));
      const { receipt } = await deleteBundle(entry.token, authToken);
      if (receipt) showReceipt(receipt);
    } catch (error) {
      // すでに期限切れ・削除済みなら履歴からだけ消せばよい
      showError(`サーバー側の削除に失敗しました: ${describeError(error)}`);
    }
    removeHistory(entry.token);
    render();
  }

  function render(): void {
    clear(list);
    const entries = activeHistory();

    if (entries.length === 0) {
      list.append(
        h(
          'div',
          { class: 'empty' },
          icon('clock'),
          h('p', {}, '有効な送信履歴はまだありません。'),
          h(
            'button',
            { type: 'button', class: 'link', on: { click: () => navigate('/') } },
            'ファイルを送る →',
          ),
        ),
      );
      return;
    }

    list.append(
      h(
        'div',
        { class: 'card-head' },
        h('h2', { class: 'card-title' }, `有効なリンク (${entries.length})`),
        h(
          'span',
          { class: 'card-note' },
          `合計 ${formatBytes(entries.reduce((sum, entry) => sum + entry.totalSize, 0))}`,
        ),
      ),
    );

    for (const entry of entries) {
      const label =
        entry.files.length === 1
          ? entry.files[0]!.name
          : `${entry.files[0]?.name ?? 'ファイル'} ほか ${entry.files.length - 1} 件`;

      list.append(
        h(
          'div',
          { class: 'file-row' },
          h('span', { class: 'file-badge' }, extensionLabel(entry.files[0]?.name ?? '')),
          h(
            'div',
            { class: 'file-main' },
            h('div', { class: 'file-name' }, label),
            h(
              'div',
              { class: 'file-sub' },
              [
                `${relativeTime(entry.createdAt)}に送信`,
                `期限 ${formatDateTime(entry.expiresAt)}（残り ${formatDuration((entry.expiresAt - Date.now()) / 1000)}）`,
                entry.maxDownloads === null ? 'DL 無制限' : `DL ${entry.maxDownloads} 回まで`,
                entry.hasPassword ? 'パスワードあり' : null,
              ]
                .filter(Boolean)
                .join(' · '),
            ),
          ),
          h('span', { class: 'file-size' }, formatBytes(entry.totalSize)),
          h(
            'div',
            { class: 'row-actions' },
            h(
              'button',
              {
                type: 'button',
                class: 'icon-button',
                title: 'リンクをコピー',
                on: {
                  click: (event) =>
                    void copyToClipboard(historyUrl(entry), event.currentTarget as HTMLElement),
                },
              },
              icon('link', 'icon-sm'),
            ),
            h(
              'button',
              {
                type: 'button',
                class: 'icon-button',
                title: '削除証明を確認',
                on: { click: () => void checkReceipt(entry) },
              },
              icon('shield', 'icon-sm'),
            ),
            h(
              'button',
              {
                type: 'button',
                class: 'icon-button',
                title: '今すぐ削除',
                on: { click: () => void remove(entry) },
              },
              icon('trash', 'icon-sm'),
            ),
          ),
        ),
      );
    }
  }

  render();
}

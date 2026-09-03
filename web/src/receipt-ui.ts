import { h } from './dom.js';
import { icon } from './icons.js';
import { formatBytes, formatDateTime } from './format.js';
import { copyToClipboard } from './ui.js';
import { describeDeletionReason, type DeletionReceipt } from '../../shared/receipt.js';

/** 削除レシートを表示するカード。送信履歴・受信ページで共通に使う */
export function renderReceiptCard(receipt: DeletionReceipt): HTMLElement {
  const copyButton = h(
    'button',
    {
      type: 'button',
      class: 'link',
      on: {
        click: (event) =>
          void copyToClipboard(JSON.stringify(receipt), event.currentTarget as HTMLElement),
      },
    },
    icon('copy', 'icon-sm'),
    h('span', {}, '証明をコピー'),
  );

  return h(
    'div',
    { class: 'card' },
    h(
      'div',
      { class: 'card-head' },
      h('h2', { class: 'card-title' }, '削除証明'),
      h('span', { class: 'badge' }, icon('shield', 'icon-sm'), '署名済み'),
    ),
    h(
      'dl',
      { class: 'summary' },
      h('dt', {}, '削除理由'),
      h('dd', {}, describeDeletionReason(receipt.reason)),
      h('dt', {}, '削除日時'),
      h('dd', {}, formatDateTime(receipt.deletedAt)),
      h('dt', {}, 'ファイル数'),
      h('dd', {}, `${receipt.fileCount} 件`),
      h('dt', {}, '合計サイズ'),
      h('dd', {}, formatBytes(receipt.totalPlainSize)),
    ),
    h(
      'p',
      { class: 'hint' },
      'サーバーの秘密鍵で署名済みです。JSON をコピーして「証明の検証」から確認できます。',
    ),
    h('div', { class: 'card-actions' }, h('span', {}), copyButton),
  );
}

export function renderNotDeletedHint(expiresAt: number): HTMLElement {
  return h(
    'div',
    { class: 'card' },
    h('div', { class: 'card-head' }, h('h2', { class: 'card-title' }, '削除証明')),
    h(
      'p',
      { class: 'hint' },
      `まだ削除されていません（有効期限 ${formatDateTime(expiresAt)}）。`,
    ),
  );
}

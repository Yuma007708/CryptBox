import { h } from '../dom.js';
import { icon } from '../icons.js';
import { EXPIRY_OPTIONS } from '../../../shared/format.js';
import { clearHistory, listHistory } from '../history.js';
import { getSettings, updateSettings, type Theme } from '../settings.js';

const THEMES: Array<{ value: Theme; label: string }> = [
  { value: 'system', label: 'OS の設定に従う' },
  { value: 'light', label: 'ライト' },
  { value: 'dark', label: 'ダーク' },
];

const DOWNLOAD_LIMITS: Array<{ label: string; value: number | null }> = [
  { label: '1回まで', value: 1 },
  { label: '5回まで', value: 5 },
  { label: '10回まで', value: 10 },
  { label: '50回まで', value: 50 },
  { label: '無制限', value: null },
];

export function renderSettings(view: HTMLElement): void {
  const settings = getSettings();

  const themeSelect = h('select', {
    aria: { label: 'テーマ' },
    on: { change: () => updateSettings({ theme: themeSelect.value as Theme }) },
  });
  for (const theme of THEMES) themeSelect.append(h('option', { value: theme.value }, theme.label));
  themeSelect.value = settings.theme;

  const expirySelect = h('select', {
    aria: { label: '既定の有効期限' },
    on: { change: () => updateSettings({ defaultExpiry: Number(expirySelect.value) }) },
  });
  for (const option of EXPIRY_OPTIONS) {
    expirySelect.append(h('option', { value: String(option.seconds) }, option.label));
  }
  expirySelect.value = String(settings.defaultExpiry);

  const limitSelect = h('select', {
    aria: { label: '既定のダウンロード回数' },
    on: {
      change: () =>
        updateSettings({
          defaultMaxDownloads: limitSelect.value === '' ? null : Number(limitSelect.value),
        }),
    },
  });
  for (const limit of DOWNLOAD_LIMITS) {
    limitSelect.append(
      h('option', { value: limit.value === null ? '' : String(limit.value) }, limit.label),
    );
  }
  limitSelect.value = settings.defaultMaxDownloads === null ? '' : String(settings.defaultMaxDownloads);

  const historySwitch = h('button', {
    type: 'button',
    class: 'switch',
    role: 'switch',
    aria: { checked: String(settings.keepHistory), label: '送信履歴を保存する' },
    on: {
      click: () => {
        const next = !getSettings().keepHistory;
        updateSettings({ keepHistory: next });
        historySwitch.setAttribute('aria-checked', String(next));
      },
    },
  });

  const count = h('span', { class: 'card-note' }, `${listHistory().length} 件保存されています`);

  view.append(
    h('h1', { class: 'view-title' }, '設定'),
    h('p', { class: 'view-lead' }, 'この端末のブラウザにのみ保存される設定です。'),

    h(
      'div',
      { class: 'card' },
      h('div', { class: 'card-head' }, h('h2', { class: 'card-title' }, '表示')),
      h('div', { class: 'option-row' }, h('span', { class: 'option-label' }, 'テーマ'), themeSelect),
    ),

    h(
      'div',
      { class: 'card' },
      h('div', { class: 'card-head' }, h('h2', { class: 'card-title' }, '送信時の既定値')),
      h(
        'div',
        { class: 'option-row' },
        h('span', { class: 'option-label' }, '有効期限'),
        expirySelect,
      ),
      h(
        'div',
        { class: 'option-row' },
        h('span', { class: 'option-label' }, 'ダウンロード回数'),
        limitSelect,
      ),
    ),

    h(
      'div',
      { class: 'card' },
      h(
        'div',
        { class: 'card-head' },
        h('h2', { class: 'card-title' }, '送信履歴'),
        count,
      ),
      h(
        'p',
        { class: 'hint' },
        '履歴には復号鍵を含む共有リンクが入ります。共有端末で使う場合はオフにしてください。',
      ),
      h(
        'div',
        { class: 'option-row' },
        h('span', { class: 'option-label' }, 'この端末に履歴を保存する'),
        historySwitch,
      ),
      h(
        'div',
        { class: 'card-actions' },
        h(
          'button',
          {
            type: 'button',
            class: 'ghost',
            on: {
              click: () => {
                if (!confirm('この端末の送信履歴をすべて消します。共有リンクは無効になりません。'))
                  return;
                clearHistory();
                count.textContent = '0 件保存されています';
              },
            },
          },
          icon('trash', 'icon-sm'),
          '履歴をすべて消す',
        ),
      ),
    ),
  );
}

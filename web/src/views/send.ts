import { clear, h } from '../dom.js';
import { adSlot } from '../ads.js';
import { extensionLabel, icon } from '../icons.js';
import { formatBytes, formatDateTime, formatDuration, relativeTime } from '../format.js';
import { addHistory, activeHistory, historyUrl } from '../history.js';
import { getSettings } from '../settings.js';
import { uploadBundle, type UploadResult } from '../upload.js';
import { describeError, copyToClipboard, createTracker, navigate } from '../ui.js';
import { fromFile, fromNativePath, type FileSource } from '../filesource.js';
import { isNative } from '../platform.js';
import { keepAwake, pickDocuments, pickMedia } from '../native.js';
import { EXPIRY_OPTIONS, MAX_FILES_PER_BUNDLE } from '../../../shared/format.js';
import { getServerConfig } from '../server-config.js';
import { createTurnstileWidget, type TurnstileWidget } from '../turnstile.js';

/** /api/config が取れるまでの表示用フォールバック（サーバー既定値と同じ） */
const FALLBACK_MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024;

const DOWNLOAD_LIMITS: Array<{ label: string; value: number | null }> = [
  { label: '1回まで', value: 1 },
  { label: '5回まで', value: 5 },
  { label: '10回まで', value: 10 },
  { label: '50回まで', value: 50 },
  { label: '無制限', value: null },
];

interface Options {
  expiresIn: number;
  maxDownloads: number | null;
  passwordEnabled: boolean;
  password: string;
}

export function renderSend(view: HTMLElement): void {
  const settings = getSettings();
  const options: Options = {
    expiresIn: settings.defaultExpiry,
    maxDownloads: settings.defaultMaxDownloads,
    passwordEnabled: false,
    password: '',
  };

  let selected: FileSource[] = [];
  let controller: AbortController | null = null;

  const left = h('div');
  const right = h('div');
  const alert = h('div', { class: 'alert', hidden: true });

  view.append(
    h('h1', { class: 'view-title' }, 'ファイルを送る'),
    h('p', { class: 'view-lead' }, 'ファイルを暗号化して、安全に共有できます。'),
    alert,
    h('div', { class: 'send-grid' }, left, right),
  );

  const showError = (message: string) => {
    clear(alert);
    alert.append(icon('shield', 'icon-sm'), h('span', {}, message));
    alert.hidden = false;
  };
  const clearError = () => {
    alert.hidden = true;
  };

  /* ---------------- 右カラム: オプション設定 ---------------- */

  const passwordInput = h('input', {
    type: 'password',
    autocomplete: 'new-password',
    placeholder: 'パスワードを入力',
    on: {
      input: () => {
        options.password = passwordInput.value;
      },
    },
  });

  const revealButton = h(
    'button',
    {
      type: 'button',
      class: 'icon-button',
      title: 'パスワードを表示',
      on: {
        click: () => {
          const shown = passwordInput.type === 'text';
          passwordInput.type = shown ? 'password' : 'text';
          clear(revealButton);
          revealButton.append(icon(shown ? 'eye' : 'eye-off', 'icon-sm'));
        },
      },
    },
    icon('eye', 'icon-sm'),
  );

  const passwordRow = h('div', { class: 'password-row', hidden: true }, passwordInput, revealButton);

  const passwordSwitch = h('button', {
    type: 'button',
    class: 'switch',
    role: 'switch',
    aria: { checked: 'false', label: 'パスワード保護' },
    on: {
      click: () => {
        options.passwordEnabled = !options.passwordEnabled;
        passwordSwitch.setAttribute('aria-checked', String(options.passwordEnabled));
        passwordRow.hidden = !options.passwordEnabled;
        if (options.passwordEnabled) passwordInput.focus();
        else {
          passwordInput.value = '';
          options.password = '';
        }
      },
    },
  });

  const expirySelect = h('select', {
    aria: { label: '有効期限' },
    on: {
      change: () => {
        options.expiresIn = Number(expirySelect.value);
      },
    },
  });
  for (const option of EXPIRY_OPTIONS) {
    expirySelect.append(h('option', { value: String(option.seconds) }, option.label));
  }
  expirySelect.value = String(options.expiresIn);

  const limitSelect = h('select', {
    aria: { label: 'ダウンロード回数' },
    on: {
      change: () => {
        options.maxDownloads = limitSelect.value === '' ? null : Number(limitSelect.value);
      },
    },
  });
  for (const limit of DOWNLOAD_LIMITS) {
    limitSelect.append(h('option', { value: limit.value === null ? '' : String(limit.value) }, limit.label));
  }
  limitSelect.value = options.maxDownloads === null ? '' : String(options.maxDownloads);

  const optionsCard = h(
    'div',
    { class: 'card' },
    h('div', { class: 'card-head' }, h('h2', { class: 'card-title' }, 'オプション設定')),
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
    h(
      'div',
      { class: 'option-row' },
      h('span', { class: 'option-label' }, 'パスワード保護'),
      passwordSwitch,
    ),
    passwordRow,
    h(
      'div',
      { class: 'info-box' },
      icon('lock'),
      h(
        'div',
        {},
        h('strong', {}, '強力な暗号化'),
        h(
          'span',
          {},
          'AES-256-GCM でブラウザ内で暗号化され、リンクを持つ受信者だけが復号できます。',
        ),
      ),
    ),
  );
  right.append(optionsCard);

  /* ---------------- Turnstile（見えないウィジェット） ---------------- */

  const turnstileContainer = h('div', { class: 'turnstile-container' });
  const turnstileErrorBox = h('div', { class: 'alert', hidden: true });
  right.append(turnstileContainer, turnstileErrorBox);
  let turnstileWidget: TurnstileWidget | null = null;

  function initTurnstile(siteKey: string): void {
    turnstileErrorBox.hidden = true;
    clear(turnstileContainer);
    createTurnstileWidget(turnstileContainer, siteKey)
      .then((widget) => {
        turnstileWidget = widget;
      })
      .catch((error) => {
        console.error('Turnstile の初期化に失敗しました', error);
        clear(turnstileErrorBox);
        turnstileErrorBox.append(
          icon('shield', 'icon-sm'),
          h(
            'span',
            {},
            '認証の読み込みに失敗しました。広告ブロッカーを無効にするか、時間をおいて再度お試しください',
          ),
          h(
            'button',
            {
              type: 'button',
              class: 'ghost',
              on: { click: () => initTurnstile(siteKey) },
            },
            '再試行',
          ),
        );
        turnstileErrorBox.hidden = false;
      });
  }

  void getServerConfig().then((config) => {
    if (!config.turnstileSiteKey) return;
    initTurnstile(config.turnstileSiteKey);
  });

  /* ---------------- 左カラム ---------------- */

  const fileInput = h('input', {
    type: 'file',
    hidden: true,
    on: {
      change: () => {
        addFiles(Array.from(fileInput.files ?? []).map(fromFile));
        fileInput.value = '';
      },
    },
  });
  fileInput.multiple = true;

  const pickButton = h(
    'button',
    {
      type: 'button',
      class: 'primary',
      on: {
        click: (event) => {
          event.stopPropagation();
          fileInput.click();
        },
      },
    },
    'ファイルを選択',
  );

  /** アプリ版: ネイティブピッカーで選び、パスから FileSource を作る */
  const pickNative = async (kind: 'media' | 'documents') => {
    clearError();
    try {
      const picked = kind === 'media' ? await pickMedia() : await pickDocuments();
      addFiles(picked.map((file) => fromNativePath(file)));
    } catch (error) {
      // ユーザーがキャンセルした場合はプラグインが reject するので黙って戻る
      const message = describeError(error).toLowerCase();
      if (message.includes('cancel')) return;
      showError(describeError(error));
    }
  };

  const nativePickers = h(
    'div',
    { class: 'picker-row' },
    h(
      'button',
      { type: 'button', class: 'primary', on: { click: () => void pickNative('media') } },
      icon('file', 'icon-sm'),
      '写真・動画',
    ),
    h(
      'button',
      { type: 'button', class: 'ghost', on: { click: () => void pickNative('documents') } },
      icon('upload', 'icon-sm'),
      'ファイル',
    ),
  );

  const hintText = (maxFileSize: number) => `最大 ${MAX_FILES_PER_BUNDLE} ファイル・合計 ${formatBytes(maxFileSize)} まで`;
  const nativeHint = h('p', { class: 'dropzone-hint' }, hintText(FALLBACK_MAX_FILE_SIZE));
  const webHint = h('p', { class: 'dropzone-hint' }, hintText(FALLBACK_MAX_FILE_SIZE));
  void getServerConfig().then((config) => {
    nativeHint.textContent = hintText(config.maxFileSize);
    webHint.textContent = hintText(config.maxFileSize);
  });

  const dropzone = isNative
    ? h(
        'div',
        { class: 'dropzone' },
        icon('upload'),
        h('p', { class: 'dropzone-title' }, '送るファイルを選ぶ'),
        h('p', { class: 'dropzone-or' }, '写真・動画は元データのまま（無変換）で取り込みます'),
        nativePickers,
        nativeHint,
      )
    : h(
        'div',
        { class: 'dropzone', on: { click: () => fileInput.click() } },
        icon('upload'),
        h('p', { class: 'dropzone-title' }, 'ファイルをドラッグ＆ドロップ'),
        h('p', { class: 'dropzone-or' }, 'または'),
        pickButton,
        webHint,
      );

  for (const type of ['dragenter', 'dragover'] as const) {
    dropzone.addEventListener(type, (event) => {
      event.preventDefault();
      dropzone.classList.add('dragover');
    });
  }
  for (const type of ['dragleave', 'drop'] as const) {
    dropzone.addEventListener(type, () => dropzone.classList.remove('dragover'));
  }
  dropzone.addEventListener('drop', (event) => {
    event.preventDefault();
    addFiles(Array.from(event.dataTransfer?.files ?? []).map(fromFile));
  });

  function addFiles(incoming: FileSource[]): void {
    clearError();
    const seen = new Set(selected.map((file) => file.key));
    for (const file of incoming) {
      if (seen.has(file.key)) continue;
      if (selected.length >= MAX_FILES_PER_BUNDLE) {
        showError(`1 度に送れるのは ${MAX_FILES_PER_BUNDLE} ファイルまでです`);
        break;
      }
      selected.push(file);
      seen.add(file.key);
    }
    renderIdle();
  }

  /* ---------------- 状態ごとの描画 ---------------- */

  function renderIdle(): void {
    clear(left);
    left.append(h('div', { class: 'card' }, fileInput, dropzone));

    if (selected.length > 0) {
      const total = selected.reduce((sum, file) => sum + file.size, 0);
      const list = h('div', {});
      selected.forEach((file, index) => {
        list.append(
          h(
            'div',
            { class: 'file-row' },
            h('span', { class: 'file-badge' }, extensionLabel(file.name)),
            h('div', { class: 'file-main' }, h('div', { class: 'file-name' }, file.name)),
            h('span', { class: 'file-size' }, formatBytes(file.size)),
            h(
              'button',
              {
                type: 'button',
                class: 'icon-button',
                title: 'このファイルを外す',
                on: {
                  click: () => {
                    selected.splice(index, 1);
                    renderIdle();
                  },
                },
              },
              icon('close', 'icon-sm'),
            ),
          ),
        );
      });

      left.append(
        h(
          'div',
          { class: 'card' },
          h(
            'div',
            { class: 'card-head' },
            h('h2', { class: 'card-title' }, `選択中のファイル (${selected.length})`),
            h('span', { class: 'card-note' }, `合計サイズ: ${formatBytes(total)}`),
          ),
          list,
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
                    options.expiresIn = getSettings().defaultExpiry;
                    options.maxDownloads = getSettings().defaultMaxDownloads;
                    options.passwordEnabled = false;
                    options.password = '';
                    passwordInput.value = '';
                    passwordRow.hidden = true;
                    passwordSwitch.setAttribute('aria-checked', 'false');
                    expirySelect.value = String(options.expiresIn);
                    limitSelect.value =
                      options.maxDownloads === null ? '' : String(options.maxDownloads);
                  },
                },
              },
              'オプションをリセット',
            ),
            h(
              'button',
              { type: 'button', class: 'primary', on: { click: () => void start() } },
              icon('lock', 'icon-sm'),
              '暗号化して送信する',
            ),
          ),
        ),
      );
    }

    renderRecent();
  }

  function renderRecent(): void {
    const entries = activeHistory().slice(0, 3);
    if (entries.length === 0) return;

    const list = h('div', {});
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
            h('div', { class: 'file-sub' }, `${relativeTime(entry.createdAt)}に送信`),
          ),
          h('span', { class: 'file-size' }, formatBytes(entry.totalSize)),
          h(
            'span',
            { class: 'file-sub' },
            `有効期限: 残り ${formatDuration((entry.expiresAt - Date.now()) / 1000)}`,
          ),
          h(
            'button',
            {
              type: 'button',
              class: 'icon-button',
              title: 'リンクをコピー',
              on: {
                click: (event) => void copyToClipboard(historyUrl(entry), event.currentTarget as HTMLElement),
              },
            },
            icon('link', 'icon-sm'),
          ),
        ),
      );
    }

    left.append(
      h(
        'div',
        { class: 'card' },
        h(
          'div',
          { class: 'card-head' },
          h('h2', { class: 'card-title' }, '最近の送信'),
          h(
            'button',
            { type: 'button', class: 'link', on: { click: () => navigate('/history') } },
            'すべて見る →',
          ),
        ),
        list,
      ),
    );
  }

  function renderUploading(): {
    stage: HTMLElement;
    bar: HTMLElement;
    detail: HTMLElement;
  } {
    clear(left);
    const stage = h('p', { class: 'card-title' }, '準備中…');
    const bar = h('div', { class: 'progress-bar' });
    const detail = h('p', { class: 'progress-detail' });

    left.append(
      h(
        'div',
        { class: 'card' },
        stage,
        h('div', { class: 'progress' }, bar),
        detail,
        h(
          'div',
          { class: 'card-actions' },
          h(
            'button',
            { type: 'button', class: 'link danger', on: { click: () => controller?.abort() } },
            '中止する',
          ),
        ),
      ),
      adSlot('send-progress'),
    );
    return { stage, bar, detail };
  }

  function renderDone(result: UploadResult, files: FileSource[]): void {
    clear(left);
    const urlInput = h('input', { type: 'text', readOnly: true, value: result.url });

    left.append(
      h(
        'div',
        { class: 'card' },
        h(
          'div',
          { class: 'card-head' },
          h('h2', { class: 'card-title' }, '共有リンクができました'),
          h('span', { class: 'badge' }, icon('check', 'icon-sm'), '暗号化済み'),
        ),
        h(
          'p',
          { class: 'hint' },
          '「#」より後ろが復号鍵です。サーバーには送信されないため、このリンクを失うと誰も復元できません。',
        ),
        h(
          'div',
          { class: 'share-row' },
          urlInput,
          h(
            'button',
            {
              type: 'button',
              class: 'primary',
              on: {
                click: (event) =>
                  void copyToClipboard(result.url, event.currentTarget as HTMLElement),
              },
            },
            icon('copy', 'icon-sm'),
            'コピー',
          ),
        ),
        h(
          'dl',
          { class: 'summary' },
          h('dt', {}, 'ファイル'),
          h('dd', {}, files.length === 1 ? files[0]!.name : `${files.length} 件`),
          h('dt', {}, '合計サイズ'),
          h('dd', {}, formatBytes(files.reduce((sum, file) => sum + file.size, 0))),
          h('dt', {}, '有効期限'),
          h('dd', {}, formatDateTime(result.expiresAt)),
          h('dt', {}, 'ダウンロード回数'),
          h('dd', {}, result.maxDownloads === null ? '無制限' : `${result.maxDownloads} 回まで`),
          h('dt', {}, 'パスワード'),
          h('dd', {}, options.passwordEnabled && options.password ? 'あり（Argon2id）' : 'なし'),
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
                  selected = [];
                  renderIdle();
                },
              },
            },
            icon('plus', 'icon-sm'),
            '別のファイルを送る',
          ),
        ),
      ),
    );
    renderRecent();
  }

  /* ---------------- 送信 ---------------- */

  async function start(): Promise<void> {
    if (selected.length === 0) return;
    if (options.passwordEnabled && options.password.length === 0) {
      showError('パスワード保護が有効です。パスワードを入力してください。');
      return;
    }

    clearError();
    const files = [...selected];
    const totalSize = files.reduce((sum, file) => sum + file.size, 0);
    const ui = renderUploading();
    const track = createTracker(totalSize);
    controller = new AbortController();
    await keepAwake(true);

    try {
      let turnstileToken: string | undefined;
      if (turnstileWidget) {
        ui.stage.textContent = '認証しています…';
        try {
          turnstileToken = await turnstileWidget.getToken();
        } catch (error) {
          throw new Error(describeError(error) || '認証に失敗しました。ページを再読み込みしてください');
        }
      }

      const result = await uploadBundle({
        files,
        password: options.passwordEnabled ? options.password : '',
        expiresIn: options.expiresIn,
        maxDownloads: options.maxDownloads,
        turnstileToken,
        signal: controller.signal,
        onStage: (text) => {
          ui.stage.textContent = text;
        },
        onProgress: (done) => {
          const status = track(done);
          ui.bar.style.width = `${(status.ratio * 100).toFixed(1)}%`;
          ui.detail.textContent = status.text;
        },
      });

      addHistory({
        token: result.token,
        linkSecret: result.linkSecret,
        createdAt: Date.now(),
        expiresAt: result.expiresAt,
        maxDownloads: result.maxDownloads,
        hasPassword: options.passwordEnabled && options.password.length > 0,
        totalSize,
        files: files.map((file) => ({ name: file.name, size: file.size })),
      });

      selected = [];
      renderDone(result, files);
    } catch (error) {
      showError(describeError(error));
      renderIdle();
    } finally {
      controller = null;
      await keepAwake(false);
    }
  }

  renderIdle();
}

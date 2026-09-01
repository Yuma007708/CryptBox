import { ApiError } from './api.js';
import { deriveAuthToken } from './crypto.js';
import {
  claim,
  decryptedStream,
  fetchInfo,
  openFile,
  WrongPassword,
  type FileInfo,
  type OpenedFile,
} from './download.js';
import { formatBytes, formatDateTime, formatDuration, formatRate } from './format.js';
import { createSaver, prepareServiceWorker, type Saver } from './saver.js';
import { uploadFile } from './upload.js';
import { EXPIRY_OPTIONS, fromBase64Url } from '../../shared/format.js';

function el<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error(`#${id} が見つかりません`);
  return node as T;
}

const errorBox = el('error');

function showError(message: string): void {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

function clearError(): void {
  errorBox.hidden = true;
  errorBox.textContent = '';
}

function describe(error: unknown): string {
  if (error instanceof DOMException && error.name === 'AbortError') return '中止しました';
  if (error instanceof ApiError || error instanceof Error) return error.message;
  return '不明なエラーが発生しました';
}

function setSummary(list: HTMLElement, rows: Array<[string, string]>): void {
  list.replaceChildren();
  for (const [term, value] of rows) {
    const dt = document.createElement('dt');
    dt.textContent = term;
    const dd = document.createElement('dd');
    dd.textContent = value;
    list.append(dt, dd);
  }
}

/** 進捗から速度と残り時間を出す（直近の平均） */
function createTracker(total: number) {
  const startedAt = performance.now();
  return (done: number) => {
    const elapsed = (performance.now() - startedAt) / 1000;
    const rate = elapsed > 0 ? done / elapsed : 0;
    const remaining = rate > 0 ? (total - done) / rate : Infinity;
    return {
      ratio: total > 0 ? done / total : 1,
      text: `${formatBytes(done)} / ${formatBytes(total)} · ${formatRate(rate)} · 残り ${formatDuration(remaining)}`,
    };
  };
}

/* ================================================================== *
 * アップロード画面
 * ================================================================== */

function initUpload(): void {
  el('view-upload').hidden = false;

  const dropzone = el<HTMLDivElement>('dropzone');
  const fileInput = el<HTMLInputElement>('file-input');
  const form = el('upload-form');
  const progress = el('upload-progress');
  const result = el('upload-result');
  const expiry = el<HTMLSelectElement>('expiry');
  const maxDownloads = el<HTMLSelectElement>('max-downloads');
  const password = el<HTMLInputElement>('password');
  const startButton = el<HTMLButtonElement>('start-upload');
  const bar = el<HTMLDivElement>('upload-bar');

  for (const option of EXPIRY_OPTIONS) {
    const node = document.createElement('option');
    node.value = String(option.seconds);
    node.textContent = option.label;
    expiry.append(node);
  }
  expiry.value = String(EXPIRY_OPTIONS[1]!.seconds);
  maxDownloads.value = '5';

  let selected: File | null = null;
  let controller: AbortController | null = null;

  const select = (file: File | null) => {
    selected = file;
    clearError();
    if (!file) {
      form.hidden = true;
      dropzone.hidden = false;
      return;
    }
    el('selected-name').textContent = file.name;
    el('selected-size').textContent = formatBytes(file.size);
    dropzone.hidden = true;
    form.hidden = false;
  };

  dropzone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => select(fileInput.files?.[0] ?? null));
  el('clear-file').addEventListener('click', () => {
    fileInput.value = '';
    select(null);
  });

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
    select(event.dataTransfer?.files?.[0] ?? null);
  });

  el('cancel-upload').addEventListener('click', () => controller?.abort());

  el('upload-another').addEventListener('click', () => {
    result.hidden = true;
    fileInput.value = '';
    password.value = '';
    select(null);
  });

  el('copy-url').addEventListener('click', async () => {
    const input = el<HTMLInputElement>('share-url');
    try {
      await navigator.clipboard.writeText(input.value);
      const button = el('copy-url');
      button.textContent = 'コピーしました';
      setTimeout(() => (button.textContent = 'コピー'), 1500);
    } catch {
      input.select();
    }
  });

  startButton.addEventListener('click', async () => {
    if (!selected) return;
    clearError();
    controller = new AbortController();
    form.hidden = true;
    progress.hidden = false;
    bar.style.width = '0%';

    const track = createTracker(selected.size);
    try {
      const uploaded = await uploadFile({
        file: selected,
        password: password.value,
        expiresIn: Number(expiry.value),
        maxDownloads: maxDownloads.value === '' ? null : Number(maxDownloads.value),
        signal: controller.signal,
        onStage: (stage) => (el('upload-stage').textContent = stage),
        onProgress: (done) => {
          const status = track(done);
          bar.style.width = `${(status.ratio * 100).toFixed(1)}%`;
          el('upload-detail').textContent = status.text;
        },
      });

      progress.hidden = true;
      result.hidden = false;
      el<HTMLInputElement>('share-url').value = uploaded.url;
      setSummary(el('result-summary'), [
        ['ファイル', selected.name],
        ['サイズ', formatBytes(selected.size)],
        ['有効期限', formatDateTime(uploaded.expiresAt)],
        ['ダウンロード回数', uploaded.maxDownloads === null ? '無制限' : `${uploaded.maxDownloads} 回まで`],
        ['パスワード', password.value ? 'あり（Argon2id）' : 'なし'],
      ]);
    } catch (error) {
      progress.hidden = true;
      form.hidden = false;
      showError(describe(error));
    } finally {
      controller = null;
    }
  });
}

/* ================================================================== *
 * ダウンロード画面
 * ================================================================== */

async function initDownload(token: string): Promise<void> {
  el('view-download').hidden = false;
  const loading = el('download-loading');
  const card = el('download-card');
  const progress = el('download-progress');
  const passwordField = el('password-field');
  const passwordInput = el<HTMLInputElement>('download-password');
  const button = el<HTMLButtonElement>('start-download');
  const bar = el<HTMLDivElement>('download-bar');

  const rawSecret = location.hash.replace(/^#/, '');
  if (!rawSecret) {
    loading.hidden = true;
    showError(
      'URL に復号鍵（# より後ろ）が含まれていません。共有されたリンクをそのまま開いてください。',
    );
    return;
  }

  let linkSecret: Uint8Array;
  try {
    linkSecret = fromBase64Url(rawSecret);
  } catch {
    loading.hidden = true;
    showError('復号鍵の形式が不正です。');
    return;
  }

  void prepareServiceWorker();

  let info: FileInfo;
  let authToken: Uint8Array;
  try {
    authToken = await deriveAuthToken(linkSecret);
    info = await fetchInfo(token, authToken);
  } catch (error) {
    loading.hidden = true;
    showError(describe(error));
    return;
  }

  loading.hidden = true;
  card.hidden = false;

  const showMeta = (opened: OpenedFile) => {
    el('download-name').textContent = opened.meta.name;
    setSummary(el('download-summary'), [
      ['サイズ', formatBytes(opened.meta.size)],
      ['有効期限', formatDateTime(info.expiresAt)],
      [
        '残りダウンロード',
        info.remainingDownloads === null ? '無制限' : `${info.remainingDownloads} 回`,
      ],
    ]);
  };

  let opened: OpenedFile | null = null;

  if (info.hasPassword) {
    passwordField.hidden = false;
    button.textContent = 'パスワードを確認';
    el('download-name').textContent = '🔒 パスワードで保護されています';
    setSummary(el('download-summary'), [
      ['有効期限', formatDateTime(info.expiresAt)],
      [
        '残りダウンロード',
        info.remainingDownloads === null ? '無制限' : `${info.remainingDownloads} 回`,
      ],
    ]);
  } else {
    try {
      opened = await openFile(info, linkSecret, '');
      showMeta(opened);
      button.textContent = 'ダウンロード';
    } catch (error) {
      showError(describe(error));
      button.disabled = true;
      return;
    }
  }

  button.addEventListener('click', async () => {
    clearError();

    // パスワード保護時は、まず鍵を導出してファイル名を出す（回数は消費しない）
    if (!opened) {
      button.disabled = true;
      button.textContent = 'Argon2id で鍵を導出中…';
      try {
        opened = await openFile(info, linkSecret, passwordInput.value);
      } catch (error) {
        showError(error instanceof WrongPassword ? 'パスワードが違います' : describe(error));
        button.disabled = false;
        button.textContent = 'パスワードを確認';
        return;
      }
      passwordField.hidden = true;
      showMeta(opened);
      button.disabled = false;
      button.textContent = 'ダウンロード';
      return;
    }

    // ここから先はユーザー操作直後 = showSaveFilePicker を呼べる
    let saver: Saver;
    try {
      saver = await createSaver(opened.meta.name, opened.meta.size);
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      showError(describe(error));
      return;
    }

    button.disabled = true;
    card.hidden = true;
    progress.hidden = false;
    el('save-method').textContent = saver.description;
    bar.style.width = '0%';

    const controller = new AbortController();
    const track = createTracker(opened.meta.size);

    try {
      const granted = await claim(token, authToken, opened.pwVerifier);
      const stream = decryptedStream({
        token,
        grant: granted.grant,
        info,
        cek: opened.cek,
        signal: controller.signal,
        onProgress: (done) => {
          const status = track(done);
          bar.style.width = `${(status.ratio * 100).toFixed(1)}%`;
          el('download-detail').textContent = status.text;
        },
        onRetry: (attempt) => {
          el('download-stage').textContent = `接続が切れました。再開しています…（${attempt} 回目）`;
        },
      });

      await stream.pipeTo(saver.writable);
      await saver.finish();

      progress.hidden = true;
      el('download-done').hidden = false;
    } catch (error) {
      controller.abort();
      await saver.abort(error);
      progress.hidden = true;
      card.hidden = false;
      button.disabled = false;
      showError(describe(error));
    }
  });
}

/* ================================================================== */

const match = /^\/d\/([A-Za-z0-9_-]+)\/?$/.exec(location.pathname);
if (match) {
  void initDownload(match[1]!);
} else {
  initUpload();
}

/**
 * Capacitor プラグインの薄いラッパー。
 * ネイティブ以外では呼ばれない前提だが、すべて動的 import にして
 * Web ビルドのバンドルに余計なコードを持ち込まないようにしている。
 */
import { isAndroid, isIOS, isNative } from './platform.js';
import type { NativePickedFile } from './filesource.js';

/* ------------------------------------------------------------------ *
 * ファイル選択
 * ------------------------------------------------------------------ */

async function picker() {
  const { FilePicker } = await import('@capawesome/capacitor-file-picker');
  return FilePicker;
}

function normalize(
  files: Array<{ name: string; mimeType: string; size: number; path?: string }>,
): NativePickedFile[] {
  return files
    .filter((file) => typeof file.path === 'string' && file.path.length > 0)
    .map((file) => ({
      name: file.name,
      mimeType: file.mimeType || 'application/octet-stream',
      size: file.size,
      path: file.path!,
    }));
}

/** 「ファイル」アプリ / ストレージアクセスフレームワークから選ぶ（元データそのまま） */
export async function pickDocuments(): Promise<NativePickedFile[]> {
  const FilePicker = await picker();
  const result = await FilePicker.pickFiles({ readData: false });
  return normalize(result.files);
}

/**
 * 写真・動画ライブラリから選ぶ。
 * iOS は既定で HEIC→JPEG などの変換が入るため skipTranscoding で元ファイルを要求する
 * （= 劣化ゼロを守るための重要な指定）。
 */
export async function pickMedia(): Promise<NativePickedFile[]> {
  const FilePicker = await picker();
  const result = await FilePicker.pickMedia({ readData: false, skipTranscoding: true });
  return normalize(result.files);
}

/* ------------------------------------------------------------------ *
 * 保存
 * ------------------------------------------------------------------ */

const B64_STEP = 0x8000;

/** Uint8Array → 標準 base64（Filesystem プラグインが要求する形式） */
export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += B64_STEP) {
    binary += String.fromCharCode(...bytes.subarray(i, i + B64_STEP));
  }
  return btoa(binary);
}

/** 1 回の appendFile に載せるバイト数。ブリッジ越しの文字列が巨大になりすぎないように */
const APPEND_STEP = 4 * 1024 * 1024;

export interface NativeFileWriter {
  /** ファイルアプリ上での場所の説明（UI 表示用） */
  location: string;
  append(bytes: Uint8Array): Promise<void>;
  /** 書き込みを確定し、共有などに使える URI を返す */
  finish(): Promise<{ uri: string }>;
  abort(): Promise<void>;
}

/** パス区切りや制御文字をファイル名から取り除く */
export function safeName(name: string): string {
  // eslint-disable-next-line no-control-regex
  const cleaned = name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').trim();
  return cleaned || 'download';
}

/**
 * 復号済みデータをアプリの Documents に書き出す。
 *   iOS     … アプリの Documents（Info.plist の UIFileSharingEnabled 等により
 *             「ファイル」アプリの「このiPhone内 / CryptBox」に出る）
 *   Android … 公開 Documents/CryptBox（Android 11+ は自分で作ったファイルのみ扱える）
 */
export async function createNativeWriter(filename: string): Promise<NativeFileWriter> {
  const { Filesystem, Directory } = await import('@capacitor/filesystem');
  const directory = Directory.Documents;
  const folder = isAndroid ? 'CryptBox' : '';
  const base = safeName(filename);

  // 同名ファイルがあれば (2), (3)… を付ける
  let path = folder ? `${folder}/${base}` : base;
  for (let n = 2; n < 1000; n++) {
    try {
      await Filesystem.stat({ path, directory });
    } catch {
      break;
    }
    const dot = base.lastIndexOf('.');
    const stem = dot > 0 ? base.slice(0, dot) : base;
    const ext = dot > 0 ? base.slice(dot) : '';
    path = `${folder ? `${folder}/` : ''}${stem} (${n})${ext}`;
  }

  // 空ファイルを作ってから追記していく（recursive でフォルダも作る）
  await Filesystem.writeFile({ path, directory, data: '', recursive: true });

  return {
    location: isIOS ? '「ファイル」アプリ › このiPhone内 › CryptBox' : 'Documents › CryptBox',
    async append(bytes) {
      for (let offset = 0; offset < bytes.length; offset += APPEND_STEP) {
        await Filesystem.appendFile({
          path,
          directory,
          data: toBase64(bytes.subarray(offset, offset + APPEND_STEP)),
        });
      }
    },
    async finish() {
      const { uri } = await Filesystem.getUri({ path, directory });
      return { uri };
    },
    async abort() {
      await Filesystem.deleteFile({ path, directory }).catch(() => undefined);
    },
  };
}

/** OS の共有シートでファイルを渡す（iOS の「ファイルに保存」など） */
export async function shareFile(uri: string, title: string): Promise<void> {
  const { Share } = await import('@capacitor/share');
  await Share.share({ title, files: [uri] });
}

/* ------------------------------------------------------------------ *
 * 転送中のスリープ防止
 * ------------------------------------------------------------------ */

export async function keepAwake(on: boolean): Promise<void> {
  if (!isNative) return;
  try {
    const { KeepAwake } = await import('@capacitor-community/keep-awake');
    if (on) await KeepAwake.keepAwake();
    else await KeepAwake.allowSleep();
  } catch {
    /* 対応していない環境では何もしない */
  }
}

/* ------------------------------------------------------------------ *
 * ディープリンク / ステータスバー
 * ------------------------------------------------------------------ */

/** 共有リンク (https://host/d/<token>#<key>) でアプリが開かれたときに呼ばれる */
export async function onAppUrlOpen(handler: (url: URL) => void): Promise<void> {
  if (!isNative) return;
  const { App } = await import('@capacitor/app');
  await App.addListener('appUrlOpen', (event) => {
    try {
      handler(new URL(event.url));
    } catch {
      /* 不正な URL は無視 */
    }
  });
  // コールドスタート時に渡された URL も拾う
  const launch = await App.getLaunchUrl().catch(() => null);
  if (launch?.url) {
    try {
      handler(new URL(launch.url));
    } catch {
      /* ignore */
    }
  }
}

export async function applyStatusBar(theme: 'light' | 'dark'): Promise<void> {
  if (!isNative) return;
  try {
    const { StatusBar, Style } = await import('@capacitor/status-bar');
    await StatusBar.setStyle({ style: theme === 'dark' ? Style.Dark : Style.Light });
    if (isAndroid) {
      await StatusBar.setBackgroundColor({ color: theme === 'dark' ? '#15151e' : '#ffffff' });
    }
  } catch {
    /* ignore */
  }
}

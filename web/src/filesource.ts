import { Capacitor } from '@capacitor/core';
import { isIOS } from './platform.js';

/**
 * アップロード元ファイルの抽象。
 * ブラウザでは File、アプリではネイティブピッカーが返したパスを包む。
 * どちらも「全体をメモリに載せずに [start, end) を取り出せる」ことが要件。
 */
export interface FileSource {
  name: string;
  type: string;
  size: number;
  /** [start, end) のバイト列を返す。呼び出しはチャンク順に行われる */
  read(start: number, end: number): Promise<Uint8Array>;
  /** 読み終わった後の後始末 */
  close(): Promise<void>;
  /** 同一ファイル判定用 */
  key: string;
}

/* ------------------------------------------------------------------ *
 * ブラウザ: File.slice()
 * ------------------------------------------------------------------ */

export function fromFile(file: File): FileSource {
  return {
    name: file.name,
    type: file.type,
    size: file.size,
    key: `file:${file.name}:${file.size}:${file.lastModified}`,
    async read(start, end) {
      return new Uint8Array(await file.slice(start, end).arrayBuffer());
    },
    async close() {
      /* nothing to release */
    },
  };
}

/* ------------------------------------------------------------------ *
 * アプリ: WebView のローカルファイルサーバー経由で読む
 *
 *   iOS     … Range ヘッダーに正しく応える（seek + 指定長のみ読む）ので
 *             ランダムアクセスで取り出す
 *   Android … Range を送っても先頭からの全体が返ってくる実装のため、
 *             1 本のストリームを順番に消費する（=読み出しは必ず昇順）
 * ------------------------------------------------------------------ */

export interface NativePickedFile {
  name: string;
  mimeType: string;
  size: number;
  path: string;
}

/** テストから差し替えられるように fetch を注入可能にしておく */
export interface NativeSourceOptions {
  fetchImpl?: typeof fetch;
  /** true なら Range を使う（iOS）。false なら逐次ストリーム（Android） */
  useRange?: boolean;
  /** convertFileSrc を差し替える（テスト用） */
  toUrl?: (path: string) => string;
}

export function fromNativePath(file: NativePickedFile, options: NativeSourceOptions = {}): FileSource {
  const fetchImpl = options.fetchImpl ?? fetch;
  const useRange = options.useRange ?? isIOS;
  const url = (options.toUrl ?? Capacitor.convertFileSrc)(file.path);

  if (useRange) return rangeSource(file, url, fetchImpl);
  return streamSource(file, url, fetchImpl);
}

function rangeSource(file: NativePickedFile, url: string, fetchImpl: typeof fetch): FileSource {
  return {
    name: file.name,
    type: file.mimeType,
    size: file.size,
    key: `native:${file.path}`,
    async read(start, end) {
      if (end <= start) return new Uint8Array(0);
      const response = await fetchImpl(url, { headers: { Range: `bytes=${start}-${end - 1}` } });
      if (response.status !== 206) {
        throw new Error(`ファイルの部分読み出しに失敗しました (HTTP ${response.status})`);
      }
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (bytes.length !== end - start) {
        throw new Error(`読み出し長が一致しません (${bytes.length} / ${end - start})`);
      }
      return bytes;
    },
    async close() {
      /* nothing to release */
    },
  };
}

function streamSource(file: NativePickedFile, url: string, fetchImpl: typeof fetch): FileSource {
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let cursor = 0;
  let buffer: Uint8Array[] = [];
  let buffered = 0;
  // read() を呼び出し順に直列化する
  let chain: Promise<unknown> = Promise.resolve();

  async function open(): Promise<void> {
    const response = await fetchImpl(url);
    if (!response.ok || !response.body) {
      throw new Error(`ファイルを開けませんでした (HTTP ${response.status})`);
    }
    reader = response.body.getReader();
  }

  function take(length: number): Uint8Array {
    const out = new Uint8Array(length);
    let filled = 0;
    while (filled < length) {
      const head = buffer[0]!;
      const need = length - filled;
      if (head.length <= need) {
        out.set(head, filled);
        filled += head.length;
        buffer.shift();
      } else {
        out.set(head.subarray(0, need), filled);
        buffer[0] = head.subarray(need);
        filled += need;
      }
    }
    buffered -= length;
    return out;
  }

  async function readSequential(start: number, end: number): Promise<Uint8Array> {
    if (start !== cursor) {
      throw new Error(`この環境ではファイルを順番にしか読めません (要求 ${start}, 現在 ${cursor})`);
    }
    const length = end - start;
    if (length === 0) return new Uint8Array(0);
    if (!reader) await open();
    while (buffered < length) {
      const { value, done } = await reader!.read();
      if (done) throw new Error('ファイルの途中で読み出しが終了しました');
      buffer.push(value);
      buffered += value.length;
    }
    cursor = end;
    return take(length);
  }

  return {
    name: file.name,
    type: file.mimeType,
    size: file.size,
    key: `native:${file.path}`,
    read(start, end) {
      const next = chain.then(() => readSequential(start, end));
      // 失敗しても後続の read を巻き込まないように握りつぶした鎖を保持する
      chain = next.catch(() => undefined);
      return next;
    },
    async close() {
      await reader?.cancel().catch(() => undefined);
      reader = null;
      buffer = [];
      buffered = 0;
    },
  };
}

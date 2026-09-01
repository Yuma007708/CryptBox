/**
 * 復号済みストリームをディスクに保存する。
 * 巨大ファイルをメモリに載せないため、上から順に試す:
 *   1. File System Access API   … 直接ファイルへ書き込む（Chromium 系）
 *   2. Service Worker ストリーム … ダウンロードを SW が生成する（Firefox / Safari）
 *   3. Blob                     … 上記が使えない環境向けの最終手段
 */

export type SaveMethod = 'fs-access' | 'service-worker' | 'blob';

export interface Saver {
  method: SaveMethod;
  description: string;
  writable: WritableStream<Uint8Array>;
  /** 書き込み完了後の後始末（Blob 方式ではここで実際の保存が起きる） */
  finish(): Promise<void>;
  abort(reason?: unknown): Promise<void>;
}

interface SaveFilePickerWindow extends Window {
  showSaveFilePicker?: (options: {
    suggestedName?: string;
  }) => Promise<{ createWritable(): Promise<WritableStream<Uint8Array>> }>;
}

let swRegistration: Promise<ServiceWorkerRegistration | null> | null = null;

/** ページ表示時に呼んでおくと、保存時に待たされない */
export function prepareServiceWorker(): Promise<ServiceWorkerRegistration | null> {
  if (swRegistration) return swRegistration;
  if (!('serviceWorker' in navigator) || !window.isSecureContext) {
    swRegistration = Promise.resolve(null);
    return swRegistration;
  }
  swRegistration = navigator.serviceWorker
    .register('/sw.js', { scope: '/' })
    .then(async (registration) => {
      await navigator.serviceWorker.ready;
      if (!navigator.serviceWorker.controller) {
        // clients.claim() が効くまで少しだけ待つ
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, 2000);
          navigator.serviceWorker.addEventListener(
            'controllerchange',
            () => {
              clearTimeout(timer);
              resolve();
            },
            { once: true },
          );
        });
      }
      return registration;
    })
    .catch(() => null);
  return swRegistration;
}

/**
 * 保存先を用意する。File System Access API を使う可能性があるため、
 * 必ずユーザー操作（クリック）のハンドラから同期的に呼ぶこと。
 *
 * 複数ファイルを続けて保存する場合は allowPicker を false にする。
 * 2 ファイル目以降はユーザー操作から離れており、保存ダイアログを開けないため。
 */
export async function createSaver(
  filename: string,
  size: number,
  options: { allowPicker?: boolean } = {},
): Promise<Saver> {
  const picker = (window as SaveFilePickerWindow).showSaveFilePicker;
  if (options.allowPicker !== false && typeof picker === 'function') {
    const handle = await picker({ suggestedName: filename });
    const writable = await handle.createWritable();
    return {
      method: 'fs-access',
      description: '選択したファイルへ直接書き込みます（メモリを使いません）',
      writable,
      async finish() {
        /* pipeTo が close 済み */
      },
      async abort(reason) {
        await writable.abort(reason).catch(() => undefined);
      },
    };
  }

  const registration = await prepareServiceWorker();
  if (registration && navigator.serviceWorker.controller) {
    return createServiceWorkerSaver(filename, size);
  }

  return createBlobSaver(filename);
}

function createServiceWorkerSaver(filename: string, size: number): Saver {
  const id = crypto.randomUUID();
  const channel = new MessageChannel();
  const port = channel.port1;

  let pullCredits = 0;
  const waiting: Array<{ value: Uint8Array; resolve: () => void }> = [];
  let failure: unknown = null;
  let onFailure: ((error: unknown) => void) | null = null;

  const send = (value: Uint8Array) => {
    const transferable =
      value.byteOffset === 0 && value.byteLength === value.buffer.byteLength
        ? [value.buffer]
        : [];
    port.postMessage({ type: 'chunk', value }, transferable as Transferable[]);
  };

  port.onmessage = (event: MessageEvent<{ type: string }>) => {
    if (event.data.type === 'pull') {
      const next = waiting.shift();
      if (next) {
        send(next.value);
        next.resolve();
      } else {
        pullCredits += 1;
      }
    } else if (event.data.type === 'cancel') {
      failure = new Error('保存がキャンセルされました');
      onFailure?.(failure);
    }
  };

  navigator.serviceWorker.controller!.postMessage({ type: 'init', id, filename, size }, [
    channel.port2,
  ]);

  // SW が Content-Disposition: attachment を返すので、iframe を開くだけで保存が始まる
  const frame = document.createElement('iframe');
  frame.hidden = true;
  frame.src = `/_dl/${id}/${encodeURIComponent(filename)}`;
  document.body.append(frame);
  const cleanup = () => frame.remove();

  const writable = new WritableStream<Uint8Array>({
    write(value) {
      if (failure) return Promise.reject(failure);
      if (pullCredits > 0) {
        pullCredits -= 1;
        send(value);
        return Promise.resolve();
      }
      return new Promise<void>((resolve, reject) => {
        onFailure = reject;
        waiting.push({ value, resolve });
      });
    },
    close() {
      port.postMessage({ type: 'end' });
      port.close();
      cleanup();
    },
    abort(reason) {
      port.postMessage({ type: 'abort', reason: String(reason) });
      port.close();
      cleanup();
    },
  });

  return {
    method: 'service-worker',
    description: 'ブラウザのダウンロード機能へ直接流し込みます（メモリを使いません）',
    writable,
    async finish() {
      /* close() 済み */
    },
    async abort(reason) {
      await writable.abort(reason).catch(() => undefined);
    },
  };
}

function createBlobSaver(filename: string): Saver {
  const parts: Uint8Array[] = [];
  const writable = new WritableStream<Uint8Array>({
    write(value) {
      parts.push(value);
    },
  });

  return {
    method: 'blob',
    description: 'この環境ではストリーム保存が使えないため、いったんメモリに展開します',
    writable,
    async finish() {
      const blob = new Blob(parts as BlobPart[], { type: 'application/octet-stream' });
      parts.length = 0;
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    },
    async abort(reason) {
      parts.length = 0;
      await writable.abort(reason).catch(() => undefined);
    },
  };
}

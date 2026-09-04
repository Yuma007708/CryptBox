import { ApiError, deleteJson, postJson } from './api.js';
import { apiUrl } from './config.js';
import {
  decryptChunk,
  decryptMeta,
  deriveKeys,
  importCek,
  unwrapCek,
  type FileMeta,
} from './crypto.js';
import {
  type Argon2Params,
  GCM_TAG_BYTES,
  fromBase64Url,
  toBase64Url,
} from '../../shared/format.js';
import type { DeletionReceipt } from '../../shared/receipt.js';

export interface RemoteFile {
  index: number;
  plainSize: number;
  cipherSize: number;
  chunkSize: number;
  totalChunks: number;
  noncePrefix: string;
  wrappedCek: string;
  wrapNonce: string;
  metaCipher: string;
  metaNonce: string;
}

export interface BundleInfo {
  createdAt: number;
  expiresAt: number;
  maxDownloads: number | null;
  remainingDownloads: number | null;
  totalPlainSize: number;
  kdfSalt: string;
  hasPassword: boolean;
  pwSalt: string | null;
  pwParams: Argon2Params | null;
  files: RemoteFile[];
}

export class WrongPassword extends Error {
  constructor() {
    super('パスワードが違います');
  }
}

export async function fetchInfo(token: string, authToken: Uint8Array): Promise<BundleInfo> {
  return postJson<BundleInfo>(`/api/files/${encodeURIComponent(token)}/info`, {
    authToken: toBase64Url(authToken),
  });
}

export async function deleteBundle(
  token: string,
  authToken: Uint8Array,
): Promise<{ receipt: DeletionReceipt | null }> {
  return deleteJson(`/api/files/${encodeURIComponent(token)}`, {
    authToken: toBase64Url(authToken),
  });
}

/** 削除レシートを取得する。他の API 同様、authToken（linkSecret 由来）による認可が要る */
export async function fetchReceipt(
  token: string,
  authToken: Uint8Array,
): Promise<{ deleted: boolean; receipt?: DeletionReceipt }> {
  return postJson(`/api/files/${encodeURIComponent(token)}/receipt`, {
    authToken: toBase64Url(authToken),
  });
}

/** DB を見ず署名だけを再検証する */
export async function verifyReceipt(receipt: DeletionReceipt): Promise<boolean> {
  const result = await postJson<{ valid: boolean }>('/api/receipts/verify', { receipt });
  return result.valid;
}

export interface OpenedFile {
  remote: RemoteFile;
  meta: FileMeta;
  cek: CryptoKey;
}

export interface OpenedBundle {
  files: OpenedFile[];
  pwVerifier: Uint8Array | null;
}

/**
 * 鍵を導出して各ファイルの CEK を取り出し、ファイル名を復号する。
 * パスワードが違えば AES-GCM の認証に失敗するので、
 * サーバーに問い合わせる前に（＝ダウンロード回数を消費せずに）判定できる。
 */
export async function openBundle(
  info: BundleInfo,
  linkSecret: Uint8Array,
  password: string,
): Promise<OpenedBundle> {
  const keys = await deriveKeys({
    linkSecret,
    kdfSalt: fromBase64Url(info.kdfSalt),
    password: info.hasPassword ? password : undefined,
    pwSalt: info.pwSalt ? fromBase64Url(info.pwSalt) : undefined,
    pwParams: info.pwParams ?? undefined,
  });

  const files: OpenedFile[] = [];
  for (const remote of info.files) {
    let cekRaw: Uint8Array;
    try {
      cekRaw = await unwrapCek(
        keys.kek,
        fromBase64Url(remote.wrappedCek),
        fromBase64Url(remote.wrapNonce),
      );
    } catch {
      throw new WrongPassword();
    }
    const cek = await importCek(cekRaw);
    cekRaw.fill(0);
    const meta = await decryptMeta(
      cek,
      fromBase64Url(remote.metaCipher),
      fromBase64Url(remote.metaNonce),
    );
    files.push({ remote, meta, cek });
  }

  return { files, pwVerifier: keys.pwVerifier };
}

export interface Claim {
  grant: string;
  grantExpiresAt: number;
  remainingDownloads: number | null;
}

/** ダウンロード回数を 1 消費し、バンドル全体の取得に使えるグラントを得る */
export async function claim(
  token: string,
  authToken: Uint8Array,
  pwVerifier: Uint8Array | null,
): Promise<Claim> {
  return postJson<Claim>(`/api/files/${encodeURIComponent(token)}/claim`, {
    authToken: toBase64Url(authToken),
    pwVerifier: pwVerifier ? toBase64Url(pwVerifier) : null,
  });
}

/** ダウンロード中の生存信号。上限到達後の猶予タイマーをリセットする */
export async function pingDownload(token: string, grant: string): Promise<void> {
  await postJson(`/api/files/${encodeURIComponent(token)}/ping`, { grant });
}

/**
 * ダウンロード完了（またはページ離脱）を通知する。
 * 回数上限に達していれば、サーバーはこの時点でバンドルを完全削除する。
 */
export async function finishDownload(
  token: string,
  grant: string,
): Promise<{ deleted: boolean; receipt?: DeletionReceipt }> {
  return postJson(`/api/files/${encodeURIComponent(token)}/finish`, { grant });
}

/** ページ離脱時用。レスポンスを待たずに finish を送る */
export function finishDownloadBeacon(token: string, grant: string): void {
  const url = `/api/files/${encodeURIComponent(token)}/finish`;
  const body = new Blob([JSON.stringify({ grant })], { type: 'application/json' });
  if (!navigator.sendBeacon?.(url, body)) {
    void fetch(url, { method: 'POST', body, keepalive: true }).catch(() => undefined);
  }
}

/** チャンク i の暗号文の長さ */
function cipherLengthOf(index: number, file: RemoteFile): number {
  const plainStart = index * file.chunkSize;
  const plainLength = Math.min(file.chunkSize, Math.max(0, file.plainSize - plainStart));
  return plainLength + GCM_TAG_BYTES;
}

interface StreamOptions {
  token: string;
  grant: string;
  file: RemoteFile;
  cek: CryptoKey;
  signal: AbortSignal;
  onProgress(plainBytes: number): void;
  onRetry?(attempt: number): void;
}

/**
 * 暗号文を 1 本のレスポンスとして受け取り、チャンク境界ごとに復号して流す。
 * 途中で切れた場合は最後に復号し終えたチャンク境界から Range で再開する
 * （＝巨大ファイルでも最初からやり直しにならない）。
 */
export function decryptedStream(options: StreamOptions): ReadableStream<Uint8Array> {
  const { token, grant, file, cek, signal } = options;
  const noncePrefix = fromBase64Url(file.noncePrefix);

  let chunkIndex = 0;
  let cipherOffset = 0;
  let plainDone = 0;
  let attempts = 0;

  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let buffer: Uint8Array[] = [];
  let buffered = 0;

  async function openStream(): Promise<void> {
    const url = apiUrl(
      `/api/files/${encodeURIComponent(token)}/files/${file.index}/blob` +
        `?g=${encodeURIComponent(grant)}`,
    );
    const response = await fetch(url, {
      headers: cipherOffset > 0 ? { Range: `bytes=${cipherOffset}-` } : {},
      signal,
    });
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try {
        const body = (await response.json()) as { error?: string };
        if (body.error) message = body.error;
      } catch {
        /* ignore */
      }
      throw new ApiError(message, response.status);
    }
    if (!response.body) throw new Error('レスポンスボディがありません');
    reader = response.body.getReader();
    buffer = [];
    buffered = 0;
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

  async function nextChunk(): Promise<Uint8Array | null> {
    while (chunkIndex < file.totalChunks) {
      const needed = cipherLengthOf(chunkIndex, file);
      if (buffered >= needed) {
        const cipher = take(needed);
        const plain = await decryptChunk(cek, cipher, noncePrefix, chunkIndex, file.totalChunks);
        chunkIndex += 1;
        cipherOffset += needed;
        plainDone += plain.length;
        attempts = 0;
        options.onProgress(plainDone);
        return plain;
      }

      try {
        if (!reader) await openStream();
        const { value, done } = await reader!.read();
        if (done) {
          if (buffered > 0 || chunkIndex < file.totalChunks) {
            throw new Error('転送が途中で終了しました');
          }
          return null;
        }
        if (value) {
          buffer.push(value);
          buffered += value.length;
        }
      } catch (error) {
        if (signal.aborted) throw error;
        if (error instanceof ApiError && error.status < 500 && error.status !== 429) throw error;
        attempts += 1;
        if (attempts > 5) throw error;
        options.onRetry?.(attempts);
        await reader?.cancel().catch(() => undefined);
        reader = null;
        buffer = [];
        buffered = 0;
        await new Promise((resolve) => setTimeout(resolve, Math.min(8000, 500 * 2 ** attempts)));
      }
    }
    return null;
  }

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const chunk = await nextChunk();
        if (chunk === null) {
          await reader?.cancel().catch(() => undefined);
          controller.close();
        } else {
          controller.enqueue(chunk);
        }
      } catch (error) {
        await reader?.cancel().catch(() => undefined);
        controller.error(error);
      }
    },
    async cancel() {
      await reader?.cancel().catch(() => undefined);
    },
  });
}

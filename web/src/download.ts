import { ApiError, postJson } from './api.js';
import { decryptChunk, decryptMeta, deriveKeys, importCek, unwrapCek, type FileMeta } from './crypto.js';
import {
  type Argon2Params,
  GCM_TAG_BYTES,
  fromBase64Url,
  toBase64Url,
} from '../../shared/format.js';

export interface FileInfo {
  plainSize: number;
  cipherSize: number;
  chunkSize: number;
  totalChunks: number;
  noncePrefix: string;
  kdfSalt: string;
  wrappedCek: string;
  wrapNonce: string;
  metaCipher: string;
  metaNonce: string;
  hasPassword: boolean;
  pwSalt: string | null;
  pwParams: Argon2Params | null;
  expiresAt: number;
  maxDownloads: number | null;
  remainingDownloads: number | null;
}

export class WrongPassword extends Error {
  constructor() {
    super('パスワードが違います');
  }
}

export async function fetchInfo(token: string, authToken: Uint8Array): Promise<FileInfo> {
  return postJson<FileInfo>(`/api/files/${encodeURIComponent(token)}/info`, {
    authToken: toBase64Url(authToken),
  });
}

export interface OpenedFile {
  meta: FileMeta;
  cek: CryptoKey;
  pwVerifier: Uint8Array | null;
}

/**
 * 鍵を導出してファイル鍵を取り出し、メタデータを復号する。
 * パスワードが違えば AES-GCM の認証に失敗するので、
 * サーバーに問い合わせる前に（＝ダウンロード回数を消費せずに）判定できる。
 */
export async function openFile(info: FileInfo, linkSecret: Uint8Array, password: string): Promise<OpenedFile> {
  const keys = await deriveKeys({
    linkSecret,
    kdfSalt: fromBase64Url(info.kdfSalt),
    password: info.hasPassword ? password : undefined,
    pwSalt: info.pwSalt ? fromBase64Url(info.pwSalt) : undefined,
    pwParams: info.pwParams ?? undefined,
  });

  let cekRaw: Uint8Array;
  try {
    cekRaw = await unwrapCek(keys.kek, fromBase64Url(info.wrappedCek), fromBase64Url(info.wrapNonce));
  } catch {
    throw new WrongPassword();
  }

  const cek = await importCek(cekRaw);
  cekRaw.fill(0);
  const meta = await decryptMeta(cek, fromBase64Url(info.metaCipher), fromBase64Url(info.metaNonce));
  return { meta, cek, pwVerifier: keys.pwVerifier };
}

export interface Claim {
  grant: string;
  grantExpiresAt: number;
  remainingDownloads: number | null;
}

/** ダウンロード回数を 1 消費し、本体取得用のグラントを得る */
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

/** チャンク i の暗号文の長さ */
function cipherLengthOf(index: number, info: FileInfo): number {
  const plainStart = index * info.chunkSize;
  const plainLength = Math.min(info.chunkSize, Math.max(0, info.plainSize - plainStart));
  return plainLength + GCM_TAG_BYTES;
}

interface StreamOptions {
  token: string;
  grant: string;
  info: FileInfo;
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
  const { token, grant, info, cek, signal } = options;
  const noncePrefix = fromBase64Url(info.noncePrefix);

  let chunkIndex = 0;
  let cipherOffset = 0;
  let plainDone = 0;
  let attempts = 0;

  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let buffer: Uint8Array[] = [];
  let buffered = 0;

  async function openStream(): Promise<void> {
    const url = `/api/files/${encodeURIComponent(token)}/blob?g=${encodeURIComponent(grant)}`;
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
    while (chunkIndex < info.totalChunks) {
      const needed = cipherLengthOf(chunkIndex, info);
      if (buffered >= needed) {
        const cipher = take(needed);
        const plain = await decryptChunk(cek, cipher, noncePrefix, chunkIndex, info.totalChunks);
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
          if (buffered > 0 || chunkIndex < info.totalChunks) {
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

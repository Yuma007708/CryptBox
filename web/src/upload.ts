import { postJson, putBytes, withRetry } from './api.js';
import { PUBLIC_ORIGIN, apiUrl } from './config.js';
import type { FileSource } from './filesource.js';
import {
  deriveAuthToken,
  deriveKeys,
  encryptChunk,
  encryptMeta,
  importCek,
  randomBytes,
  sha256Hex,
  wrapCek,
} from './crypto.js';
import {
  ARGON2_DEFAULTS,
  DEFAULT_CHUNK_SIZE,
  KDF_SALT_BYTES,
  KEY_BYTES,
  LINK_SECRET_BYTES,
  NONCE_BYTES,
  NONCE_PREFIX_BYTES,
  PW_SALT_BYTES,
  toBase64Url,
  totalChunks as computeChunks,
} from '../../shared/format.js';

/** 同時にアップロードするチャンク数。多すぎるとメモリを食うので控えめに */
const CONCURRENCY = 3;

export interface UploadOptions {
  files: FileSource[];
  password: string;
  expiresIn: number;
  maxDownloads: number | null;
  signal: AbortSignal;
  /** Cloudflare Turnstile のトークン。サイトキーが無い（無効化されている）環境では undefined */
  turnstileToken?: string;
  onStage(stage: string): void;
  onProgress(sentPlainBytes: number, totalPlainBytes: number): void;
}

export interface UploadResult {
  url: string;
  token: string;
  linkSecret: string;
  expiresAt: number;
  maxDownloads: number | null;
}

interface PreparedFile {
  file: FileSource;
  cek: CryptoKey;
  noncePrefix: Uint8Array;
  wrapNonce: Uint8Array;
  metaNonce: Uint8Array;
  wrappedCek: Uint8Array;
  metaCipher: Uint8Array;
  chunks: number;
}

/**
 * 選択されたファイル群を 1 つの共有リンク（バンドル）として暗号化・送信する。
 * ファイルごとに独立した CEK を持ち、それらを共通の KEK でラップする。
 */
export async function uploadBundle(options: UploadOptions): Promise<UploadResult> {
  const { files, password, signal } = options;
  if (files.length === 0) throw new Error('ファイルが選択されていません');

  const chunkSize = DEFAULT_CHUNK_SIZE;
  const totalPlainSize = files.reduce((sum, file) => sum + file.size, 0);

  options.onStage('鍵を生成しています…');
  const linkSecret = randomBytes(LINK_SECRET_BYTES);
  const kdfSalt = randomBytes(KDF_SALT_BYTES);
  const pwSalt = randomBytes(PW_SALT_BYTES);

  if (password) options.onStage('Argon2id でパスワードから鍵を導出しています…');
  const keys = await deriveKeys({
    linkSecret,
    kdfSalt,
    password: password || undefined,
    pwSalt,
    pwParams: ARGON2_DEFAULTS,
  });
  const authToken = await deriveAuthToken(linkSecret);

  options.onStage('ファイルごとの鍵を用意しています…');
  const prepared: PreparedFile[] = [];
  for (const file of files) {
    const cekRaw = randomBytes(KEY_BYTES);
    const cek = await importCek(cekRaw);
    const noncePrefix = randomBytes(NONCE_PREFIX_BYTES);
    const wrapNonce = randomBytes(NONCE_BYTES);
    const metaNonce = randomBytes(NONCE_BYTES);
    const wrappedCek = await wrapCek(keys.kek, cekRaw, wrapNonce);
    const metaCipher = await encryptMeta(
      cek,
      { name: file.name, type: file.type, size: file.size },
      metaNonce,
    );
    cekRaw.fill(0);
    prepared.push({
      file,
      cek,
      noncePrefix,
      wrapNonce,
      metaNonce,
      wrappedCek,
      metaCipher,
      chunks: computeChunks(file.size, chunkSize),
    });
  }

  options.onStage('アップロードを開始しています…');
  const session = await postJson<{ uploadToken: string; files: { index: number }[] }>(
    '/api/uploads',
    {
      chunkSize,
      files: files.map((file) => ({ plainSize: file.size })),
      turnstileToken: options.turnstileToken,
    },
    signal,
  );

  const abortSession = async () => {
    try {
      await fetch(apiUrl(`/api/uploads/${encodeURIComponent(session.uploadToken)}`), {
        method: 'DELETE',
      });
    } catch {
      /* 後始末は Cron でも行われる */
    }
  };

  try {
    options.onStage('暗号化してアップロードしています…');

    // (ファイル番号, チャンク番号) の平坦なタスク列を数本のワーカーで消化する
    const tasks: Array<{ fileIndex: number; chunkIndex: number }> = [];
    prepared.forEach((entry, fileIndex) => {
      for (let chunkIndex = 0; chunkIndex < entry.chunks; chunkIndex++) {
        tasks.push({ fileIndex, chunkIndex });
      }
    });

    let sent = 0;
    let next = 0;
    const worker = async () => {
      for (;;) {
        const task = tasks[next++];
        if (!task) return;
        if (signal.aborted) throw new DOMException('中止されました', 'AbortError');

        const entry = prepared[task.fileIndex]!;
        const start = task.chunkIndex * chunkSize;
        const end = Math.min(entry.file.size, start + chunkSize);
        const plain = await entry.file.read(start, end);
        const cipher = await encryptChunk(
          entry.cek,
          plain,
          entry.noncePrefix,
          task.chunkIndex,
          entry.chunks,
        );
        plain.fill(0);

        await withRetry(
          () =>
            putBytes(
              `/api/uploads/${encodeURIComponent(session.uploadToken)}/files/${task.fileIndex}/parts/${task.chunkIndex}`,
              cipher,
              signal,
            ),
          { signal },
        );

        sent += end - start;
        options.onProgress(sent, totalPlainSize);
      }
    };

    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, tasks.length) }, worker));

    options.onStage('仕上げをしています…');
    const completed = await postJson<{
      token: string;
      expiresAt: number;
      maxDownloads: number | null;
    }>(
      `/api/uploads/${encodeURIComponent(session.uploadToken)}/complete`,
      {
        expiresIn: options.expiresIn,
        maxDownloads: options.maxDownloads,
        authHash: await sha256Hex(authToken),
        kdfSalt: toBase64Url(kdfSalt),
        hasPassword: Boolean(password),
        pwSalt: password ? toBase64Url(pwSalt) : null,
        pwParams: password ? ARGON2_DEFAULTS : null,
        pwHash: keys.pwVerifier ? await sha256Hex(keys.pwVerifier) : null,
        files: prepared.map((entry) => ({
          noncePrefix: toBase64Url(entry.noncePrefix),
          wrappedCek: toBase64Url(entry.wrappedCek),
          wrapNonce: toBase64Url(entry.wrapNonce),
          metaCipher: toBase64Url(entry.metaCipher),
          metaNonce: toBase64Url(entry.metaNonce),
        })),
      },
      signal,
    );

    // 復号鍵はフラグメントに載せる = HTTP リクエストに含まれずサーバーには届かない
    const secret = toBase64Url(linkSecret);
    return {
      url: `${PUBLIC_ORIGIN}/d/${completed.token}#${secret}`,
      token: completed.token,
      linkSecret: secret,
      expiresAt: completed.expiresAt,
      maxDownloads: completed.maxDownloads,
    };
  } catch (error) {
    await abortSession();
    throw error;
  } finally {
    await Promise.all(prepared.map((entry) => entry.file.close().catch(() => undefined)));
  }
}

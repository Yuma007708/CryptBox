import { postJson, putBytes, withRetry } from './api.js';
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
  file: File;
  password: string;
  expiresIn: number;
  maxDownloads: number | null;
  signal: AbortSignal;
  onStage(stage: string): void;
  onProgress(sentPlainBytes: number, totalPlainBytes: number): void;
}

export interface UploadResult {
  url: string;
  token: string;
  expiresAt: number;
  maxDownloads: number | null;
}

export async function uploadFile(options: UploadOptions): Promise<UploadResult> {
  const { file, password, signal } = options;
  const chunkSize = DEFAULT_CHUNK_SIZE;
  const chunks = computeChunks(file.size, chunkSize);

  options.onStage('鍵を生成しています…');
  const linkSecret = randomBytes(LINK_SECRET_BYTES);
  const kdfSalt = randomBytes(KDF_SALT_BYTES);
  const pwSalt = randomBytes(PW_SALT_BYTES);
  const noncePrefix = randomBytes(NONCE_PREFIX_BYTES);
  const wrapNonce = randomBytes(NONCE_BYTES);
  const metaNonce = randomBytes(NONCE_BYTES);
  const cekRaw = randomBytes(KEY_BYTES);
  const cek = await importCek(cekRaw);

  if (password) options.onStage('Argon2id でパスワードから鍵を導出しています…');
  const keys = await deriveKeys({
    linkSecret,
    kdfSalt,
    password: password || undefined,
    pwSalt,
    pwParams: ARGON2_DEFAULTS,
  });
  const authToken = await deriveAuthToken(linkSecret);

  const wrappedCek = await wrapCek(keys.kek, cekRaw, wrapNonce);
  const metaCipher = await encryptMeta(
    cek,
    { name: file.name, type: file.type, size: file.size },
    metaNonce,
  );
  cekRaw.fill(0);

  options.onStage('アップロードを開始しています…');
  const session = await postJson<{ uploadToken: string; totalChunks: number }>(
    '/api/uploads',
    { plainSize: file.size, chunkSize },
    signal,
  );

  let sent = 0;
  const abortSession = async () => {
    try {
      await fetch(`/api/uploads/${encodeURIComponent(session.uploadToken)}`, { method: 'DELETE' });
    } catch {
      /* 後始末は Cron でも行われる */
    }
  };

  try {
    options.onStage('暗号化してアップロードしています…');
    let next = 0;
    const worker = async () => {
      for (;;) {
        const index = next++;
        if (index >= chunks) return;
        if (signal.aborted) throw new DOMException('中止されました', 'AbortError');

        const start = index * chunkSize;
        const end = Math.min(file.size, start + chunkSize);
        const plain = new Uint8Array(await file.slice(start, end).arrayBuffer());
        const cipher = await encryptChunk(cek, plain, noncePrefix, index, chunks);
        plain.fill(0);

        await withRetry(
          () =>
            putBytes(
              `/api/uploads/${encodeURIComponent(session.uploadToken)}/parts/${index}`,
              cipher,
              signal,
            ),
          { signal },
        );

        sent += end - start;
        options.onProgress(sent, file.size);
      }
    };

    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, chunks) }, worker));

    options.onStage('仕上げをしています…');
    const completed = await postJson<{ token: string; expiresAt: number; maxDownloads: number | null }>(
      `/api/uploads/${encodeURIComponent(session.uploadToken)}/complete`,
      {
        expiresIn: options.expiresIn,
        maxDownloads: options.maxDownloads,
        authHash: await sha256Hex(authToken),
        hasPassword: Boolean(password),
        pwSalt: password ? toBase64Url(pwSalt) : null,
        pwParams: password ? ARGON2_DEFAULTS : null,
        pwHash: keys.pwVerifier ? await sha256Hex(keys.pwVerifier) : null,
        noncePrefix: toBase64Url(noncePrefix),
        kdfSalt: toBase64Url(kdfSalt),
        wrappedCek: toBase64Url(wrappedCek),
        wrapNonce: toBase64Url(wrapNonce),
        metaCipher: toBase64Url(metaCipher),
        metaNonce: toBase64Url(metaNonce),
      },
      signal,
    );

    // 復号鍵はフラグメントに載せる = HTTP リクエストに含まれずサーバーには届かない
    const url = `${location.origin}/d/${completed.token}#${toBase64Url(linkSecret)}`;
    return {
      url,
      token: completed.token,
      expiresAt: completed.expiresAt,
      maxDownloads: completed.maxDownloads,
    };
  } catch (error) {
    await abortSession();
    throw error;
  }
}

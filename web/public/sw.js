/**
 * 復号済みデータをブラウザのダウンロードとして書き出すための Service Worker。
 * ページから MessagePort でチャンクを受け取り、/_dl/<id> のレスポンスとして流す。
 * File System Access API が無い環境（Firefox / Safari）向けの経路。
 */

const streams = new Map();

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('message', (event) => {
  const data = event.data;
  if (!data || data.type !== 'init') return;
  streams.set(data.id, {
    port: event.ports[0],
    filename: data.filename,
    size: data.size,
    createdAt: Date.now(),
  });
  // 開始されないまま放置されたエントリを掃除する
  for (const [id, entry] of streams) {
    if (Date.now() - entry.createdAt > 60_000) streams.delete(id);
  }
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith('/_dl/')) return;

  // /_dl/<id>/<ファイル名> 。末尾にファイル名を置くのは、
  // Content-Disposition を解釈できない環境でも名前が保たれるようにするため
  const id = url.pathname.slice('/_dl/'.length).split('/')[0];
  const entry = streams.get(id);
  if (!entry) {
    event.respondWith(new Response('Not Found', { status: 404 }));
    return;
  }
  streams.delete(id);

  const { port, filename, size } = entry;
  const body = new ReadableStream({
    start(controller) {
      port.onmessage = (message) => {
        const data = message.data;
        if (data.type === 'chunk') {
          controller.enqueue(new Uint8Array(data.value));
        } else if (data.type === 'end') {
          controller.close();
          port.close();
        } else if (data.type === 'abort') {
          controller.error(new Error(data.reason || 'aborted'));
          port.close();
        }
      };
      port.start?.();
    },
    pull() {
      port.postMessage({ type: 'pull' });
    },
    cancel() {
      port.postMessage({ type: 'cancel' });
    },
  });

  // RFC 6266: 非 ASCII 名は filename* で渡し、古い解析系のために ASCII の代替も付ける
  const encoded = encodeURIComponent(filename).replace(/['()*]/g, (c) =>
    '%' + c.charCodeAt(0).toString(16).toUpperCase(),
  );
  const ascii = filename.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_') || 'download';

  event.respondWith(
    new Response(body, {
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(size),
        'Content-Disposition': `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      },
    }),
  );
});

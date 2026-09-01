import { ApiError } from './api.js';
import { formatBytes, formatDuration, formatRate } from './format.js';

export function describeError(error: unknown): string {
  if (error instanceof DOMException && error.name === 'AbortError') return '中止しました';
  if (error instanceof ApiError || error instanceof Error) return error.message;
  return '不明なエラーが発生しました';
}

/** 進捗から速度と残り時間を出す */
export function createTracker(total: number) {
  const startedAt = performance.now();
  return (done: number) => {
    const elapsed = (performance.now() - startedAt) / 1000;
    const rate = elapsed > 0 ? done / elapsed : 0;
    const remaining = rate > 0 ? (total - done) / rate : Infinity;
    return {
      ratio: total > 0 ? Math.min(1, done / total) : 1,
      text: `${formatBytes(done)} / ${formatBytes(total)} · ${formatRate(rate)} · 残り ${formatDuration(remaining)}`,
    };
  };
}

export async function copyToClipboard(text: string, trigger?: HTMLElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return;
  }
  if (!trigger) return;
  const original = trigger.getAttribute('title');
  trigger.setAttribute('title', 'コピーしました');
  const label = trigger.querySelector('span');
  if (label) {
    const text = label.textContent;
    label.textContent = 'コピーしました';
    setTimeout(() => (label.textContent = text), 1500);
  }
  setTimeout(() => {
    if (original) trigger.setAttribute('title', original);
  }, 1500);
}

/** パスによるルーティング。SPA フォールバックがあるので直リンクでも開ける */
export function navigate(path: string): void {
  if (location.pathname === path) return;
  history.pushState(null, '', path);
  window.dispatchEvent(new PopStateEvent('popstate'));
}

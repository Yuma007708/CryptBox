import { PUBLIC_ORIGIN } from './config.js';
import { getSettings } from './settings.js';

/**
 * 送信履歴。サーバーには何も残さず、送信した本人のブラウザにだけ保存する。
 * 復号鍵を含むリンクを保持するので、共有端末では設定から履歴を切れるようにしてある。
 */
export interface HistoryEntry {
  token: string;
  linkSecret: string;
  createdAt: number;
  expiresAt: number;
  maxDownloads: number | null;
  hasPassword: boolean;
  totalSize: number;
  files: { name: string; size: number }[];
}

const KEY = 'cryptbox.history.v1';
const LIMIT = 100;

export function listHistory(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const entries = JSON.parse(raw) as HistoryEntry[];
    return Array.isArray(entries) ? entries : [];
  } catch {
    return [];
  }
}

function write(entries: HistoryEntry[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(entries.slice(0, LIMIT)));
  } catch {
    /* 保存できない環境では履歴を諦める */
  }
}

export function addHistory(entry: HistoryEntry): void {
  if (!getSettings().keepHistory) return;
  write([entry, ...listHistory().filter((item) => item.token !== entry.token)]);
}

export function removeHistory(token: string): void {
  write(listHistory().filter((entry) => entry.token !== token));
}

export function clearHistory(): void {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* noop */
  }
}

export function historyUrl(entry: HistoryEntry): string {
  return `${PUBLIC_ORIGIN}/d/${entry.token}#${entry.linkSecret}`;
}

/** 期限切れのものを落として新しい順に返す */
export function activeHistory(now = Date.now()): HistoryEntry[] {
  const entries = listHistory();
  const active = entries.filter((entry) => entry.expiresAt > now);
  if (active.length !== entries.length) write(active);
  return active;
}

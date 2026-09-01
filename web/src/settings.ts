import { EXPIRY_OPTIONS } from '../../shared/format.js';

export type Theme = 'system' | 'light' | 'dark';

export interface Settings {
  theme: Theme;
  defaultExpiry: number;
  defaultMaxDownloads: number | null;
  keepHistory: boolean;
}

const KEY = 'cryptbox.settings.v1';

const DEFAULTS: Settings = {
  theme: 'system',
  defaultExpiry: EXPIRY_OPTIONS[2]!.seconds, // 7 日
  defaultMaxDownloads: 10,
  keepHistory: true,
};

function read(): Settings {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULTS };
    return { ...DEFAULTS, ...(JSON.parse(raw) as Partial<Settings>) };
  } catch {
    return { ...DEFAULTS };
  }
}

let current = read();

export function getSettings(): Settings {
  return current;
}

export function updateSettings(patch: Partial<Settings>): Settings {
  current = { ...current, ...patch };
  try {
    localStorage.setItem(KEY, JSON.stringify(current));
  } catch {
    /* プライベートモードなどで書けない場合はメモリ上だけ更新する */
  }
  applyTheme();
  return current;
}

/** 実際に表示されているテーマ（system の場合は OS の設定に従う） */
export function resolvedTheme(): 'light' | 'dark' {
  if (current.theme !== 'system') return current.theme;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function applyTheme(): void {
  document.documentElement.dataset.theme = resolvedTheme();
}

/** ヘッダーのボタン用: light ⇄ dark をその場で切り替える */
export function toggleTheme(): void {
  updateSettings({ theme: resolvedTheme() === 'dark' ? 'light' : 'dark' });
}

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if (current.theme === 'system') applyTheme();
});

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${UNITS[unit]}`;
}

export function formatRate(bytesPerSecond: number): string {
  if (!Number.isFinite(bytesPerSecond) || bytesPerSecond <= 0) return '—';
  return `${formatBytes(bytesPerSecond)}/s`;
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  if (seconds < 60) return `${Math.ceil(seconds)} 秒`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} 分 ${Math.floor(seconds % 60)} 秒`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} 時間 ${minutes % 60} 分`;
  const days = Math.floor(hours / 24);
  return `${days} 日 ${hours % 24} 時間`;
}

/** 「3 分前」「2 日前」のような相対表記 */
export function relativeTime(timestamp: number, now = Date.now()): string {
  const seconds = Math.max(0, (now - timestamp) / 1000);
  if (seconds < 60) return 'たった今';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} 分前`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} 時間前`;
  return `${Math.floor(hours / 24)} 日前`;
}

export function formatDateTime(timestamp: number): string {
  return new Date(timestamp).toLocaleString('ja-JP', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * 削除レシート: バンドルが削除されたとき「いつ・なぜ消えたか」を
 * サーバーの秘密鍵で署名した記録。トークンやファイル名は含まない。
 *
 * 署名対象の正規化文字列はフィールド順序を固定する:
 *   v1|<bundleId>|<createdAt>|<deletedAt>|<reason>|<fileCount>|<totalPlainSize>
 */

export const DELETION_REASONS = ['expired', 'limit_reached', 'sender_deleted'] as const;

export type DeletionReason = (typeof DELETION_REASONS)[number];

export interface DeletionReceipt {
  version: 1;
  /** SHA-256(shareToken) の hex。生トークンは含まない */
  bundleId: string;
  createdAt: number;
  deletedAt: number;
  reason: DeletionReason;
  fileCount: number;
  totalPlainSize: number;
  /** base64url(HMAC-SHA256(receiptSigningString(...))) */
  signature: string;
}

export type UnsignedDeletionReceipt = Omit<DeletionReceipt, 'signature'>;

/** 署名（および検証）対象の正規化文字列。フィールド順序は固定 */
export function receiptSigningString(receipt: UnsignedDeletionReceipt): string {
  return [
    'v1',
    receipt.bundleId,
    receipt.createdAt,
    receipt.deletedAt,
    receipt.reason,
    receipt.fileCount,
    receipt.totalPlainSize,
  ].join('|');
}

function isFiniteNonNegativeInt(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 0 &&
    !Object.is(value, -0)
  );
}

/** API/クライアントの境界で受け取った値がレシートの形をしているかを確認する（未検証の署名は別） */
export function isDeletionReceiptShape(value: unknown): value is DeletionReceipt {
  if (typeof value !== 'object' || value === null) return false;
  const r = value as Record<string, unknown>;
  return (
    r.version === 1 &&
    typeof r.bundleId === 'string' &&
    r.bundleId.length > 0 &&
    isFiniteNonNegativeInt(r.createdAt) &&
    isFiniteNonNegativeInt(r.deletedAt) &&
    typeof r.reason === 'string' &&
    (DELETION_REASONS as readonly string[]).includes(r.reason) &&
    isFiniteNonNegativeInt(r.fileCount) &&
    isFiniteNonNegativeInt(r.totalPlainSize) &&
    typeof r.signature === 'string' &&
    r.signature.length > 0
  );
}

/** 削除理由の日本語表示 */
export function describeDeletionReason(reason: DeletionReason): string {
  switch (reason) {
    case 'expired':
      return '有効期限切れ';
    case 'limit_reached':
      return 'ダウンロード上限に到達';
    case 'sender_deleted':
      return '送信者が削除';
  }
}

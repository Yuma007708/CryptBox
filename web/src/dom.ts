/** 小さな DOM ヘルパー。テンプレート文字列を使わないので XSS の余地がない */
type Child = Node | string | null | undefined | false;

interface Attributes {
  class?: string;
  id?: string;
  type?: string;
  href?: string;
  hidden?: boolean;
  disabled?: boolean;
  value?: string;
  placeholder?: string;
  title?: string;
  role?: string;
  readOnly?: boolean;
  autocomplete?: string;
  min?: string;
  max?: string;
  step?: string;
  dataset?: Record<string, string>;
  aria?: Record<string, string>;
  on?: Partial<{ [K in keyof HTMLElementEventMap]: (event: HTMLElementEventMap[K]) => void }>;
}

/**
 * URL を取る属性。値は allowlist で検査してから設定する。
 * `formAction` / `xlinkHref` のようなキャメルケース指定（コロン区切りの
 * `xlink:href` も含む）も同じ属性として扱えるよう、小文字化して比較する。
 */
const URL_ATTRIBUTES = new Set(['href', 'src', 'action', 'formaction', 'xlinkhref', 'poster']);

function normalizeAttrKey(key: string): string {
  return key.toLowerCase().replace(/[:-]/g, '');
}

const SAFE_SCHEMES = new Set(['http:', 'https:', 'mailto:']);

/**
 * `javascript:` / `data:` / `vbscript:` などのスクリプト実行可能な URL を弾く。
 * 許可するのは http / https / mailto と、`/` `#` `.` で始まる相対パスのみ。
 */
export function isSafeUrl(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed === '') return false;
  // 相対パス（プロトコル相対 `//host` はオリジンが変わるので除外）
  if (trimmed.startsWith('//')) return false;
  if (/^[/#.]/.test(trimmed)) return true;
  try {
    return SAFE_SCHEMES.has(new URL(trimmed, 'https://cryptbox.invalid/').protocol);
  } catch {
    return false;
  }
}

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attributes: Attributes = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  const { dataset, aria, on, ...rest } = attributes;

  for (const [key, value] of Object.entries(rest)) {
    if (value === undefined || value === null || value === false) continue;
    if (URL_ATTRIBUTES.has(normalizeAttrKey(key)) && !isSafeUrl(String(value))) {
      console.warn(`h(): 安全でない URL のため ${key} を無視しました`, value);
      continue;
    }
    if (key === 'class') node.className = String(value);
    else if (key === 'readOnly') (node as HTMLInputElement).readOnly = Boolean(value);
    else if (key === 'autocomplete') node.setAttribute('autocomplete', String(value));
    else if (key === 'hidden' || key === 'disabled') (node as never as Record<string, boolean>)[key] = Boolean(value);
    else if (key in node) (node as never as Record<string, unknown>)[key] = value;
    else node.setAttribute(key, String(value));
  }

  if (dataset) for (const [key, value] of Object.entries(dataset)) node.dataset[key] = value;
  if (aria) for (const [key, value] of Object.entries(aria)) node.setAttribute(`aria-${key}`, value);
  if (on) {
    for (const [event, handler] of Object.entries(on)) {
      node.addEventListener(event, handler as EventListener);
    }
  }

  append(node, children);
  return node;
}

export function append(parent: Node, children: Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    parent.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
}

export function clear(node: Element): void {
  node.replaceChildren();
}

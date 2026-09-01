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

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attributes: Attributes = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  const { dataset, aria, on, ...rest } = attributes;

  for (const [key, value] of Object.entries(rest)) {
    if (value === undefined || value === null || value === false) continue;
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

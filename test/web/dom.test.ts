import { afterEach, describe, expect, it, vi } from 'vitest';
import { h, isSafeUrl } from '../../web/src/dom.js';

describe('isSafeUrl', () => {
  it('http / https / mailto を許可する', () => {
    expect(isSafeUrl('https://example.com/a?b=1')).toBe(true);
    expect(isSafeUrl('http://example.com')).toBe(true);
    expect(isSafeUrl('mailto:abuse@example.com')).toBe(true);
  });

  it('相対パス（/ # . 始まり）を許可する', () => {
    expect(isSafeUrl('/help')).toBe(true);
    expect(isSafeUrl('#top')).toBe(true);
    expect(isSafeUrl('./a.png')).toBe(true);
    expect(isSafeUrl('../b.png')).toBe(true);
  });

  it('javascript: / data: / vbscript: を拒否する', () => {
    expect(isSafeUrl('javascript:alert(1)')).toBe(false);
    expect(isSafeUrl('  JavaScript:alert(1)')).toBe(false);
    expect(isSafeUrl('java\tscript:alert(1)')).toBe(false);
    expect(isSafeUrl('data:text/html,<script>alert(1)</script>')).toBe(false);
    expect(isSafeUrl('vbscript:msgbox(1)')).toBe(false);
  });

  it('プロトコル相対 URL と空文字を拒否する', () => {
    expect(isSafeUrl('//evil.example')).toBe(false);
    expect(isSafeUrl('')).toBe(false);
    expect(isSafeUrl('   ')).toBe(false);
  });
});

describe('h(): URL 属性の allowlist', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('安全な href はそのまま設定する', () => {
    const a = h('a', { href: '/help' }, 'ヘルプ');
    expect(a.getAttribute('href')).toBe('/help');
  });

  it('javascript: の href は属性ごと落とし、console.warn する', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const a = h('a', { href: 'javascript:alert(1)' }, 'x');

    expect(a.hasAttribute('href')).toBe(false);
    expect(warn).toHaveBeenCalled();
  });

  it('data: の src も落とす', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const img = h('img', { src: 'data:text/html,<script>alert(1)</script>' } as never);
    expect(img.hasAttribute('src')).toBe(false);
  });

  it('URL 以外の属性は検査対象にしない', () => {
    const input = h('input', { value: 'javascript:not-a-url' });
    expect(input.value).toBe('javascript:not-a-url');
  });

  it('formAction のようなキャメルケース属性も allowlist 検査を通す', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const button = h('button', { formAction: 'javascript:alert(1)' } as never);

    expect(button.hasAttribute('formAction')).toBe(false);
    expect(button.hasAttribute('formaction')).toBe(false);
    expect(warn).toHaveBeenCalled();
  });

  it('安全な formAction は設定される', () => {
    const button = h('button', { formAction: '/submit' } as never);
    expect((button as HTMLButtonElement).formAction).toContain('/submit');
  });

  it('xlinkHref のようなキャメルケース属性も allowlist 検査を通す', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const use = h('a', { xlinkHref: 'javascript:alert(1)' } as never);

    expect(use.hasAttribute('xlinkHref')).toBe(false);
    expect(use.hasAttribute('xlinkhref')).toBe(false);
    expect(warn).toHaveBeenCalled();
  });
});

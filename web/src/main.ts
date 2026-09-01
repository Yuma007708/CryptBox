import { clear, h } from './dom.js';
import { brandMark, icon } from './icons.js';
import { applyTheme, resolvedTheme, toggleTheme } from './settings.js';
import { navigate } from './ui.js';
import { renderHelp } from './views/help.js';
import { renderHistory } from './views/history.js';
import { renderReceive } from './views/receive.js';
import { renderSend } from './views/send.js';
import { renderSettings } from './views/settings.js';

interface Route {
  path: string;
  label: string;
  iconName: string;
  render(view: HTMLElement): void;
}

const ROUTES: Route[] = [
  { path: '/', label: 'ファイルを送る', iconName: 'upload', render: renderSend },
  { path: '/history', label: '送信履歴', iconName: 'clock', render: renderHistory },
  { path: '/settings', label: '設定', iconName: 'settings', render: renderSettings },
  { path: '/help', label: 'ヘルプ', iconName: 'help', render: renderHelp },
];

const root = document.getElementById('app')!;
applyTheme();

function themeButton(): HTMLElement {
  const button = h('button', {
    type: 'button',
    class: 'icon-button',
    title: 'テーマを切り替える',
    aria: { label: 'テーマを切り替える' },
  });
  const paint = () => {
    clear(button);
    button.append(icon(resolvedTheme() === 'dark' ? 'moon' : 'sun'));
  };
  button.addEventListener('click', () => {
    toggleTheme();
    paint();
  });
  paint();
  return button;
}

function renderShell(active: Route): void {
  clear(root);
  const view = h('div', { class: 'view' });

  const nav = h('nav', { class: 'nav' });
  for (const route of ROUTES.slice(0, 2)) nav.append(navItem(route, active));

  const nav2 = h('nav', { class: 'nav' });
  for (const route of ROUTES.slice(2)) nav2.append(navItem(route, active));

  const sidebar = h(
    'aside',
    { class: 'sidebar' },
    h(
      'a',
      {
        class: 'brand',
        href: '/',
        on: {
          click: (event) => {
            event.preventDefault();
            navigate('/');
          },
        },
      },
      brandMark(28),
      h('span', { class: 'brand-name' }, 'Crypt', h('em', {}, 'Box')),
    ),
    nav,
    h('div', { class: 'nav-divider' }),
    nav2,
    h('div', { class: 'sidebar-spacer' }),
    h(
      'div',
      { class: 'sidebar-card' },
      icon('shield'),
      h('h3', {}, 'エンドツーエンド暗号化'),
      h('p', {}, '鍵はこのブラウザから出ません。サーバーは暗号文しか保持しません。'),
    ),
  );

  root.append(
    h(
      'div',
      { class: 'layout' },
      sidebar,
      h('div', { class: 'content' }, h('header', { class: 'topbar' }, themeButton()), view),
    ),
  );

  active.render(view);
}

function navItem(route: Route, active: Route): HTMLElement {
  return h(
    'button',
    {
      type: 'button',
      class: route === active ? 'nav-item active' : 'nav-item',
      on: { click: () => navigate(route.path) },
    },
    icon(route.iconName),
    h('span', {}, route.label),
  );
}

function render(): void {
  const receive = /^\/d\/([A-Za-z0-9_-]+)\/?$/.exec(location.pathname);
  if (receive) {
    clear(root);
    renderReceive(root, receive[1]!);
    return;
  }
  const route = ROUTES.find((candidate) => candidate.path === location.pathname) ?? ROUTES[0]!;
  renderShell(route);
}

window.addEventListener('popstate', render);
render();

import { h } from './dom.js';
import { getServerConfig } from './server-config.js';

export type AdSlotName = 'receive-top' | 'receive-bottom' | 'send-progress';

/**
 * 広告枠（ダミー）を返す。広告ネットワークはまだ接続していない —
 * レイアウトと ON/OFF の仕組みだけをここに用意する。
 *
 * `GET /api/config` の `adsEnabled` は非同期にしか分からないため、呼び出し直後は
 * 見た目に何も残らない空のマウント要素を返し、判明した時点で有効なら
 * 固定サイズのプレースホルダーに差し替える。無効なままなら何も描画しない。
 *
 * 復号や鍵に触れるコードとは完全に分離する。このファイルは `location.hash`
 * （URL の # 以降＝復号鍵）を一切読まない。
 */
export function adSlot(name: AdSlotName): DocumentFragment {
  const mount = h('div', { class: 'ad-slot-mount' });
  const fragment = document.createDocumentFragment();
  fragment.append(mount);

  void getServerConfig().then((config) => {
    if (!config.adsEnabled) return;
    mount.replaceWith(placeholder(name));
  });

  return fragment;
}

/**
 * 固定サイズのプレースホルダー。`data-ad-slot` は、将来ここに広告ネットワークの
 * `iframe` タグを差し込む場所の目印。今回はタグは入れない。
 */
function placeholder(name: AdSlotName): HTMLElement {
  return h(
    'div',
    {
      class: 'ad-slot',
      dataset: { adSlot: name },
      role: 'complementary',
      aria: { label: '広告' },
    },
    h('span', { class: 'ad-slot-label' }, '広告'),
    h('span', { class: 'ad-slot-note' }, 'スポンサー枠（準備中）'),
  );
}

import { get, post } from './api.js';
import { $, $$, esc, store, toast, clock, lsGet, lsSet, applyTheme, openDialog, closeDialog } from './util.js';
import { setSoundEnabled, playSound } from './sound.js';
import { elevate } from './forms.js';
import * as summary from './summary.js';
import * as target from './target.js';
import * as events from './events.js';
import * as apps from './apps.js';
import * as alerts from './alerts.js';
import * as settings from './settings.js';

applyTheme();
setSoundEnabled(lsGet('sound', true));

let current = null, unread = 0, soundHinted = false;

function route() {
  const h = location.hash || '#/';
  current?.destroy?.(); current = null;
  const root = $('#view'); root.innerHTML = '';
  document.title = 'TraceMe';
  let nav = 'summary';
  if (h.startsWith('#/t/')) current = target.mount(root, decodeURIComponent(h.slice(4)));
  else if (h.startsWith('#/apps')) { nav = 'apps'; const k = h.slice(6).replace(/^\//, ''); current = apps.mount(root, k ? decodeURIComponent(k) : null); }
  else if (h.startsWith('#/events')) { nav = 'events'; unread = 0; showCount(); current = events.mount(root); }
  else if (h.startsWith('#/alerts')) { nav = 'alerts'; current = alerts.mount(root); }
  else if (h.startsWith('#/settings')) { nav = 'settings'; current = settings.mount(root); }
  else current = summary.mount(root);
  $$('#nav a').forEach(a => a.classList.toggle('on', a.dataset.nav === nav));
}

function showCount() { const c = $('#evCount'); c.hidden = !unread; c.textContent = unread > 99 ? '99+' : unread; }

function renderBanners() {
  const limited = store.targets.filter(t => t.method !== 'icmp' && !t.agent);
  const el = $('#banners');
  if (!store.system.elevated && limited.length) {
    el.innerHTML = `<div class="banner"><span class="grow"><b>${limited.length} UDP/TCP target${limited.length > 1 ? 's' : ''}</b> can detect the destination but not the routers on the path: Windows only delivers ICMP “Time Exceeded” messages to administrators.</span><button id="bElev">Restart as administrator</button></div>`;
    $('#bElev').onclick = elevate;
  } else el.innerHTML = '';
}

function startEventStream() {
  const es = new EventSource('/api/events/stream');
  es.onmessage = ev => {
    const m = JSON.parse(ev.data), e = m.event;
    document.dispatchEvent(new CustomEvent('tm-event', { detail: m }));
    if (m.toast) toast(e.message, e.severity === 'warn' ? 'warn' : e.severity === 'critical' ? 'critical' : 'info', e.severity === 'info' ? 6000 : 12000);
    if (m.sound && !playSound(m.sound) && !soundHinted && lsGet('sound', true)) { soundHinted = true; toast('Click anywhere on the page once to enable alert sounds.', 'info'); }
    if (lsGet('notify', false) && e.type === 'alert' && e.severity !== 'info' && 'Notification' in window && Notification.permission === 'granted') new Notification('TraceMe alert', { body: e.message });
    if (e.severity !== 'info' && !location.hash.startsWith('#/events')) { unread++; showCount(); }
  };
}

function login() {
  if ($('#dlg').open) return;
  openDialog(`<div class="hd"><h2>Access token required</h2></div><div class="bd">
      <p class="mute">This TraceMe instance is protected. Enter the token printed on the console or set in <span class="mono">TRACEME_TOKEN</span>.</p>
      <label class="f">Token<input name="token" type="password" autofocus autocomplete="current-password"></label></div>
      <div class="ft"><button class="primary" value="ok">Sign in</button></div>`,
    { onSubmit: async fd => { await post('/login', { token: fd.get('token') }); location.reload(); } });
}
document.addEventListener('tm-unauthorized', login);

$('#themeBtn').onclick = () => {
  const order = ['auto', 'light', 'dark'], next = order[(order.indexOf(lsGet('theme', 'auto')) + 1) % 3];
  lsSet('theme', next); applyTheme(); toast('Theme: ' + next, 'info', 1500);
  document.dispatchEvent(new CustomEvent('tm-settings'));
};

async function boot() {
  try {
    store.system = await get('/system');
    clock.offset = store.system.time - Date.now();
    store.settings = await get('/settings');
  } catch (e) { if (e.message !== 'Authentication required') $('#view').innerHTML = `<div class="empty bad">Cannot reach the TraceMe service: ${esc(e.message)}</div>`; return; }
  const b = $('#adminBadge');
  b.textContent = store.system.elevated ? 'Administrator' : 'Standard user';
  b.className = 'badge ' + (store.system.elevated ? 'good' : 'plain');
  b.title = store.system.elevated ? 'UDP and TCP traces can read router addresses' : 'ICMP traces work fully; UDP/TCP can only detect the destination';
  b.style.cursor = store.system.elevated ? '' : 'pointer';
  b.onclick = () => { if (!store.system.elevated) elevate(); };
  document.addEventListener('tm-settings', async () => { try { store.settings = await get('/settings'); } catch { /* keep old */ } });
  document.addEventListener('tm-targets', renderBanners);
  try { store.targets = await get('/targets'); } catch { /* summary will retry */ }
  renderBanners(); startEventStream();
  addEventListener('hashchange', route); route();
}
boot();

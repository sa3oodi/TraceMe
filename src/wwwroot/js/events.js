import { get, del } from './api.js';
import { $, esc, fmtTime, store, toast } from './util.js';

const TYPES = ['alert', 'route', 'error', 'info'];

export function mount(root) {
  let tid = '', type = '', items = [], more = false, dead = false;
  root.innerHTML = `
    <div class="row" style="margin-bottom:10px"><h2 class="grow">Events</h2>
      <select id="ftid" aria-label="Target"><option value="">All targets</option></select>
      <select id="ftype" aria-label="Type"><option value="">All types</option>${TYPES.map(t => `<option>${t}</option>`).join('')}</select>
      <button id="clear" class="danger">Clear…</button></div>
    <div class="panel flush"><div id="list" class="list"></div></div>
    <p class="row" style="justify-content:center"><button id="more" hidden>Load older</button></p>`;

  const name = id => store.targets.find(t => t.id === id)?.displayName ?? id;
  async function load(reset) {
    const before = !reset && items.length ? items[items.length - 1].id : '';
    const q = new URLSearchParams({ limit: 100 }); if (tid) q.set('tid', tid); if (type) q.set('type', type); if (before) q.set('before', before);
    const batch = await get('/events?' + q);
    items = reset ? batch : items.concat(batch); more = batch.length === 100;
    render();
  }
  function render() {
    if (dead) return;
    $('#list', root).innerHTML = items.length ? items.map(e =>
      `<div class="item"><span class="sev ${e.severity}"></span><span class="t">${fmtTime(e.t, true)}</span>
       <span class="grow">${esc(e.message)}</span>${e.tid ? `<a href="#/t/${e.tid}" class="badge plain">${esc(name(e.tid))}</a>` : ''}<span class="badge plain">${esc(e.type)}</span></div>`).join('')
      : '<div class="empty"><h2>No events</h2>Alerts, route changes and errors show up here.</div>';
    $('#more', root).hidden = !more;
  }
  const fill = () => { $('#ftid', root).innerHTML = '<option value="">All targets</option>' + store.targets.map(t => `<option value="${t.id}" ${t.id === tid ? 'selected' : ''}>${esc(t.displayName)}</option>`).join(''); };
  (async () => { if (!store.targets.length) { try { store.targets = await get('/targets'); } catch { /* ignore */ } } fill(); load(true); })();
  $('#ftid', root).onchange = e => { tid = e.target.value; load(true); };
  $('#ftype', root).onchange = e => { type = e.target.value; load(true); };
  $('#more', root).onclick = () => load(false);
  $('#clear', root).onclick = async () => {
    if (!confirm(tid ? 'Delete the events of this target?' : 'Delete all events?')) return;
    await del('/events' + (tid ? '?tid=' + tid : '')); toast('Events cleared'); load(true);
  };
  const onEv = e => {
    const ev = e.detail.event;
    if ((!tid || ev.tid === tid) && (!type || ev.type === type)) { items.unshift(ev); render(); }
  };
  document.addEventListener('tm-event', onEv);
  return { destroy() { dead = true; document.removeEventListener('tm-event', onEv); } };
}

import { get, post } from './api.js';
import { $, $$, esc, fmtMs, fmtPct, health, latClass, lossClass, mosClass, store, toast, menu, lsGet, lsSet } from './util.js';
import { drawSpark } from './graphs.js';
import { targetDialog } from './forms.js';

const STATUS_LABEL = { starting: 'starting…', paused: 'paused', stopped: 'stopped (auto-stop)', error: 'error', running: '' };

function card(t) {
  const h = health(t);
  const addr = t.address && t.address !== t.host ? `${esc(t.host)} <span class="mute">→ ${esc(t.address)}</span>` : esc(t.host);
  const st = STATUS_LABEL[t.status];
  return `<div class="panel card" data-id="${t.id}" draggable="true" tabindex="0" role="link" aria-label="Open ${esc(t.displayName)}">
    <div class="title"><span class="dot ${h}"></span><span class="grow" style="overflow:hidden;text-overflow:ellipsis">${esc(t.displayName)}</span>
      ${t.appKey ? `<span class="chip game" title="Traced for ${esc(t.appKey)}">APP</span>` : ''}<span class="badge">${esc(t.method)}${t.agent ? ' · agent' : ''}</span>
      <button class="ghost icon sm" data-act="menu" aria-label="Target menu">⋯</button></div>
    <div class="mute mono" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${addr}</div>
    <div class="metrics">
      <div class="metric"><b class="${latClass(t.avg)}">${fmtMs(t.avg)}</b><span>avg ms</span></div>
      <div class="metric"><b>${fmtMs(t.jitter)}</b><span>jitter</span></div>
      <div class="metric"><b class="${lossClass(t.lossPct)}">${fmtPct(t.lossPct)}</b><span>loss</span></div>
      <div class="metric"><b class="${mosClass(t.mos)}">${t.mos ?? '–'}</b><span>MOS</span></div>
    </div>
    <canvas data-spark="${t.id}" style="width:100%;height:38px;display:block"></canvas>
    <div class="row mute" style="font-size:12px">
      <span>${t.destHop ? t.destHop + ' hops' : t.hopCount ? '≥' + t.hopCount + ' hops' : ''}</span>
      <span>${t.round} traces</span><span class="spacer"></span>
      ${t.alerts?.length ? `<span class="badge bad" title="${esc(t.alerts.map(a => a.rule + ' (hop ' + a.hop + ')').join('\n'))}">${t.alerts.length} alert${t.alerts.length > 1 ? 's' : ''}</span>` : ''}
      ${st ? `<span class="badge ${t.status === 'error' ? 'bad' : 'plain'}" title="${esc(t.error || '')}">${st}</span>` : ''}
      ${t.warning ? `<span class="badge warn" title="${esc(t.warning)}">limited</span>` : ''}
    </div>
    ${t.error ? `<div class="bad" style="font-size:12px">${esc(t.error)}</div>` : ''}
  </div>`;
}

export function mount(root) {
  let timer = null, dead = false, filter = lsGet('filter', '');
  root.innerHTML = `
    <div class="row" style="margin-bottom:6px">
      <h2 class="grow">Targets</h2>
      <input id="flt" type="search" placeholder="Filter…" value="${esc(filter)}" style="width:180px" aria-label="Filter targets">
      <button class="primary" id="add">+ Add target</button>
    </div>
    <div id="list"></div>`;

  async function addTarget() {
    const r = await targetDialog();
    if (r && r.id) { toast(`Tracing ${r.displayName}`); location.hash = '#/t/' + r.id; }
  }
  $('#add', root).onclick = addTarget;
  $('#flt', root).oninput = e => { filter = e.target.value; lsSet('filter', filter); render(); };

  function render() {
    const f = filter.trim().toLowerCase();
    const list = store.targets.filter(t => !f || [t.displayName, t.host, t.address, t.group].some(x => (x || '').toLowerCase().includes(f)));
    const host = $('#list', root);
    if (!store.targets.length) {
      host.innerHTML = `<div class="panel empty"><h2>Nothing is being traced yet</h2>
        <p>Add a host to start a continuous traceroute with per-hop latency, jitter and packet loss.</p>
        <p><button class="primary" id="add2">+ Add target</button> <button id="quick">Trace 8.8.8.8</button></p></div>`;
      $('#add2', host).onclick = addTarget;
      $('#quick', host).onclick = async () => { const r = await post('/targets', { host: '8.8.8.8', method: 'icmp' }); location.hash = '#/t/' + r.id; };
      return;
    }
    if (!list.length) { host.innerHTML = '<div class="empty">No targets match the filter.</div>'; return; }
    const groups = new Map();
    for (const t of list) { const g = t.group || ''; if (!groups.has(g)) groups.set(g, []); groups.get(g).push(t); }
    const names = [...groups.keys()].sort((a, b) => (a === '') - (b === '') || a.localeCompare(b));
    host.innerHTML = names.map(g => `${names.length > 1 || g ? `<div class="group-h">${esc(g || 'Ungrouped')}</div>` : ''}<div class="grid cards">${groups.get(g).map(card).join('')}</div>`).join('');
    const maxOf = t => Math.max(5, ...(t.series || []).filter(v => v != null)) * 1.15;
    for (const t of list) { const c = host.querySelector(`canvas[data-spark="${t.id}"]`); if (c) drawSpark(c, t.series || [], { max: maxOf(t) }); }
  }

  root.addEventListener('click', async e => {
    const c = e.target.closest('.card'); if (!c) return;
    const t = store.targets.find(x => x.id === c.dataset.id); if (!t) return;
    if (e.target.closest('[data-act=menu]')) {
      e.stopPropagation();
      menu(e.target.closest('button'), [
        { label: t.status === 'paused' || t.status === 'stopped' ? 'Resume' : 'Pause', fn: async () => { await post(`/targets/${t.id}/pause`, { paused: !(t.status === 'paused' || t.status === 'stopped') }); refresh(); } },
        { label: 'Settings…', fn: async () => { const full = await get('/targets/' + t.id); const r = await targetDialog(full); if (r) refresh(); } },
        { label: 'Duplicate', fn: async () => { const full = await get('/targets/' + t.id); const { id, created, sort, paused, ...cfg } = full.config; cfg.name = (cfg.name || cfg.host) + ' (copy)'; if (cfg.agentToken === '••••••') cfg.agentToken = null; await post('/targets', cfg); refresh(); } },
      ]);
      return;
    }
    location.hash = '#/t/' + t.id;
  });
  root.addEventListener('keydown', e => { if (e.key === 'Enter' && e.target.classList?.contains('card')) location.hash = '#/t/' + e.target.dataset.id; });

  // drag to reorder
  let dragId = null;
  root.addEventListener('dragstart', e => { const c = e.target.closest?.('.card'); if (c) { dragId = c.dataset.id; e.dataTransfer.effectAllowed = 'move'; } });
  root.addEventListener('dragover', e => { const c = e.target.closest?.('.card'); if (c && dragId) { e.preventDefault(); $$('.card.dragover', root).forEach(x => x.classList.remove('dragover')); c.classList.add('dragover'); } });
  root.addEventListener('dragend', () => { dragId = null; $$('.card.dragover', root).forEach(x => x.classList.remove('dragover')); });
  root.addEventListener('drop', async e => {
    const c = e.target.closest?.('.card'); if (!c || !dragId || c.dataset.id === dragId) return;
    e.preventDefault();
    const ids = store.targets.map(t => t.id).filter(i => i !== dragId);
    ids.splice(ids.indexOf(c.dataset.id), 0, dragId);
    store.targets.sort((a, b) => ids.indexOf(a.id) - ids.indexOf(b.id));
    dragId = null; render();
    await post('/targets/reorder', { ids });
  });

  async function refresh() {
    try { store.targets = await get('/targets'); document.dispatchEvent(new CustomEvent('tm-targets')); if (!dead) render(); } catch { /* retry on next tick */ }
  }
  refresh();
  timer = setInterval(() => { if (!document.hidden && !$('#dlg').open) refresh(); }, 2000);
  return { destroy() { dead = true; clearInterval(timer); } };
}

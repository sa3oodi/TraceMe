import { get, post, put, del } from './api.js';
import {
  $, $$, esc, fmtMs, fmtPct, fmtTime, fmtDuration, latClass, lossClass, mosClass, mosFrom, now, store, toast, menu, popover,
  lsGet, lsSet, throttle, download, copyText, openDialog,
} from './util.js';
import { Timeline, drawSpark } from './graphs.js';
import { targetDialog, alertDialog, elevate } from './forms.js';
import { verdictCard, pathStrip } from './diagnosis.js';

const WINDOWS = [['5m', 5 * 60e3], ['15m', 15 * 60e3], ['30m', 30 * 60e3], ['1h', 3600e3], ['3h', 3 * 3600e3], ['6h', 6 * 3600e3], ['12h', 12 * 3600e3], ['24h', 24 * 3600e3], ['7d', 7 * 86400e3]];

const BASE_COLS = [
  { k: 'hop', label: 'Hop', always: true },
  { k: 'host', label: 'Host', cls: 'l', always: true },
  { k: 'asn', label: 'AS / owner', cls: 'l' },
  { k: 'sent', label: 'Count' },
  { k: 'avg', label: 'Avg ms' },
  { k: 'min', label: 'Min' },
  { k: 'max', label: 'Max' },
  { k: 'last', label: 'Cur' },
  { k: 'jitter', label: 'Jitter' },
  { k: 'loss', label: 'PL %' },
  { k: 'band', label: 'Min – Max  (│ avg)' },
  { k: 'spark', label: 'Recent' },
];
const colClass = c => String(c.k).replace(/[^\w-]/g, '_');
const DEFAULT_COLS =['hop', 'host', 'sent', 'avg', 'min', 'max', 'last', 'jitter', 'loss', 'band', 'spark'];

export function mount(root, id) {
  let snap = null, selHop = null, es = null, dead = false;
  let view = lsGet('view', { mode: 'live', ms: 5 * 60e3 });
  if (view.mode !== 'live') view = { mode: 'live', ms: view.ms || 5 * 60e3 };
  let sel = null, selStats = null, tlAbort = null, tlTimer = null, tabTimer = null;
  let tab = lsGet('tab', 'events');
  let cols = lsGet('cols', DEFAULT_COLS);
  let tl = null;

  root.innerHTML = `
    <div class="row" style="margin-bottom:10px" id="head"></div>
    <div id="notices"></div>
    <div class="panel"><div class="bd"><div class="strip" id="strip"></div></div></div>
    <div id="diag" class="diagpanel"></div>
    <div class="panel flush" style="margin-top:14px">
      <div class="hd"><h3>Hops</h3><span id="scope" class="mute grow"></span>
        <button class="sm" id="colsBtn">Columns ▾</button></div>
      <div class="bd" id="tbl"></div>
    </div>
    <div class="panel" style="margin-top:14px">
      <div class="hd" style="flex-wrap:wrap">
        <h3 id="tlTitle">Timeline</h3><span class="spacer"></span>
        <div class="seg" id="win" role="group" aria-label="Time window"></div>
        <button class="sm" id="zoomSel" hidden>Zoom to selection</button>
        <button class="sm" id="clrSel" hidden>Clear selection</button>
        <button class="sm" id="addComment">+ Comment</button>
      </div>
      <div class="tl-wrap" id="tlw"><canvas class="tl main" aria-label="Latency timeline"></canvas><canvas class="tl small jit" aria-label="Jitter timeline"></canvas></div>
      <div class="legend"><span><i style="background:var(--graph-line)"></i>average</span><span><i style="background:var(--graph-band)"></i>min – max</span>
        <span><i style="background:var(--graph-loss)"></i>packet loss</span><span><i style="background:#d97706"></i>route change</span><span><i style="background:#dc2626"></i>alert</span><span><i style="background:#2563eb"></i>comment</span>
        <span class="spacer"></span><span>Drag on the graph to select a period · double-click to clear</span></div>
    </div>
    <div class="panel" style="margin-top:14px">
      <div class="tabs" id="tabs">
        <button data-tab="events">Events</button><button data-tab="routes">Route history</button>
        <button data-tab="comments">Comments</button><button data-tab="info">Details</button>
      </div>
      <div id="tabbody"></div>
    </div>`;

  tl = new Timeline($('#tlw', root), { onSelect: onSelectRange });

  // ------------------------------------------------------------------ helpers
  const range = () => { if (view.mode === 'frozen') return { from: view.from, to: view.to }; const to = now(); return { from: to - view.ms, to }; };
  const rowsNow = () => (sel && selStats ? selStats.hops : snap?.hops) || [];
  const destRow = rows => rows.find(h => h.hop === snap?.destHop) || [...rows].reverse().find(h => h.recv > 0);
  const customCols = () => (store.settings.columns || []).filter(c => c.visible !== false);
  const allCols = () => [...BASE_COLS, ...customCols().map(c => ({ k: 'c:' + c.id, label: c.name, cc: c }))];
  const visible = () => allCols().filter(c => c.always || cols.includes(c.k) || (c.cc && !cols.includes('-' + c.k)));

  // ------------------------------------------------------------------ rendering
  function renderHead() {
    const s = snap; if (!s) return;
    document.title = `${s.displayName} – TraceMe`;
    const paused = s.status === 'paused' || s.status === 'stopped';
    $('#head', root).innerHTML = `
      <a href="#/" class="ghost" style="padding:4px 8px" aria-label="Back to summary">←</a>
      <div class="grow" style="min-width:200px"><h2 style="font-size:19px">${esc(s.displayName)} <span class="badge">${esc(s.method)}${s.agent ? ' · remote agent' : ''}</span>
        ${paused ? `<span class="badge plain">${s.status}</span>` : ''}</h2>
        <div class="mute mono">${esc(s.host)}${s.address && s.address !== s.host ? ' → ' + esc(s.address) : ''}${s.source ? '  ·  from ' + esc(s.source) : ''}${s.destHop ? '  ·  ' + s.destHop + ' hops' : ''}</div></div>
      <button id="bPause">${paused ? '▶ Resume' : '❚❚ Pause'}</button>
      <button id="bNow" title="Run a trace immediately" ${paused ? 'disabled' : ''}>Trace now</button>
      <button id="bReset" title="Restart session statistics">Reset stats</button>
      <button id="bExport">Export ▾</button>
      <button id="bEdit">Settings</button>`;
    $('#bPause', root).onclick = () => post(`/targets/${id}/pause`, { paused: !paused });
    $('#bNow', root).onclick = () => post(`/targets/${id}/trace-now`);
    $('#bReset', root).onclick = () => { sel = selStats = null; post(`/targets/${id}/reset`); renderScope(); };
    $('#bEdit', root).onclick = async () => { const r = await targetDialog(snap); if (r?.deleted) location.hash = '#/'; };
    $('#bExport', root).onclick = e => menu(e.currentTarget, [
      { label: 'CSV (selection or visible range)', fn: () => { const r = sel || range(); location.href = `/api/targets/${id}/export.csv?from=${r.from}&to=${r.to}`; } },
      { label: 'Timeline image (PNG)', fn: async () => download(`traceme-${snap.displayName.replace(/\W+/g, '_')}-hop${selHop}.png`, await tl.toPng(`${snap.displayName} — hop ${selHop}`)) },
      { label: 'Path as text (copy)', fn: () => copyText(pathText()) },
      { label: 'Snapshot (JSON)', fn: () => download(`traceme-${snap.displayName.replace(/\W+/g, '_')}.json`, JSON.stringify(snap, null, 2), 'application/json') },
    ]);
  }

  function pathText() {
    const rows = rowsNow();
    return `TraceMe — ${snap.displayName} (${snap.method.toUpperCase()}) ${new Date().toLocaleString()}\n` +
      'Hop  Host                                      Sent  Loss%   Avg    Min    Max   Jitter\n' +
      rows.map(h => `${String(h.hop).padStart(3)}  ${(h.name ? h.name + ' [' + h.address + ']' : h.address || '*').padEnd(40)}  ${String(h.sent).padStart(4)}  ${String(fmtPct(h.lossPct, 1)).padStart(6)}  ${String(fmtMs(h.avg)).padStart(5)}  ${String(fmtMs(h.min)).padStart(5)}  ${String(fmtMs(h.max)).padStart(5)}  ${String(fmtMs(h.jitter)).padStart(5)}`).join('\n');
  }

  function renderNotices() {
    const s = snap, out = [];
    if (s.error) out.push(`<div class="banner err"><span class="grow"><b>Error:</b> ${esc(s.error)}</span></div>`);
    if (s.warning) out.push(`<div class="banner"><span class="grow">${esc(s.warning)}</span>${store.system.elevated ? '' : '<button id="nElev">Restart as administrator</button>'}</div>`);
    if (s.status === 'stopped') out.push('<div class="banner"><span class="grow">Tracing stopped automatically (auto-stop condition reached).</span><button id="nResume">Resume</button></div>');
    if (s.alerts?.length) out.push(`<div class="banner err"><span class="grow"><b>Active alerts:</b> ${s.alerts.map(a => `${esc(a.rule)} (hop ${a.hop})`).join(', ')}</span></div>`);
    const host = $('#notices', root); host.innerHTML = out.join('');
    $('#nElev', host)?.addEventListener('click', elevate);
    $('#nResume', host)?.addEventListener('click', () => post(`/targets/${id}/pause`, { paused: false }));
  }

  function renderStrip() {
    const rows = rowsNow(), d = destRow(rows);
    const mos = sel ? mosFrom(d?.avg, d?.jitter, d?.lossPct ?? 0) : snap.mos;
    const item = (v, l, c = '') => `<div class="s"><b class="${c}">${v}</b><span>${l}</span></div>`;
    $('#strip', root).innerHTML = d ? [
      item(fmtMs(d.avg), 'avg latency (ms)', latClass(d.avg)), item(fmtMs(d.min), 'min'), item(fmtMs(d.max), 'max'),
      item(fmtMs(d.jitter), 'jitter (ms)'), item(fmtPct(d.lossPct), 'packet loss', lossClass(d.lossPct)),
      item(mos ?? '–', 'MOS', mosClass(mos)), item(rows.length, 'hops'), item(d.sent.toLocaleString(), 'samples'),
    ].join('') : '<div class="mute">Waiting for the first replies…</div>';
  }

  function renderScope() {
    const el = $('#scope', root);
    el.innerHTML = sel
      ? `Selection <b>${fmtTime(sel.from)} – ${fmtTime(sel.to)}</b> (${fmtDuration(sel.to - sel.from)}) <button class="sm" id="scopeClr">✕ back to live</button>`
      : `Live statistics since ${fmtTime(snap?.sessionStart ?? Date.now())}`;
    $('#scopeClr', el)?.addEventListener('click', () => onSelectRange(null));
    $('#zoomSel', root).hidden = $('#clrSel', root).hidden = !sel;
  }

  function cell(h, c, ctx) {
    switch (c.k) {
      case 'hop': return `<td>${h.hop}${h.hop === snap.destHop ? ' <span title="Destination" class="mute">●</span>' : ''}</td>`;
      case 'host': {
        if (!h.address) return '<td class="l mute">no response</td>';
        const flag = h.routeChanged ? ` <span class="warn" title="Answered by several addresses:\n${esc(h.addresses.join('\n'))}">⚠ ${h.addresses.length} paths</span>` : '';
        const det = h.detail && h.hop === snap.destHop ? ` <span class="mute" title="${esc(h.detail)}">(${esc(h.detail.split(' (')[0])})</span>` : '';
        return `<td class="l"><div class="hostcell">${h.name ? `<span>${esc(h.name)}</span><span class="ip mono">${esc(h.address)}</span>` : `<span class="mono">${esc(h.address)}</span>`}${flag}${det}</div></td>`;
      }
      case 'asn': return `<td class="l mute">${h.asn ? esc(h.asn.private ? 'Private network' : [h.asn.asn, h.asn.name, h.asn.country].filter(Boolean).join(' · ')) : ''}</td>`;
      case 'sent': return `<td>${h.sent}</td>`;
      case 'avg': return `<td><span class="lat ${latClass(h.avg)}">${fmtMs(h.avg)}</span></td>`;
      case 'min': return `<td>${fmtMs(h.min)}</td>`;
      case 'max': return `<td>${fmtMs(h.max)}</td>`;
      case 'last': return `<td>${fmtMs(h.last)}</td>`;
      case 'jitter': return `<td>${fmtMs(h.jitter)}</td>`;
      case 'loss': return `<td class="${lossClass(h.lossPct)}">${fmtPct(h.lossPct)}</td>`;
      case 'band': {
        if (h.avg == null) return '<td><span class="band"></span></td>';
        const l = h.min / ctx.max * 100, w = Math.max((h.max - h.min) / ctx.max * 100, .8), a = h.avg / ctx.max * 100;
        return `<td><span class="band" title="min ${fmtMs(h.min)} · avg ${fmtMs(h.avg)} · max ${fmtMs(h.max)} ms"><i style="left:${l}%;width:${w}%"></i><u style="left:${a}%"></u></span></td>`;
      }
      case 'spark': return `<td><canvas data-spark="${h.hop}" style="width:110px;height:22px"></canvas></td>`;
      default: {
        const v = h.custom?.[c.k.slice(2)];
        const cls = c.k === 'c:mos' ? mosClass(v) : '';
        return `<td class="${cls}">${v == null ? '–' : typeof v === 'number' ? v.toFixed(c.cc?.decimals ?? 2) : esc(v)}</td>`;
      }
    }
  }

  function renderTable() {
    const rows = rowsNow(), vc = visible();
    const liveByHop = new Map((snap?.hops || []).map(h => [h.hop, h]));
    const max = Math.max(20, ...rows.map(h => h.max || 0)) * 1.05;
    const ctx = { max };
    if (sel && selStats && rows.every(h => h.sent === 0)) {
      $('#tbl', root).innerHTML = `<div class="empty"><h2>No samples in this period</h2>Nothing was recorded between ${fmtTime(sel.from)} and ${fmtTime(sel.to)}. Drag over a period that has data, or <button class="sm" id="emptyClr">go back to live</button>.</div>`;
      $('#emptyClr', root).onclick = () => onSelectRange(null);
      return;
    }
    const head = `<thead><tr>${vc.map(c => `<th class="${c.cls || ''} k-${colClass(c)}">${esc(c.label)}</th>`).join('')}<th></th></tr></thead>`;
    const body = rows.map(h => `<tr data-hop="${h.hop}" tabindex="0" class="${h.hop === selHop ? 'sel' : ''} ${h.address ? '' : 'noresp'}">${vc.map(c => cell(h, c, ctx)).join('')}<td><button class="ghost sm rowmenu" data-menu="${h.hop}" aria-label="Hop ${h.hop} actions">⋯</button></td></tr>`).join('');
    $('#tbl', root).innerHTML = `<table>${head}<tbody>${body || `<tr><td colspan="${vc.length + 1}" class="empty">Waiting for the first trace to complete…</td></tr>`}</tbody></table>`;
    // Column classes let the stylesheet drop the less important columns on a phone.
    $$('#tbl tbody tr[data-hop]', root).forEach(tr => vc.forEach((c, i) => tr.children[i]?.classList.add('k-' + colClass(c))));
    const sparkMax = Math.max(10, ...(snap?.hops || []).flatMap(h => h.series.filter(v => v != null))) * 1.1;
    $$('canvas[data-spark]', root).forEach(c => { const h = liveByHop.get(+c.dataset.spark); if (h) drawSpark(c, h.series.slice(-60), { max: sparkMax }); });
  }

  function renderWindow() {
    const host = $('#win', root);
    const frozen = view.mode === 'frozen';
    host.innerHTML = (frozen ? `<button data-live="1" class="on">● Live</button>` : '') + WINDOWS.map(([l, ms]) => `<button data-ms="${ms}" class="${!frozen && view.ms === ms ? 'on' : ''}">${l}</button>`).join('');
    host.onclick = e => {
      const b = e.target.closest('button'); if (!b) return;
      view = { mode: 'live', ms: b.dataset.ms ? +b.dataset.ms : (view.lastMs || 5 * 60e3) };
      lsSet('view', view); renderWindow(); loadTimeline();
    };
  }

  const renderAll = throttle(() => {
    if (dead || !snap) return;
    renderHead(); renderNotices(); renderStrip(); renderScope(); renderTable(); updateTitle();
  }, 250);

  function updateTitle() {
    const h = (snap.hops || []).find(x => x.hop === selHop);
    $('#tlTitle', root).textContent = h ? `Hop ${selHop} — ${h.name || h.address || 'no response'}${h.hop === snap.destHop ? ' (destination)' : ''}` : 'Timeline';
  }

  // ------------------------------------------------------------------ timeline & selection
  async function loadTimeline() {
    if (dead || !snap || selHop == null) return;
    tlAbort?.abort(); tlAbort = new AbortController();
    const { from, to } = range();
    const buckets = Math.max(60, Math.min(600, Math.floor($('canvas.main', root).clientWidth / 4)));
    try {
      const d = await get(`/targets/${id}/timeline?from=${from}&to=${to}&hop=${selHop}&buckets=${buckets}`, { signal: tlAbort.signal });
      if (!dead) { tl.setData(d); tl.setSelection(sel); }
    } catch (e) { if (e.name !== 'AbortError' && !dead) console.warn('timeline', e); }
  }
  const loadTimelineSoon = throttle(() => loadTimeline(), 1000);

  async function onSelectRange(s) {
    sel = s; selStats = null; tl.setSelection(sel); renderScope();
    if (sel) {
      try { selStats = await get(`/targets/${id}/stats?from=${sel.from}&to=${sel.to}`); } catch (e) { toast(e.message, 'warn'); sel = null; }
    }
    renderTable(); renderStrip(); renderScope(); tl.setSelection(sel); loadDiag();
  }
  $('#clrSel', root).onclick = () => onSelectRange(null);
  $('#zoomSel', root).onclick = () => {
    if (!sel) return;
    const pad = Math.max(1000, (sel.to - sel.from) * 0.05);
    view = { mode: 'frozen', from: sel.from - pad, to: sel.to + pad, lastMs: view.ms || view.lastMs };
    renderWindow(); loadTimeline();
  };

  $('#addComment', root).onclick = async () => {
    const t = sel ? sel.from : now();
    const r = await openDialog(`<div class="hd"><h2>Add comment</h2></div><div class="bd">
      <p class="mute">Marks ${fmtTime(t, true)} on the timeline of <b>${esc(snap.displayName)}</b>.</p>
      <label class="f">Comment<textarea name="text" rows="3" maxlength="2000" required autofocus></textarea></label></div>
      <div class="ft"><button value="cancel" formnovalidate>Cancel</button><button class="primary" value="ok">Add</button></div>`,
      { onSubmit: async fd => post(`/targets/${id}/comments`, { text: fd.get('text'), t }) });
    if (r) { loadTimeline(); if (tab === 'comments') loadTab(); }
  };

  // ------------------------------------------------------------------ diagnosis (is the problem on my side?)
  async function loadDiag() {
    if (dead) return;
    try {
      const q = sel ? `from=${sel.from}&to=${sel.to}` : 'window=300';
      const d = await get(`/targets/${id}/diagnosis?${q}`);
      if (dead) return;
      $('#diag', root).innerHTML = verdictCard(d, { title: sel ? `Diagnosis for the selected period (${fmtTime(sel.from)} – ${fmtTime(sel.to)})` : 'Diagnosis — last 5 minutes' })
        + `<div class="panel" style="margin-top:10px;padding:10px 14px">${pathStrip(d)}</div>`;
    } catch { /* the target may have been removed */ }
  }

  // ------------------------------------------------------------------ bottom tabs
  async function loadTab() {
    if (dead) return;
    $$('#tabs button', root).forEach(b => b.classList.toggle('on', b.dataset.tab === tab));
    const host = $('#tabbody', root);
    try {
      if (tab === 'events') {
        const ev = await get(`/events?tid=${id}&limit=100`);
        host.innerHTML = ev.length ? `<div class="list">${ev.map(e => `<div class="item"><span class="sev ${e.severity}"></span><span class="t">${fmtTime(e.t, true)}</span><span class="grow">${esc(e.message)}</span><span class="badge plain">${esc(e.type)}</span></div>`).join('')}</div>` : '<div class="empty">No events yet. Alerts, route changes and errors for this target appear here.</div>';
      } else if (tab === 'routes') {
        const from = now() - 7 * 86400e3, paths = await get(`/targets/${id}/routes?from=${from}&to=${now()}`);
        if (!paths.length) { host.innerHTML = '<div class="empty">No route recorded yet.</div>'; return; }
        const items = paths.map((p, i) => {
          const prev = paths[i - 1];
          const chips = p.hops.filter(h => h.addr || (prev && prev.hops[h.hop - 1]?.addr)).map(h => {
            const was = prev?.hops[h.hop - 1]?.addr; const diff = prev && was !== h.addr;
            return `<span class="${diff ? 'diff' : ''}" title="${diff ? 'was ' + esc(was || 'none') : ''}">${h.hop}: ${esc(h.name || h.addr || '–')}</span>`;
          }).join('');
          return `<div class="item"><span class="t">${fmtTime(p.t, true)}</span><div class="path grow">${chips}</div>${!prev ? '<span class="badge plain">first seen</span>' : ''}</div>`;
        }).reverse();
        host.innerHTML = `<div class="list">${items.join('')}</div><div class="mute" style="padding:8px 14px">Highlighted hops differ from the previous recorded path (last 7 days). Per-flow load balancing can make this change between probes.</div>`;
      } else if (tab === 'comments') {
        const from = now() - 30 * 86400e3, cs = await get(`/targets/${id}/comments?from=${from}&to=${now() + 60e3}`);
        host.innerHTML = cs.length ? `<div class="list">${cs.slice().reverse().map(c => `<div class="item"><span class="t">${fmtTime(c.t, true)}</span><span class="grow">${esc(c.text)}</span><button class="ghost sm" data-del="${c.id}" aria-label="Delete comment">✕</button></div>`).join('')}</div>` : '<div class="empty">No comments. Use “+ Comment” to mark something on the timeline.</div>';
        host.onclick = async e => { const b = e.target.closest('[data-del]'); if (b) { await del(`/targets/${id}/comments/${b.dataset.del}`); loadTab(); loadTimeline(); } };
      } else {
        const c = snap.config, kv = (k, v) => `<tr><td class="l mute">${k}</td><td class="l">${v}</td></tr>`;
        host.innerHTML = `<div class="bd"><table style="max-width:640px"><tbody>
          ${kv('Host', esc(c.host))}${kv('Resolved address', esc(snap.address || '–'))}${kv('Source address', esc(snap.source || 'automatic'))}
          ${kv('Method', esc(c.method.toUpperCase()) + (c.method !== 'icmp' ? ` · port ${c.port || (c.method === 'udp' ? 33434 : 80)}` : ''))}
          ${kv('Trace interval', c.intervalMs + ' ms')}${kv('Timeout', c.timeoutMs + ' ms')}${kv('Hops', `${c.startHop} – ${c.maxHops}`)}
          ${kv('Packet size', c.packetSize + ' bytes')}${kv('Inter-hop delay', c.interHopDelayMs + ' ms')}${kv('TOS', c.tos)}
          ${kv('Remote agent', c.agentUrl ? esc(c.agentUrl) : 'none')}${kv('Session started', fmtTime(snap.sessionStart, true))}${kv('Traces this run', snap.round)}
          </tbody></table></div>`;
      }
    } catch (e) { host.innerHTML = `<div class="empty bad">${esc(e.message)}</div>`; }
  }
  $('#tabs', root).onclick = e => { const b = e.target.closest('button'); if (b) { tab = b.dataset.tab; lsSet('tab', tab); loadTab(); } };

  // ------------------------------------------------------------------ table interactions
  const tbl = $('#tbl', root);
  tbl.addEventListener('click', e => {
    const m = e.target.closest('[data-menu]');
    if (m) { e.stopPropagation(); hopMenu(m, +m.dataset.menu); return; }
    const tr = e.target.closest('tr[data-hop]');
    if (tr) selectHop(+tr.dataset.hop);
  });
  tbl.addEventListener('keydown', e => {
    const tr = e.target.closest('tr[data-hop]'); if (!tr) return;
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectHop(+tr.dataset.hop); }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); const n = e.key === 'ArrowDown' ? tr.nextElementSibling : tr.previousElementSibling; n?.focus(); }
  });
  function selectHop(h) { selHop = h; renderTable(); updateTitle(); loadTimeline(); }

  function hopMenu(anchor, hop) {
    const h = (snap.hops || []).find(x => x.hop === hop); if (!h) return;
    const ip = h.address;
    menu(anchor, [
      { label: `Show hop ${hop} timeline`, fn: () => selectHop(hop) },
      { sep: true },
      { label: 'Copy IP address', disabled: !ip, fn: () => copyText(ip) },
      { label: 'Copy host name', disabled: !h.name, fn: () => copyText(h.name) },
      { label: 'Look up AS / owner (Team Cymru)…', disabled: !ip, fn: () => lookupAsn(ip) },
      { label: 'Set a custom name…', disabled: !ip, fn: () => setAlias(ip, h.name) },
      { sep: true },
      { label: 'Trace this hop as a target', disabled: !ip, fn: async () => { const r = await post('/targets', { host: ip, method: 'icmp' }); toast('Tracing ' + ip); location.hash = '#/t/' + r.id; } },
      { label: 'Create alert for this hop…', fn: () => alertDialog(null, { scope: 'hop', hop, targetId: id, name: `${snap.displayName} hop ${hop}` }) },
    ]);
  }
  async function lookupAsn(ip) {
    if (!confirm(`Send ${ip} to Team Cymru's whois service to look up the AS owner?`)) return;
    try { const r = await get('/asn?ip=' + encodeURIComponent(ip)); toast(r.private ? `${ip}: private network` : `${ip}: ${r.asn ?? '?'} · ${r.name ?? ''} · ${r.country ?? ''} · ${r.prefix ?? ''}`, 'info', 12000); }
    catch (e) { toast(e.message, 'warn'); }
  }
  async function setAlias(ip, cur) {
    const name = prompt(`Name for ${ip} (empty removes it):`, cur || '');
    if (name === null) return;
    const s = await get('/settings');
    if (name.trim()) s.aliases[ip] = name.trim(); else delete s.aliases[ip];
    store.settings = await put('/settings', s);
    renderAll();
  }

  $('#colsBtn', root).onclick = e => {
    const all = allCols().filter(c => !c.always);
    popover(e.currentTarget, all.map(c => `<label><input type="checkbox" data-k="${c.k}" ${visible().some(v => v.k === c.k) ? 'checked' : ''}> ${esc(c.label)}</label>`).join(''), m => {
      m.onchange = ev => {
        const k = ev.target.dataset.k, on = ev.target.checked;
        cols = cols.filter(x => x !== k && x !== '-' + k);
        if (k.startsWith('c:')) { if (!on) cols.push('-' + k); } else if (on) cols.push(k);
        lsSet('cols', cols); renderTable();
      };
    });
  };

  // ------------------------------------------------------------------ live feed
  function connect() {
    es = new EventSource(`/api/targets/${id}/stream`);
    es.onmessage = ev => {
      snap = JSON.parse(ev.data);
      if (selHop == null || !snap.hops.some(h => h.hop === selHop)) {
        const d = destRow(snap.hops); selHop = d ? d.hop : snap.hops[0]?.hop ?? null;
        if (selHop != null) loadTimeline();
      }
      renderAll();
      if (!sel && view.mode === 'live') loadTimelineSoon();
    };
    es.onerror = async () => {
      try { await get('/targets/' + id); } catch (e) { if (/not found/i.test(e.message) || /404/.test(e.message)) { location.hash = '#/'; } }
    };
  }

  renderWindow(); loadTab(); loadDiag();
  const diagTimer = setInterval(() => { if (!document.hidden) loadDiag(); }, 5000);
  connect();
  tlTimer = setInterval(() => { if (!document.hidden && !sel && view.mode === 'live') loadTimeline(); }, 4000);
  tabTimer = setInterval(() => { if (!document.hidden && tab !== 'comments') loadTab(); }, 10000);
  const onEv = e => { if (e.detail?.event?.tid === id) { loadTab(); loadTimelineSoon(); } };
  document.addEventListener('tm-event', onEv);
  const onSettings = () => renderAll();
  document.addEventListener('tm-settings', onSettings);

  return {
    destroy() {
      dead = true; es?.close(); clearInterval(tlTimer); clearInterval(tabTimer); clearInterval(diagTimer); tlAbort?.abort(); tl?.destroy();
      document.removeEventListener('tm-event', onEv); document.removeEventListener('tm-settings', onSettings);
      document.title = 'TraceMe';
    },
  };
}

import { get, post, put, del } from './api.js';
import { $, $$, esc, fmtTime, fmtMs, fmtPct, fmtDuration, store, toast, menu, copyText, lsGet, lsSet, latClass, lossClass, mosClass, setHtml } from './util.js';
import { verdictCard, pathStrip, sideChip, headline } from './diagnosis.js';
import { appRuleDialog, elevate } from './forms.js';
import { drawSpark } from './graphs.js';

/** bytes/s -> human bit rate */
const rate = v => v == null ? '–' : v * 8 >= 1e6 ? (v * 8 / 1e6).toFixed(1) + ' Mbps' : v * 8 >= 1e3 ? (v * 8 / 1e3).toFixed(0) + ' kbps' : Math.round(v * 8) + ' bps';
const bytes = v => v == null ? '–' : v >= 1e9 ? (v / 1e9).toFixed(2) + ' GB' : v >= 1e6 ? (v / 1e6).toFixed(1) + ' MB' : v >= 1e3 ? (v / 1e3).toFixed(0) + ' KB' : v + ' B';
const ago = t => { const s = Math.max(0, Math.round((Date.now() - t) / 1000)); return s < 5 ? 'now' : s < 90 ? s + ' s ago' : Math.round(s / 60) + ' min ago'; };
const ROLE = { game: ['Game server', 'game'], udp: ['UDP traffic', ''], service: ['Web / service', ''], tcp: ['TCP', ''], local: ['Local network', ''], other: ['Other', ''] };
const modalOpen = () => $('#dlg').open || !$('#menu').hidden;

function captureBanner(c) {
  if (!c) return '';
  if (c.live) return '';
  const why = c.elevated ? esc(c.error || 'Live capture is not running.') : 'UDP game traffic can only be seen when TraceMe runs as administrator (Windows restricts the kernel network trace).';
  return `<div class="banner" style="margin:0 0 14px"><span class="grow"><b>Limited mode:</b> ${why} Only established TCP connections are listed, so most online games will not appear.</span>${c.elevated ? '' : '<button id="capElev">Restart as administrator</button>'}</div>`;
}

// =========================================================================================================== list
function mountList(root) {
  let data = null, dead = false, timer = null, games = [];
  let f = lsGet('appsFilter', { q: '', games: false, all: false });

  root.innerHTML = `
    <div class="row pagehead" style="margin-bottom:12px">
      <div class="grow"><h2>Apps</h2><div class="mute">See which servers an application talks to, trace them automatically and find out whether a problem is on your side.</div></div>
      <input id="q" type="search" placeholder="Filter apps…" style="width:180px" aria-label="Filter apps" value="${esc(f.q)}">
      <label class="ck"><input type="checkbox" id="fg" ${f.games ? 'checked' : ''}> Games only</label>
      <label class="ck" title="Include every running program, even without network traffic"><input type="checkbox" id="fa" ${f.all ? 'checked' : ''}> All running</label>
      <button class="primary" id="watch">+ Watch an app</button>
    </div>
    <div id="cap"></div><div id="body"></div>`;

  const save = () => lsSet('appsFilter', f);
  $('#q', root).oninput = e => { f.q = e.target.value; save(); render(); };
  $('#fg', root).onchange = e => { f.games = e.target.checked; save(); render(); };
  $('#fa', root).onchange = e => { f.all = e.target.checked; save(); load(); };
  $('#watch', root).onclick = async () => { if (await appRuleDialog()) load(); };

  async function load() {
    try { data = await get('/apps' + (f.all ? '?all=true' : '')); } catch (e) { if (!dead) $('#body', root).innerHTML = `<div class="empty bad">${esc(e.message)}</div>`; return; }
    if (!dead) render();
  }

  function render() {
    if (!data || dead) return;
    $('#cap', root).innerHTML = captureBanner(data.capture);
    $('#capElev', root)?.addEventListener('click', elevate);
    const q = f.q.trim().toLowerCase();
    let apps = data.apps.filter(a => (!f.games || a.isGame) && (!q || a.key.includes(q) || (a.friendly || '').toLowerCase().includes(q)));
    apps = apps.filter(a => f.all || a.endpoints > 0 || a.rule || a.running);
    apps.sort((a, b) => (!!b.session - !!a.session) || (b.gameEndpoints - a.gameEndpoints) || ((b.bpsIn + b.bpsOut) - (a.bpsIn + a.bpsOut)) || a.key.localeCompare(b.key));
    const body = $('#body', root);
    if (!apps.length) {
      body.innerHTML = `<div class="panel empty"><h2>${data.capture.live ? 'No application is using the network right now' : 'No applications to show'}</h2>
        <p>Start your game, or choose one to watch — TraceMe will begin tracing its servers as soon as it connects.</p>
        <div class="row" style="justify-content:center">${popular().map(g => `<button class="sm" data-quick="${esc(g.exe)}">${esc(g.name)}</button>`).join('')}</div></div>`;
      loadGames();
      return;
    }
    setHtml(body, `<div class="panel flush"><table><thead><tr><th class="l">Application</th><th class="l hm">Status</th><th class="hm">Traffic</th><th class="l hm">Servers</th><th class="l">Auto-trace</th><th class="l hm">Verdict</th><th class="hm"></th></tr></thead><tbody>${apps.map(row).join('')}</tbody></table></div>`);
  }

  function popular() { return (games.length ? games : [{ exe: 'cod.exe', name: 'Call of Duty' }, { exe: 'fortniteclient-win64-shipping.exe', name: 'Fortnite' }, { exe: 'valorant-win64-shipping.exe', name: 'VALORANT' }, { exe: 'cs2.exe', name: 'Counter-Strike 2' }, { exe: 'r5apex.exe', name: 'Apex Legends' }, { exe: 'dota2.exe', name: 'Dota 2' }]).slice(0, 8); }
  async function loadGames() { if (games.length) return; try { games = await get('/apps/games'); if (!dead && !data?.apps.length) render(); } catch { /* optional */ } }

  function row(a) {
    const v = a.verdict;
    return `<tr data-key="${esc(a.key)}" tabindex="0">
      <td class="l"><div class="appcell">${appIcon(a.key, a.friendly || a.name)}<div><b>${esc(a.friendly || a.name)}</b> ${a.friendly ? `<span class="mute mono">${esc(a.name)}</span>` : ''} ${a.isGame ? '<span class="chip game">GAME</span>' : ''}<div class="mob mute">${a.running ? '<span class="dot good"></span> running' : 'not running'}${a.session ? ' · session live' : ''} · ↓ ${rate(a.bpsIn)} ↑ ${rate(a.bpsOut)}<br>${a.publicEndpoints} public${a.gameEndpoints ? ` · <b>${a.gameEndpoints} likely game server${a.gameEndpoints > 1 ? 's' : ''}</b>` : ''}${a.tracedServers ? ` · ${a.tracedServers} traced` : ''}</div>${v ? `<div class="mob">${sideChip(v)} <span class="mute">${esc(v.headline)}</span></div>` : ''}</div></div></td>
      <td class="l hm">${a.running ? '<span class="dot good"></span> running' : '<span class="mute">not running</span>'}${a.session ? ' · <span class="chip warn">session live</span>' : ''}</td>
      <td class="nowrap hm">↓ ${rate(a.bpsIn)}<br><span class="mute">↑ ${rate(a.bpsOut)}</span></td>
      <td class="l hm">${a.publicEndpoints} public${a.gameEndpoints ? ` · <b>${a.gameEndpoints} likely game server${a.gameEndpoints > 1 ? 's' : ''}</b>` : ''}${a.tracedServers ? `<div class="mute">${a.tracedServers} traced</div>` : ''}</td>
      <td class="l"><label class="switch" title="Trace this app's servers automatically whenever it runs"><input type="checkbox" data-watch ${a.rule?.enabled ? 'checked' : ''}> ${a.rule?.enabled ? 'On' : 'Off'}</label></td>
      <td class="l hm">${v ? `${sideChip(v)}<div class="mute" style="font-size:12px;max-width:340px;white-space:normal">${esc(v.headline)}</div>` : '<span class="mute">–</span>'}</td>
      <td class="hm"><a href="#/apps/${encodeURIComponent(a.key)}">Open →</a></td></tr>`;
  }

  root.addEventListener('click', async e => {
    const q = e.target.closest('[data-quick]');
    if (q) { try { await post(`/apps/${encodeURIComponent(q.dataset.quick)}/watch`, { enabled: true }); toast('Watching ' + q.dataset.quick + ' — start the game and TraceMe does the rest.', 'info'); location.hash = '#/apps/' + encodeURIComponent(q.dataset.quick); } catch (err) { toast(err.message, 'warn'); } return; }
    const w = e.target.closest('[data-watch]');
    if (w) {
      e.stopPropagation();
      const key = w.closest('tr').dataset.key;
      try { await post(`/apps/${encodeURIComponent(key)}/watch`, { enabled: w.checked }); toast(w.checked ? `Watching ${key}` : `Stopped watching ${key}`, 'info', 2500); } catch (err) { toast(err.message, 'warn'); }
      load(); return;
    }
    if (e.target.closest('a')) return;
    const tr = e.target.closest('tr[data-key]'); if (tr) location.hash = '#/apps/' + encodeURIComponent(tr.dataset.key);
  });
  root.addEventListener('keydown', e => { if (e.key === 'Enter' && e.target.matches('tr[data-key]')) location.hash = '#/apps/' + encodeURIComponent(e.target.dataset.key); });

  load();
  timer = setInterval(() => { if (!document.hidden && !modalOpen()) load(); }, 2000);
  return { destroy() { dead = true; clearInterval(timer); } };
}

// ========================================================================================================= icons
// The program's own icon, from /api/apps/{key}/icon; a coloured letter stays underneath when none can be read.
const noIcon = new Map();
document.addEventListener('error', e => {
  const img = e.target;
  if (img instanceof HTMLImageElement && img.dataset.aico) { noIcon.set(img.dataset.aico, Date.now()); img.remove(); }
}, true);
function appIcon(key, label, large = false) {
  const letter = (String(label || key).match(/[a-z0-9]/i) || ['?'])[0].toUpperCase();
  let h = 0; for (const c of key) h = (h * 31 + c.charCodeAt(0)) % 360;
  const failed = noIcon.get(key) && Date.now() - noIcon.get(key) < 30000;
  return `<span class="aico${large ? ' lg' : ''}" style="--accent:hsl(${h} 55% 45%);--accent-soft:hsl(${h} 55% 45% / .16)" aria-hidden="true">${letter}${failed ? '' : `<img data-aico="${esc(key)}" src="/api/apps/${encodeURIComponent(key)}/icon" alt="" width="${large ? 48 : 32}" height="${large ? 48 : 32}" loading="lazy">`}</span>`;
}

// ========================================================================================================= detail
function mountDetail(root, key) {
  let d = null, dead = false, timer = null, sel = null, epf = lsGet('epFilter', { pub: true, active: true });
  const K = encodeURIComponent(key);

  root.innerHTML = `<div class="row" style="margin-bottom:10px" id="head"></div><div id="cap"></div>
    <div id="hero"></div>
    <div class="panel" style="margin-top:14px"><div class="hd"><h3>Servers being traced</h3><span class="mute grow" id="srvhint"></span></div><div id="servers"></div></div>
    <div class="panel flush" style="margin-top:14px"><div class="hd"><h3>Connections</h3><span class="mute grow">Remote endpoints this application talks to, best server candidates first</span>
      <label class="ck"><input type="checkbox" id="fpub" ${epf.pub ? 'checked' : ''}> Public only</label><label class="ck"><input type="checkbox" id="fact" ${epf.active ? 'checked' : ''}> Active now</label></div>
      <div class="bd" id="eps"></div></div>
    <div class="panel flush" style="margin-top:14px"><div class="hd"><h3>Sessions</h3><span class="mute grow">Every time the game runs while watched, TraceMe records a session and a report</span></div><div id="sessions"></div></div>`;

  async function load() {
    try { d = await get('/apps/' + K); } catch (e) {
      if (!dead) { if (/not found/i.test(e.message)) root.innerHTML = `<div class="panel empty"><h2>${esc(key)} is not known yet</h2><p>Start the application so it shows up, or watch it now.</p><p><button class="primary" id="wnow">Watch ${esc(key)}</button> <a href="#/apps">Back to apps</a></p></div>`, $('#wnow', root).onclick = async () => { await post(`/apps/${K}/watch`, { enabled: true }); location.reload(); }; else toast(e.message, 'warn'); }
      return;
    }
    if (!dead) render();
  }

  function worst() {
    const rank = s => ({ bad: 3, warn: 2, ok: 1 }[s.diagnosis.status] || 0);
    return [...d.servers].sort((a, b) => rank(b) - rank(a) || (b.diagnosis.destLoss || 0) - (a.diagnosis.destLoss || 0))[0];
  }
  const current = () => d.servers.find(s => s.target.id === sel) || worst();

  function render() {
    const title = d.friendly || d.name;
    const headHtml = `<a href="#/apps" class="ghost" style="padding:4px 8px" aria-label="Back to apps">←</a>
      ${appIcon(d.key, title, true)}
      <div class="grow"><h2 style="font-size:19px">${esc(title)} ${d.isGame ? '<span class="chip game">GAME</span>' : ''} ${d.running ? '<span class="chip good">running</span>' : '<span class="chip">not running</span>'}</h2>
        <div class="mute mono">${esc(d.name)}${d.pids.length ? ' · PID ' + d.pids.slice(0, 4).join(', ') : ''}${d.path ? ' · ' + esc(d.path) : ''}</div></div>
      <label class="switch" title="Trace this app's servers automatically whenever it runs"><input type="checkbox" id="wsw" ${d.rule?.enabled ? 'checked' : ''}> Auto-trace</label>
      <button id="opts">Options…</button>
      ${d.session ? '<button id="endS" class="primary">End session &amp; report</button>' : ''}`;
    // Sections are only rewritten when their markup changed, so open <details> and focus survive the 1.5 s refresh.
    if (setHtml($('#head', root), headHtml)) {
      $('#wsw', root).onchange = async e => { try { await post(`/apps/${K}/watch`, { enabled: e.target.checked }); load(); } catch (err) { toast(err.message, 'warn'); } };
      $('#opts', root).onclick = async () => { if (await appRuleDialog(d.rule, d.rule ? {} : { processName: d.name, label: d.friendly || '' })) load(); };
      $('#endS', root)?.addEventListener('click', async () => {
        try { const s = await post(`/apps/${K}/session/stop`); toast('Session ended', 'info'); window.open(`/api/apps/sessions/${s.id}/report`, '_blank'); load(); } catch (err) { toast(err.message, 'warn'); }
      });
    }
    if (setHtml($('#cap', root), captureBanner(d.capture))) $('#capElev', root)?.addEventListener('click', elevate);

    const cur = d.servers.length ? current() : null;
    if (cur) sel = cur.target.id;
    const heroHtml = cur
      ? `${verdictCard(cur.diagnosis, { title: `${cur.target.host} — ${d.session ? 'live session' : 'last 5 minutes'}` })}<div class="panel" style="margin-top:12px;padding:12px 14px">${pathStrip(cur.diagnosis)}</div>`
      : `<div class="panel verdict"><div class="ico">…</div><div class="grow"><h2>${d.running ? 'Looking for the game server…' : 'Waiting for the application to start'}</h2>
         <div class="mute">${d.rule?.enabled ? 'Auto-trace is on: as soon as ' + esc(title) + ' exchanges game traffic with a server, TraceMe traces it and tells you where any problem is.' : 'Turn on Auto-trace, or trace one of the connections below by hand.'}</div>
         ${d.endpoints.some(e => e.role === 'game') ? '<p><button class="primary" id="traceTop">Trace the likely game server now</button></p>' : ''}</div></div>`;
    if (setHtml($('#hero', root), heroHtml)) $('#traceTop', root)?.addEventListener('click', () => traceBest());

    $('#srvhint', root).textContent = d.servers.length ? 'Click a server to see its verdict above' : '';
    setHtml($('#servers', root), d.servers.length ? `<div class="srvcards">${d.servers.map(card).join('')}</div>` : '<div class="empty" style="padding:24px">No servers traced yet.</div>');
    for (const s of d.servers) { const c = $(`canvas[data-spark="${s.target.id}"]`, root); if (c) drawSpark(c, s.target.series || []); }
    renderEndpoints(); renderSessions();
  }

  function card(s) {
    const t = s.target, g = s.diagnosis;
    return `<div class="srv ${t.id === sel ? 'on' : ''}" data-srv="${t.id}">
      <div class="row"><b class="grow mono" style="overflow:hidden;text-overflow:ellipsis">${esc(t.host)}</b>${sideChip(g)}</div>
      <div class="mute" style="font-size:12px">${esc(t.method.toUpperCase())}${s.auto ? ' · auto' : ' · manual'}${t.status === 'paused' ? ' · paused' : ''}${t.destHop ? ' · ' + t.destHop + ' hops' : ''}</div>
      <div class="metrics" style="margin:6px 0"><div class="metric"><b class="${latClass(t.avg)}">${fmtMs(t.avg)}</b><span>avg ms</span></div><div class="metric"><b>${fmtMs(t.jitter)}</b><span>jitter</span></div>
        <div class="metric"><b class="${lossClass(t.lossPct)}">${fmtPct(t.lossPct)}</b><span>loss</span></div><div class="metric"><b class="${mosClass(t.mos)}">${t.mos ?? '–'}</b><span>MOS</span></div></div>
      <canvas data-spark="${t.id}" style="width:100%;height:30px;display:block"></canvas>
      <div class="row" style="margin-top:6px"><a href="#/t/${t.id}">Open trace →</a><span class="spacer"></span>
        <button class="ghost sm" data-pause="${t.id}" data-paused="${t.status === 'paused' || t.status === 'stopped'}">${t.status === 'paused' || t.status === 'stopped' ? '▶ Resume' : '❚❚ Pause'}</button>
        <button class="ghost sm" data-rm="${t.id}" aria-label="Remove trace">✕</button></div></div>`;
  }

  function renderEndpoints() {
    let eps = d.endpoints.filter(e => (!epf.pub || e.kind === 'public') && (!epf.active || e.active));
    const host = $('#eps', root);
    if (!eps.length) { setHtml(host, `<div class="empty" style="padding:30px">${d.running ? 'No matching connections right now.' : 'The application is not running.'}</div>`); return; }
    host.style.padding = '0';
    setHtml(host, `<div style="overflow-x:auto"><table><thead><tr><th class="l">Remote</th><th class="l">Role</th><th class="l">Ports</th><th>↓ In</th><th>↑ Out</th><th>Packets/s</th><th>Total</th><th>Seen</th><th></th></tr></thead><tbody>${eps.map(e => {
      const [rl, rc] = ROLE[e.role] || ROLE.other;
      const ports = e.ports.map(p => `${p.proto} ${p.port}`).slice(0, 3).join(', ');
      return `<tr data-ip="${esc(e.ip)}" class="${e.active ? '' : 'dim'}"><td class="l"><div class="hostcell"><span class="mono">${esc(e.ip)}</span>${e.host ? `<span class="ip">${esc(e.host)}</span>` : ''}</div>${e.asn && !e.asn.private ? `<div class="mute" style="font-size:12px">${esc([e.asn.asn, e.asn.name, e.asn.country].filter(Boolean).join(' · '))}</div>` : ''}</td>
        <td class="l"><span class="chip ${rc}">${esc(rl)}</span></td><td class="l mono">${esc(ports)}</td>
        <td>${e.countersAvailable ? rate(e.bpsIn) : '–'}</td><td>${e.countersAvailable ? rate(e.bpsOut) : '–'}</td><td>${e.countersAvailable ? (e.ppsIn + e.ppsOut).toFixed(1) : '–'}</td>
        <td class="mute">${e.countersAvailable ? bytes(e.bytesIn + e.bytesOut) : '–'}</td><td class="mute">${ago(e.last)}</td>
        <td class="nowrap">${e.targetId ? `<a href="#/t/${e.targetId}">Tracing →</a>` : e.kind === 'public' ? `<button class="sm" data-trace="${esc(e.ip)}">Trace ▾</button>` : ''}
          <button class="ghost sm" data-copy="${esc(e.ip)}" aria-label="Copy IP">⧉</button></td></tr>`;
    }).join('')}</tbody></table></div>`);
  }

  function renderSessions() {
    const host = $('#sessions', root);
    if (!d.sessions.length) { setHtml(host, '<div class="empty" style="padding:24px">No sessions yet. They are recorded automatically while Auto-trace is on.</div>'); return; }
    setHtml(host, `<div class="list">${d.sessions.map(s => {
      const sm = s.summary, live = s.status === 'running';
      return `<div class="item"><span class="t">${fmtTime(s.started, true)}</span><div class="grow"><div>${live ? '<span class="chip warn">live</span> ' : sm ? sideChip(sm) + ' ' : ''}${esc(sm?.headline || (live ? 'Session in progress…' : s.status === 'interrupted' ? 'Interrupted (TraceMe was restarted)' : 'No verdict'))}</div>
        <div class="mute" style="font-size:12px">${s.ended ? fmtDuration(s.ended - s.started) : 'running'} · ${s.servers} server${s.servers === 1 ? '' : 's'}${sm?.servers?.length ? ' · ' + sm.servers.map(v => `${esc(v.ip)}: ${fmtMs(v.avg)} ms, ${fmtPct(v.lossPct)} loss`).join(' · ') : ''}</div></div>
        <a href="/api/apps/sessions/${s.id}/report" target="_blank" rel="noopener"><button class="sm">Report</button></a><button class="sm danger" data-delsess="${s.id}">Delete</button></div>`;
    }).join('')}</div>`);
  }

  async function trace(ip, method, port) {
    try { const t = await post(`/apps/${K}/trace`, { ip, method, port }); toast(`Tracing ${ip} (${method.toUpperCase()})`, 'info'); sel = t.id; load(); } catch (e) { toast(e.message, 'warn'); }
  }
  function traceBest() {
    const best = d.endpoints.filter(e => e.kind === 'public').sort((a, b) => b.score - a.score)[0];
    if (best) trace(best.ip, 'icmp', 0);
  }

  root.addEventListener('click', async e => {
    const srv = e.target.closest('[data-srv]');
    const act = e.target.closest('[data-pause],[data-rm],[data-trace],[data-copy],[data-delsess]');
    if (!act && srv && !e.target.closest('a')) { sel = srv.dataset.srv; render(); return; }
    if (!act) return;
    if (act.dataset.pause) { await post(`/targets/${act.dataset.pause}/pause`, { paused: act.dataset.paused !== 'true' }); load(); }
    else if (act.dataset.rm) { if (confirm('Remove this trace and its history?')) { await del('/targets/' + act.dataset.rm); load(); } }
    else if (act.dataset.copy) copyText(act.dataset.copy);
    else if (act.dataset.delsess) { if (confirm('Delete this session record?')) { await del('/apps/sessions/' + act.dataset.delsess); load(); } }
    else if (act.dataset.trace) {
      const ep = d.endpoints.find(x => x.ip === act.dataset.trace);
      menu(act, [
        { label: 'Trace with ICMP (ping path)', fn: () => trace(ep.ip, 'icmp', 0) },
        { label: ep.udpPort ? `Trace with UDP (port ${ep.udpPort})` : 'Trace with UDP (port 33434)', fn: () => trace(ep.ip, 'udp', ep.udpPort || 33434) },
        { label: ep.tcpPort ? `Trace with TCP (port ${ep.tcpPort})` : 'Trace with TCP (port 443)', fn: () => trace(ep.ip, 'tcp', ep.tcpPort || 443) },
      ]);
    }
  });
  $('#fpub', root).onchange = e => { epf.pub = e.target.checked; lsSet('epFilter', epf); renderEndpoints(); };
  $('#fact', root).onchange = e => { epf.active = e.target.checked; lsSet('epFilter', epf); renderEndpoints(); };

  load();
  timer = setInterval(() => { if (!document.hidden && !modalOpen()) load(); }, 1500);
  return { destroy() { dead = true; clearInterval(timer); } };
}

export function mount(root, key) { return key ? mountDetail(root, key) : mountList(root); }

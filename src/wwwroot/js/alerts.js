import { get, post, put, del } from './api.js';
import { $, esc, store, toast } from './util.js';
import { alertDialog } from './forms.js';

const METRIC = { avg: 'average latency', max: 'maximum latency', last: 'latest latency', jitter: 'jitter', loss: 'packet loss', noresponse: 'no response', mos: 'MOS', routechange: 'route change' };
const UNIT = { avg: ' ms', max: ' ms', last: ' ms', jitter: ' ms', loss: ' %' };

function describe(a) {
  const scope = a.scope === 'destination' ? 'destination' : a.scope === 'any' ? 'any hop' : `hop ${a.hop}`;
  const cond = a.metric === 'routechange' ? 'route changes'
    : a.metric === 'noresponse' ? `no response for ${a.samples} probes`
      : `${METRIC[a.metric]} ${a.op === '>' ? 'above' : 'below'} ${a.value}${UNIT[a.metric] || ''} (last ${a.samples}${a.consecutiveRounds > 1 ? `, ${a.consecutiveRounds} traces in a row` : ''})`;
  return `${scope}: ${cond}`;
}

export function mount(root) {
  let dead = false, rules = [];
  root.innerHTML = `<div class="row" style="margin-bottom:10px"><h2 class="grow">Alerts</h2><button class="primary" id="add">+ New alert</button></div>
    <div id="active"></div><div class="panel flush"><div id="list" class="list"></div></div>
    <p class="mute">Alerts are evaluated after every trace. Each rule keeps its own state per hop, so it notifies once when the condition begins and (optionally) once when it clears.</p>`;
  const tname = id => id ? (store.targets.find(t => t.id === id)?.displayName ?? id) : 'All targets';

  async function load() {
    const [r, t] = await Promise.all([get('/alerts'), get('/targets')]);
    rules = r; store.targets = t; render();
  }
  function render() {
    if (dead) return;
    const active = store.targets.filter(t => t.alerts?.length);
    $('#active', root).innerHTML = active.length ? `<div class="banner err" style="margin:0 0 12px"><span class="grow"><b>Active now:</b> ${active.map(t => `<a href="#/t/${t.id}">${esc(t.displayName)}</a> — ${t.alerts.map(a => esc(a.rule) + ' (hop ' + a.hop + ')').join(', ')}`).join(' · ')}</span></div>` : '';
    $('#list', root).innerHTML = rules.length ? rules.map(a => `
      <div class="item" data-id="${a.id}">
        <label class="ck" title="Enabled"><input type="checkbox" data-act="toggle" ${a.enabled ? 'checked' : ''}></label>
        <div class="grow"><b>${esc(a.name)}</b> <span class="badge plain">${esc(tname(a.targetId))}</span><div class="mute">${esc(describe(a))} → ${a.actions.map(x => esc(x.type)).join(', ') || 'log only'}</div></div>
        <button class="sm" data-act="test">Test</button><button class="sm" data-act="edit">Edit</button><button class="sm danger" data-act="del">Delete</button>
      </div>`).join('') : '<div class="empty"><h2>No alerts defined</h2><p>Get notified when latency, jitter or packet loss crosses a threshold, a hop stops answering, or the route changes.</p><button class="primary" id="add2">Create the first alert</button></div>';
    $('#add2', root)?.addEventListener('click', add);
  }
  async function add() {
    const r = await alertDialog(null, store.targets.length === 1 ? { targetId: store.targets[0].id } : {});
    if (r) load();
  }
  $('#add', root).onclick = add;
  root.addEventListener('click', async e => {
    const b = e.target.closest('[data-act]'); if (!b) return;
    const row = b.closest('[data-id]'); const a = rules.find(x => x.id === row?.dataset.id); if (!a) return;
    try {
      if (b.dataset.act === 'edit') { if (await alertDialog(a)) load(); }
      else if (b.dataset.act === 'del') { if (confirm(`Delete alert "${a.name}"?`)) { await del('/alerts/' + a.id); load(); } }
      else if (b.dataset.act === 'test') { await post(`/alerts/${a.id}/test`); toast('Test notification sent', 'info'); }
      else if (b.dataset.act === 'toggle') { await put('/alerts/' + a.id, { ...a, enabled: b.checked }); load(); }
    } catch (err) { toast(err.message, 'warn'); load(); }
  });
  load();
  const t = setInterval(() => { if (!document.hidden && !$('#dlg').open) get('/targets').then(x => { store.targets = x; render(); }).catch(() => { }); }, 3000);
  return { destroy() { dead = true; clearInterval(t); } };
}

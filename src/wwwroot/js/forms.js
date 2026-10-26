import { get, post, put, del } from './api.js';
import { esc, openDialog, store, toast, closeDialog } from './util.js';
import { SOUNDS, playSound, unlockAudio } from './sound.js';

const sleep = ms => new Promise(r => setTimeout(r, ms));

export async function elevate() {
  if (!confirm('TraceMe will restart with administrator rights. Windows will ask you to confirm (UAC).\n\nTracing resumes automatically afterwards.')) return;
  try { await post('/system/elevate'); } catch (e) { toast(e.message, 'warn'); return; }
  toast('Restarting as administrator…', 'info', 15000);
  for (let i = 0; i < 90; i++) {
    await sleep(1000);
    try { const s = await get('/system'); if (s.elevated) { location.reload(); return; } } catch { /* server restarting */ }
  }
  toast('The elevated instance did not come back. Check the UAC prompt.', 'warn');
}

const INTERVALS = [[200, '0.2 s'], [500, '0.5 s'], [1000, '1 s'], [2000, '2 s'], [2500, '2.5 s'], [5000, '5 s'], [10000, '10 s'], [30000, '30 s'], [60000, '1 min'], [300000, '5 min'], [600000, '10 min']];

function intervalOptions(cur) {
  const list = INTERVALS.some(([v]) => v === cur) ? INTERVALS : [...INTERVALS, [cur, `${cur} ms`]].sort((a, b) => a[0] - b[0]);
  return list.map(([v, l]) => `<option value="${v}" ${v === cur ? 'selected' : ''}>${l}</option>`).join('');
}

const METHOD_HELP = {
  icmp: 'ICMP echo through the Windows ICMP API. Works without administrator rights.',
  udp: 'UDP datagrams with increasing TTL; routers answer with ICMP Time Exceeded, the target with Port Unreachable. Needs administrator rights to read router addresses.',
  tcp: 'TCP SYN probes with increasing TTL — passes firewalls that block ICMP/UDP. Needs administrator rights to read router addresses.',
};

export async function targetDialog(t = null) {
  const edit = !!t, c = t?.config ?? {};
  const v = (k, d) => c[k] ?? d;
  let ifaces = [];
  try { ifaces = await get('/system/interfaces'); } catch { /* optional */ }
  const method = v('method', 'icmp');
  const html = `
    <div class="hd"><h2>${edit ? 'Target settings' : 'Add target'}</h2></div>
    <div class="bd">
      <div class="fgrid" style="grid-template-columns:2fr 1.4fr 1fr">
        <label class="f">Host or IP address<input name="host" required maxlength="253" value="${esc(v('host', ''))}" placeholder="8.8.8.8 or example.com" autocomplete="off" ${edit ? '' : 'autofocus'}></label>
        <label class="f">Display name (optional)<input name="name" maxlength="80" value="${esc(v('name', ''))}"></label>
        <label class="f">Group<input name="group" maxlength="60" value="${esc(v('group', ''))}" list="groups"></label>
      </div>
      <datalist id="groups">${[...new Set(store.targets.map(x => x.group).filter(Boolean))].map(g => `<option value="${esc(g)}">`).join('')}</datalist>
      <div class="col">
        <div class="seg" id="methodSeg" role="radiogroup" aria-label="Trace method">
          ${['icmp', 'udp', 'tcp'].map(m => `<button type="button" data-m="${m}" class="${m === method ? 'on' : ''}" role="radio" aria-checked="${m === method}">${m.toUpperCase()}</button>`).join('')}
        </div>
        <input type="hidden" name="method" value="${method}">
        <div class="mute" id="methodHelp"></div>
        <div id="adminWarn" class="banner" hidden>
          <span class="grow">TraceMe is not running as administrator. UDP/TCP traces can detect the destination, but routers on the path will show no address.</span>
          <button type="button" id="elevBtn">Restart as administrator</button>
        </div>
      </div>
      <div class="fgrid">
        <label class="f">Trace interval<select name="intervalMs">${intervalOptions(v('intervalMs', 1000))}</select></label>
        <label class="f">Timeout (ms)<input name="timeoutMs" type="number" min="100" max="30000" value="${v('timeoutMs', 2000)}"></label>
        <label class="f">Maximum hops<input name="maxHops" type="number" min="1" max="64" value="${v('maxHops', 30)}"></label>
        <label class="f">Starting hop<input name="startHop" type="number" min="1" max="64" value="${v('startHop', 1)}"></label>
      </div>
      <details ${edit ? '' : ''}><summary class="mute" style="cursor:pointer">Advanced packet, DNS and automation options</summary>
        <div class="col" style="margin-top:12px">
          <div class="fgrid">
            <label class="f">Packet size (bytes)<input name="packetSize" type="number" min="0" max="9000" value="${v('packetSize', 56)}"></label>
            <label class="f" data-for="udp tcp">Destination port<input name="port" type="number" min="0" max="65535" value="${v('port', 0) || ''}" placeholder="${method === 'udp' ? '33434' : '80'}"></label>
            <label class="f">Inter-hop delay (ms)<input name="interHopDelayMs" type="number" min="0" max="1000" value="${v('interHopDelayMs', 20)}"></label>
            <label class="f">TOS / DSCP byte<input name="tos" type="number" min="0" max="255" value="${v('tos', 0)}" title="Windows may ignore this unless a QoS policy allows it"></label>
            <label class="f">Source address<select name="sourceAddress"><option value="">Automatic</option>${ifaces.map(i => `<option value="${esc(i.address)}" ${i.address === v('sourceAddress', '') ? 'selected' : ''}>${esc(i.address)} — ${esc(i.name)}</option>`).join('')}</select></label>
            <label class="f">Auto-stop after N traces<input name="stopAfterRounds" type="number" min="1" value="${v('stopAfterRounds', '') ?? ''}"></label>
            <label class="f">Auto-stop after N minutes<input name="stopAfterMinutes" type="number" min="1" value="${v('stopAfterMinutes', '') ?? ''}"></label>
          </div>
          <div class="row">
            <label class="ck" data-for="icmp"><input type="checkbox" name="dontFragment" ${v('dontFragment', true) ? 'checked' : ''}> Don't fragment (ICMP)</label>
            <label class="ck"><input type="checkbox" name="resolveNames" ${v('resolveNames', true) ? 'checked' : ''}> Resolve host names</label>
            <label class="ck"><input type="checkbox" name="preferIPv6" ${v('preferIPv6', false) ? 'checked' : ''}> Prefer IPv6</label>
          </div>
          <fieldset><legend>Remote agent (optional)</legend>
            <div class="fgrid" style="grid-template-columns:2fr 1.4fr auto;align-items:end">
              <label class="f">Agent URL<input name="agentUrl" value="${esc(v('agentUrl', ''))}" placeholder="http://agent-host:5055"></label>
              <label class="f">Agent token<input name="agentToken" type="password" value="${esc(v('agentToken', ''))}" autocomplete="off"></label>
              <button type="button" id="agentTest">Test</button>
            </div>
            <div class="mute" style="margin-top:6px">The probes run on the agent and the results are shown here as if measured locally. Use only over a network you trust: the token travels with each request.</div>
          </fieldset>
        </div>
      </details>
    </div>
    <div class="ft">
      ${edit ? '<button type="submit" value="delete" class="danger">Delete target</button><span class="spacer"></span>' : ''}
      <button type="submit" value="cancel" formnovalidate>Cancel</button>
      <button type="submit" value="save" class="primary">${edit ? 'Save' : 'Start tracing'}</button>
    </div>`;
  return openDialog(html, {
    onMount: (d, form) => {
      const sync = m => {
        form.method.value = m;
        form.querySelectorAll('#methodSeg button').forEach(b => { const on = b.dataset.m === m; b.classList.toggle('on', on); b.setAttribute('aria-checked', on); });
        d.querySelector('#methodHelp').textContent = METHOD_HELP[m];
        d.querySelectorAll('[data-for]').forEach(el => { const on = el.dataset.for.split(' ').includes(m); el.style.opacity = on ? 1 : .4; el.querySelectorAll('input').forEach(i => i.disabled = !on); });
        d.querySelector('#adminWarn').hidden = m === 'icmp' || store.system.elevated;
      };
      form.querySelectorAll('#methodSeg button').forEach(b => b.onclick = () => sync(b.dataset.m));
      sync(method);
      d.querySelector('#elevBtn').onclick = () => { closeDialog(); elevate(); };
      d.querySelector('#agentTest').onclick = async () => {
        try { const r = await post('/agent-test', { url: form.agentUrl.value, token: form.agentToken.value }); toast(`Agent OK — ${r.machine} v${r.version}${r.elevated ? ' (administrator)' : ''}`, 'info'); }
        catch (e) { toast('Agent test failed: ' + e.message, 'warn'); }
      };
    },
    onSubmit: async (fd, action) => {
      if (action === 'delete') {
        if (!confirm(`Delete ${t.displayName} and all of its history?`)) return false;
        await del('/targets/' + t.id); return { deleted: true };
      }
      const n = k => { const x = fd.get(k); return x === null || x === '' ? undefined : Number(x); };
      const cfg = {
        host: fd.get('host'), name: fd.get('name'), group: fd.get('group'), method: fd.get('method'),
        intervalMs: n('intervalMs'), timeoutMs: n('timeoutMs'), maxHops: n('maxHops'), startHop: n('startHop'),
        packetSize: n('packetSize'), port: n('port') ?? 0, interHopDelayMs: n('interHopDelayMs'), tos: n('tos') ?? 0,
        sourceAddress: fd.get('sourceAddress') || null, stopAfterRounds: n('stopAfterRounds') ?? null, stopAfterMinutes: n('stopAfterMinutes') ?? null,
        dontFragment: fd.has('dontFragment') || fd.get('method') !== 'icmp', resolveNames: fd.has('resolveNames'), preferIPv6: fd.has('preferIPv6'),
        agentUrl: fd.get('agentUrl') || null, agentToken: fd.get('agentToken') || null,
      };
      return edit ? put('/targets/' + t.id, cfg) : post('/targets', cfg);
    },
  });
}

// ------------------------------------------------------------------ alert rules

const METRICS = {
  avg: ['Average latency', 'ms', true], max: ['Maximum latency', 'ms', true], last: ['Latest latency', 'ms', true],
  jitter: ['Jitter', 'ms', true], loss: ['Packet loss', '%', true], noresponse: ['No response (all lost)', '', false],
  mos: ['MOS (voice quality)', '', true], routechange: ['Route change', '', false],
};

export async function alertDialog(rule = null, prefill = {}) {
  const edit = !!rule?.id;
  const r = { name: 'New alert', enabled: true, targetId: null, scope: 'destination', hop: 1, metric: 'avg', op: '>', value: 100, samples: 10, consecutiveRounds: 1, notifyOnClear: true, repeatMinutes: 0, actions: [{ type: 'toast' }], ...(rule ?? {}), ...prefill };
  const act = type => r.actions.find(a => a.type === type);
  const allowExec = store.settings.allowExec;
  const html = `
    <div class="hd"><h2>${edit ? 'Edit alert' : 'New alert'}</h2></div>
    <div class="bd">
      <div class="fgrid" style="grid-template-columns:2fr 2fr">
        <label class="f">Name<input name="name" required value="${esc(r.name)}"></label>
        <label class="f">Applies to<select name="targetId"><option value="">All targets</option>${store.targets.map(t => `<option value="${t.id}" ${t.id === r.targetId ? 'selected' : ''}>${esc(t.displayName)}</option>`).join('')}</select></label>
      </div>
      <fieldset><legend>Condition</legend>
        <div class="fgrid">
          <label class="f">Watch<select name="scope"><option value="destination">Destination</option><option value="any">Any hop</option><option value="hop">A specific hop</option></select></label>
          <label class="f" id="hopF">Hop number<input name="hop" type="number" min="1" max="64" value="${r.hop}"></label>
          <label class="f">Metric<select name="metric">${Object.entries(METRICS).map(([k, [l]]) => `<option value="${k}">${l}</option>`).join('')}</select></label>
          <label class="f" id="opF">Is<select name="op"><option value=">">above</option><option value="<">below</option></select></label>
          <label class="f" id="valF"><span>Threshold <span id="unit"></span></span><input name="value" type="number" step="any" value="${r.value}"></label>
          <label class="f" id="smpF">Over the last N samples<input name="samples" type="number" min="1" max="600" value="${r.samples}"></label>
          <label class="f">…for N consecutive traces<input name="consecutiveRounds" type="number" min="1" max="600" value="${r.consecutiveRounds}"></label>
          <label class="f">Repeat while active (min, 0 = off)<input name="repeatMinutes" type="number" min="0" value="${r.repeatMinutes}"></label>
        </div>
        <div class="row" style="margin-top:10px"><label class="ck"><input type="checkbox" name="notifyOnClear" ${r.notifyOnClear ? 'checked' : ''}> Also notify when the condition clears</label>
        <label class="ck"><input type="checkbox" name="enabled" ${r.enabled ? 'checked' : ''}> Enabled</label></div>
      </fieldset>
      <fieldset><legend>Actions</legend><div class="col">
        <label class="ck"><input type="checkbox" name="a_toast" ${act('toast') ? 'checked' : ''}> Show a notification in TraceMe</label>
        <div class="row"><label class="ck"><input type="checkbox" name="a_sound" ${act('sound') ? 'checked' : ''}> Play a sound</label>
          <select name="sound">${SOUNDS.map(s => `<option ${act('sound')?.sound === s ? 'selected' : ''}>${s}</option>`).join('')}</select><button type="button" class="sm" id="snd">▶</button></div>
        <label class="ck"><input type="checkbox" name="a_email" ${act('email') ? 'checked' : ''}> Send an email (configure the server under Settings → Email)</label>
        <div class="fgrid" data-sub="email"><label class="f">To<input name="email_to" value="${esc(act('email')?.to ?? '')}" placeholder="me@example.com, team@example.com"></label><label class="f">Subject<input name="email_subject" value="${esc(act('email')?.subject ?? '')}" placeholder="[TraceMe] {message}"></label></div>
        <label class="ck"><input type="checkbox" name="a_webhook" ${act('webhook') ? 'checked' : ''}> Call a webhook (HTTP POST, JSON)</label>
        <div class="col" data-sub="webhook"><label class="f">URL<input name="wh_url" value="${esc(act('webhook')?.url ?? '')}" placeholder="https://hooks.example.com/…"></label>
          <label class="f">Body template (optional JSON; tokens {message} {target} {host} {hop} {hopHost} {metric} {value} {threshold} {state} {rule} {time})<textarea name="wh_body" rows="2">${esc(act('webhook')?.body ?? '')}</textarea></label></div>
        <label class="ck" title="${allowExec ? '' : 'Enable under Settings → Security first'}"><input type="checkbox" name="a_exec" ${act('exec') ? 'checked' : ''} ${allowExec ? '' : 'disabled'}> Run a program ${allowExec ? '' : '(disabled in Settings → Security)'}</label>
        <div class="fgrid" data-sub="exec"><label class="f">Program<input name="ex_path" value="${esc(act('exec')?.path ?? '')}" placeholder="C:\\Tools\\notify.exe"></label><label class="f">Arguments<input name="ex_args" value="${esc(act('exec')?.args ?? '')}" placeholder='"{message}" {hop}'></label></div>
        <label class="ck"><input type="checkbox" name="a_script" ${act('script') ? 'checked' : ''}> Run a JavaScript snippet (sandboxed; <code>notify(text)</code> and <code>log(text)</code> available)</label>
        <div data-sub="script"><textarea name="sc_body" rows="4" placeholder="if (Value > 200) notify('Very slow at hop ' + Hop);">${esc(act('script')?.script ?? '')}</textarea></div>
      </div></fieldset>
    </div>
    <div class="ft">
      <span class="spacer"></span>
      <button type="submit" value="cancel" formnovalidate>Cancel</button>
      <button type="submit" value="save" class="primary">Save alert</button>
    </div>`;
  return openDialog(html, {
    onMount: (d, form) => {
      form.scope.value = r.scope; form.metric.value = r.metric; form.op.value = r.op;
      const sync = () => {
        const m = form.metric.value, meta = METRICS[m];
        d.querySelector('#unit').textContent = meta[1] ? `(${meta[1]})` : '';
        d.querySelector('#valF').hidden = d.querySelector('#opF').hidden = !meta[2];
        d.querySelector('#smpF').hidden = m === 'routechange';
        d.querySelector('#hopF').hidden = form.scope.value !== 'hop';
        form.scope.querySelector('option[value=any]').disabled = m === 'mos';
        if (m === 'mos') { form.scope.value = 'destination'; d.querySelector('#hopF').hidden = true; }
        d.querySelectorAll('[data-sub]').forEach(el => { const on = form['a_' + { email: 'email', webhook: 'webhook', exec: 'exec', script: 'script' }[el.dataset.sub]].checked; el.style.display = on ? '' : 'none'; });
      };
      form.addEventListener('change', sync); sync();
      d.querySelector('#snd').onclick = () => { unlockAudio(); if (!playSound(form.sound.value)) toast('Sound is blocked until you interact with the page', 'warn'); };
    },
    onSubmit: async fd => {
      const actions = [];
      if (fd.has('a_toast')) actions.push({ type: 'toast' });
      if (fd.has('a_sound')) actions.push({ type: 'sound', sound: fd.get('sound') });
      if (fd.has('a_email')) actions.push({ type: 'email', to: fd.get('email_to'), subject: fd.get('email_subject') || null });
      if (fd.has('a_webhook')) actions.push({ type: 'webhook', url: fd.get('wh_url'), body: fd.get('wh_body') || null });
      if (fd.has('a_exec')) actions.push({ type: 'exec', path: fd.get('ex_path'), args: fd.get('ex_args') });
      if (fd.has('a_script')) actions.push({ type: 'script', script: fd.get('sc_body') });
      const body = {
        name: fd.get('name'), enabled: fd.has('enabled'), targetId: fd.get('targetId') || null, scope: fd.get('scope'),
        hop: Number(fd.get('hop')), metric: fd.get('metric'), op: fd.get('op'), value: Number(fd.get('value')),
        samples: Number(fd.get('samples')), consecutiveRounds: Number(fd.get('consecutiveRounds')),
        notifyOnClear: fd.has('notifyOnClear'), repeatMinutes: Number(fd.get('repeatMinutes')), actions,
      };
      return edit ? put('/alerts/' + rule.id, body) : post('/alerts', body);
    },
  });
}

// ------------------------------------------------------------------ app watch rules

export async function appRuleDialog(rule = null, prefill = {}) {
  const edit = !!rule?.id;
  const r = { processName: '', label: '', method: 'icmp', maxServers: 3, minPps: 5, includeTcp: false, useServerPort: false, intervalMs: 1000, onExit: 'pause', enabled: true, ...(rule ?? {}), ...prefill };
  let games = [], running = [];
  try { [games, running] = await Promise.all([get('/apps/games'), get('/apps?all=true').then(x => x.apps)]); } catch { /* suggestions are optional */ }
  const names = new Map();
  for (const g of games) names.set(g.exe, g.name);
  for (const a of running) if (!names.has(a.key)) names.set(a.key, a.friendly || (a.running ? 'running now' : ''));
  const html = `
    <div class="hd"><h2>${edit ? 'Watch settings' : 'Watch an application'}</h2></div>
    <div class="bd">
      <p class="mute" style="margin:0">While the application runs, TraceMe finds the servers it exchanges game traffic with, traces them, and tells you whether a problem is on your side, your ISP, the internet or the server. A report is saved when the application closes.</p>
      <div class="fgrid" style="grid-template-columns:2fr 2fr">
        <label class="f">Program (executable name)<input name="processName" required list="exes" value="${esc(r.processName)}" placeholder="cod.exe" ${edit ? 'readonly' : 'autofocus'} autocomplete="off"></label>
        <label class="f">Display name (optional)<input name="label" maxlength="60" value="${esc(r.label ?? '')}" placeholder="Call of Duty"></label>
      </div>
      <datalist id="exes">${[...names].map(([k, v]) => `<option value="${esc(k)}">${esc(v)}</option>`).join('')}</datalist>
      <fieldset><legend>How to trace the servers</legend>
        <div class="fgrid">
          <label class="f">Method<select name="method"><option value="icmp">ICMP (ping the server)</option><option value="udp">UDP (game port)</option><option value="tcp">TCP</option></select></label>
          <label class="f">Servers to trace at once<input name="maxServers" type="number" min="1" max="10" value="${r.maxServers}"></label>
          <label class="f">Minimum packets/s of a game server<input name="minPps" type="number" min="0.5" step="0.5" value="${r.minPps}" title="UDP endpoints below this rate are ignored (keep-alives, chat)"></label>
          <label class="f">Trace interval<select name="intervalMs"><option value="500">0.5 s</option><option value="1000">1 s</option><option value="2000">2 s</option><option value="5000">5 s</option></select></label>
        </div>
        <div class="mute" style="margin-top:6px">Many game servers ignore ICMP pings. If the trace never reaches the server, use UDP with the game's own port — the path is still measured up to the last router that answers.</div>
        <div class="row" style="margin-top:8px"><label class="ck"><input type="checkbox" name="useServerPort" ${r.useServerPort ? 'checked' : ''}> Probe the port the game actually uses (UDP/TCP)</label>
          <label class="ck"><input type="checkbox" name="includeTcp" ${r.includeTcp ? 'checked' : ''}> Also trace busy non-web TCP connections</label></div>
      </fieldset>
      <div class="fgrid"><label class="f">When the application closes<select name="onExit"><option value="pause">Pause its traces (keep history)</option><option value="keep">Keep tracing</option><option value="delete">Delete the traces (keep the report)</option></select></label></div>
      <label class="ck"><input type="checkbox" name="enabled" ${r.enabled ? 'checked' : ''}> Watch automatically</label>
    </div>
    <div class="ft">${edit ? '<button type="submit" value="delete" class="danger" formnovalidate>Remove rule</button><span class="spacer"></span>' : ''}
      <button type="submit" value="cancel" formnovalidate>Cancel</button><button type="submit" value="save" class="primary">${edit ? 'Save' : 'Start watching'}</button></div>`;
  return openDialog(html, {
    onMount: (d, form) => { form.method.value = r.method; form.intervalMs.value = String(r.intervalMs); form.onExit.value = r.onExit; },
    onSubmit: async (fd, action) => {
      if (action === 'delete') { if (!confirm('Remove this watch rule? Existing traces and sessions are kept.')) return false; await del('/apps/rules/' + rule.id); return { deleted: true }; }
      const body = {
        processName: fd.get('processName'), label: fd.get('label') || null, method: fd.get('method'), maxServers: Number(fd.get('maxServers')),
        minPps: Number(fd.get('minPps')), intervalMs: Number(fd.get('intervalMs')), onExit: fd.get('onExit'),
        useServerPort: fd.has('useServerPort'), includeTcp: fd.has('includeTcp'), enabled: fd.has('enabled'),
      };
      return edit ? put('/apps/rules/' + rule.id, body) : post('/apps/rules', body);
    },
  });
}

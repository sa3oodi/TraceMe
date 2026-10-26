import { get, post, put } from './api.js';
import { $, $$, esc, store, toast, download, lsGet, lsSet, applyTheme } from './util.js';
import { setSoundEnabled } from './sound.js';
import { elevate } from './forms.js';
import { mountRemote } from './remote.js';

const MASK = '••••••';

function colBlock(c) {
  return `<fieldset data-col="${esc(c.id)}"><legend>${esc(c.name)}</legend>
    <div class="fgrid colgrid">
      <label class="f">Column name<input data-f="name" value="${esc(c.name)}" maxlength="30"></label>
      <label class="f">Decimals<input data-f="decimals" type="number" min="0" max="6" value="${c.decimals}"></label>
      <label class="ck"><input type="checkbox" data-f="visible" ${c.visible !== false ? 'checked' : ''}> Show</label>
      <button type="button" class="danger sm" data-act="rm">Remove</button>
    </div>
    <label class="f" style="margin-top:8px">JavaScript function body — return a number or text<textarea data-f="script" rows="6" spellcheck="false">${esc(c.script)}</textarea></label>
    <div class="row" style="margin-top:6px"><button type="button" class="sm" data-act="test">Test with sample values</button><span class="mute" data-out></span></div>
  </fieldset>`;
}

export function mount(root) {
  let dead = false, s = null;
  root.innerHTML = '<div class="empty">Loading…</div>';

  async function load() {
    const [settings, system] = await Promise.all([get('/settings'), get('/system')]);
    s = settings; store.system = system; if (dead) return; render(system);
  }

  function render(system) {
    const num = (k, v, extra = '') => `<label class="f">${k}<input type="number" step="any" name="${extra}" value="${v}"></label>`;
    root.innerHTML = `<form id="f" class="col" style="gap:14px">
      <div class="row"><h2 class="grow">Settings</h2><button class="primary" type="submit">Save settings</button></div>

      <section class="panel"><div class="hd"><h3>Appearance &amp; thresholds</h3></div><div class="bd col">
        <div class="fgrid">
          <label class="f">Theme<select id="theme"><option value="auto">Follow system</option><option value="light">Light</option><option value="dark">Dark</option></select></label>
          <label class="f">Latency: warning above (ms)<input name="latencyWarnMs" type="number" min="1" step="any" value="${s.latencyWarnMs}"></label>
          <label class="f">Latency: critical above (ms)<input name="latencyCritMs" type="number" min="1" step="any" value="${s.latencyCritMs}"></label>
          <label class="f">Packet loss: warning from (%)<input name="lossWarnPct" type="number" min="0" step="any" value="${s.lossWarnPct}"></label>
          <label class="f">Packet loss: critical from (%)<input name="lossCritPct" type="number" min="0" step="any" value="${s.lossCritPct}"></label>
        </div>
        <div class="row"><label class="ck"><input type="checkbox" id="sound" ${lsGet('sound', true) ? 'checked' : ''}> Play alert sounds in this browser</label>
          <label class="ck"><input type="checkbox" id="notif" ${lsGet('notify', false) ? 'checked' : ''}> Show desktop notifications for alerts</label></div>
      </div></section>

      <section class="panel"><div class="hd"><h3>Data</h3></div><div class="bd col">
        <div class="fgrid"><label class="f">Keep history for (days)<input name="retentionDays" type="number" min="1" max="3650" value="${s.retentionDays}"></label></div>
        <div class="mute">Samples are stored in <span class="mono">${esc(system.dataDir)}</span>. Older samples are purged automatically.</div>
        <div class="row"><button type="button" id="wsExport">Export targets &amp; settings…</button><button type="button" id="wsImport">Import…</button><input type="file" id="wsFile" accept="application/json" hidden>
          <span class="mute">Exports never include passwords or tokens.</span></div>
      </div></section>

      <section class="panel"><div class="hd"><h3>Custom columns</h3><span class="spacer"></span><button type="button" id="addCol" class="sm">+ Add column</button></div><div class="bd col" id="cols">
        <div class="mute">Each column is a small sandboxed JavaScript function evaluated for every hop. Available variables: <span class="mono">Average, Minimum, Maximum, Current, Jitter, LostPacketCount, TotalPacketCount, PacketLossPercent, HopNumber, IPAddress, HostName</span>.</div>
        ${s.columns.map(colBlock).join('')}
      </div></section>

      <section class="panel"><div class="hd"><h3>Custom host names</h3><span class="spacer"></span><button type="button" id="addAlias" class="sm">+ Add</button></div><div class="bd col" id="aliases">
        <div class="mute">Give a router address a friendly name (it replaces the reverse-DNS name). You can also set one from a hop's ⋯ menu.</div>
        ${Object.entries(s.aliases).map(([ip, n]) => aliasRow(ip, n)).join('')}
      </div></section>

      <section class="panel"><div class="hd"><h3>Email (SMTP)</h3></div><div class="bd col">
        <div class="fgrid">
          <label class="f">Server<input name="smtp_host" value="${esc(s.smtp.host)}" placeholder="smtp.example.com"></label>
          <label class="f">Port<input name="smtp_port" type="number" value="${s.smtp.port}"></label>
          <label class="f">Security<select name="smtp_security"><option value="starttls">STARTTLS</option><option value="ssl">SSL/TLS</option><option value="none">None</option></select></label>
          <label class="f">User name<input name="smtp_user" value="${esc(s.smtp.user)}" autocomplete="off"></label>
          <label class="f">Password<input name="smtp_password" type="password" value="${esc(s.smtp.password)}" autocomplete="new-password"></label>
          <label class="f">From address<input name="smtp_from" value="${esc(s.smtp.from)}" placeholder="traceme@example.com"></label>
        </div>
        <div class="row"><input id="mailTo" placeholder="send a test to…" style="width:240px"><button type="button" id="mailTest">Send test email</button></div>
      </div></section>

      <section class="panel"><div class="hd"><h3>Remote access — view TraceMe on your phone</h3></div><div class="bd col" id="remote"><div class="mute">Loading…</div></div></section>

      <section class="panel"><div class="hd"><h3>Security &amp; integrations</h3></div><div class="bd col">
        <label class="ck"><input type="checkbox" name="asnLookup" ${s.asnLookup ? 'checked' : ''}> Look up the AS owner of each hop automatically (sends hop IP addresses to Team Cymru's whois service)</label>
        <label class="ck"><input type="checkbox" name="allowExec" ${s.allowExec ? 'checked' : ''}> Allow alert actions to run programs on this computer</label>
        <fieldset><legend>Remote agent</legend>
          <div class="fgrid" style="grid-template-columns:2fr auto;align-items:end"><label class="f">Agent token (leave empty to disable agent mode on this instance)<input name="agentToken" type="password" value="${esc(s.agentToken ?? '')}" autocomplete="off"></label>
          <button type="button" id="genTok">Generate</button></div>
          <div class="mute" style="margin-top:6px">With a token set, other TraceMe instances can run traces from this machine (add this machine's URL and token to a target's “Remote agent” settings). To open the web page from your phone use “Remote access” above.</div>
        </fieldset>
      </div></section>

      <section class="panel"><div class="hd"><h3>About this installation</h3></div><div class="bd">
        <table style="max-width:640px"><tbody>
          <tr><td class="l mute">Version</td><td class="l">${esc(system.version)}</td></tr>
          <tr><td class="l mute">Computer</td><td class="l">${esc(system.machine)} — ${esc(system.os)}</td></tr>
          <tr><td class="l mute">Privileges</td><td class="l">${system.elevated ? '<span class="good">Administrator</span> — UDP and TCP traces can read router addresses' : 'Standard user — ICMP traces work fully; UDP/TCP can only detect the destination <button type="button" class="sm" id="elev">Restart as administrator</button>'}</td></tr>
          <tr><td class="l mute">Raw ICMP capture</td><td class="l">${system.rawIcmp.length ? system.rawIcmp.map(r => `${esc(r.local)}: ${r.ok ? `ok (${r.matched} matched / ${r.packets} packets)` : esc(r.error)}`).join('<br>') : 'not used yet'}</td></tr>
          <tr><td class="l mute">IPv6</td><td class="l">${system.ipv6 ? 'available' : 'not available'}</td></tr>
          <tr><td class="l mute">Access token</td><td class="l">${system.authRequired ? 'required' : 'not required (loopback only)'}</td></tr>
        </tbody></table>
      </div></section>
    </form>`;

    const f = $('#f', root);
    f.smtp_security.value = s.smtp.security;
    $('#theme', root).value = lsGet('theme', 'auto');
    $('#theme', root).onchange = e => { lsSet('theme', e.target.value); applyTheme(); };
    $('#sound', root).onchange = e => { lsSet('sound', e.target.checked); setSoundEnabled(e.target.checked); };
    $('#notif', root).onchange = async e => {
      if (e.target.checked && 'Notification' in window && Notification.permission !== 'granted') {
        const p = await Notification.requestPermission();
        if (p !== 'granted') { e.target.checked = false; toast('Notifications were blocked by the browser', 'warn'); }
      }
      lsSet('notify', e.target.checked);
    };
    $('#elev', root)?.addEventListener('click', elevate);
    mountRemote($('#remote', root));
    $('#genTok', root).onclick = () => { const b = crypto.getRandomValues(new Uint8Array(18)); f.agentToken.type = 'text'; f.agentToken.value = [...b].map(x => x.toString(16).padStart(2, '0')).join(''); };

    // columns
    $('#addCol', root).onclick = () => {
      const c = { id: Math.random().toString(16).slice(2, 8), name: 'New column', decimals: 1, visible: true, script: 'return Average;' };
      $('#cols', root).insertAdjacentHTML('beforeend', colBlock(c));
    };
    $('#cols', root).addEventListener('click', async e => {
      const b = e.target.closest('[data-act]'); if (!b) return;
      const fs = b.closest('fieldset');
      if (b.dataset.act === 'rm') fs.remove();
      if (b.dataset.act === 'test') {
        try { const r = await post('/settings/test-column', { script: $('[data-f=script]', fs).value }); $('[data-out]', fs).textContent = r.error ? 'Error: ' + r.error : 'Result: ' + r.value; $('[data-out]', fs).className = r.error ? 'bad' : 'good'; }
        catch (err) { toast(err.message, 'warn'); }
      }
    });
    // aliases
    $('#addAlias', root).onclick = () => $('#aliases', root).insertAdjacentHTML('beforeend', aliasRow('', ''));
    $('#aliases', root).addEventListener('click', e => { if (e.target.closest('[data-rm]')) e.target.closest('.row').remove(); });
    // email test
    $('#mailTest', root).onclick = async () => {
      try { await save(false); await post('/settings/smtp-test', { to: $('#mailTo', root).value }); toast('Test email sent', 'info'); } catch (err) { toast(err.message, 'warn'); }
    };
    // workspace
    $('#wsExport', root).onclick = async () => { download('traceme-workspace.json', JSON.stringify(await get('/workspace/export'), null, 2), 'application/json'); };
    $('#wsImport', root).onclick = () => $('#wsFile', root).click();
    $('#wsFile', root).onchange = async e => {
      const file = e.target.files[0]; if (!file) return;
      try { const r = await post('/workspace/import', JSON.parse(await file.text())); toast(`Imported ${r.targets} target(s), ${r.alerts} alert(s)${r.settings ? ', settings' : ''}`, 'info'); load(); }
      catch (err) { toast('Import failed: ' + err.message, 'warn'); }
    };

    f.onsubmit = async e => { e.preventDefault(); try { await save(true); } catch (err) { toast(err.message, 'warn'); } };
  }

  const aliasRow = (ip, n) => `<div class="row"><input data-ip placeholder="IP address" value="${esc(ip)}" style="width:200px"><input data-name placeholder="Name" value="${esc(n)}" style="width:260px"><button type="button" class="ghost sm" data-rm aria-label="Remove">✕</button></div>`;

  async function save(announce) {
    const f = $('#f', root), n = k => Number(f[k].value);
    const aliases = {};
    $$('#aliases .row', root).forEach(r => { const ip = $('[data-ip]', r).value.trim(), nm = $('[data-name]', r).value.trim(); if (ip && nm) aliases[ip] = nm; });
    const columns = $$('#cols fieldset', root).map(fs => ({
      id: fs.dataset.col, name: $('[data-f=name]', fs).value.trim() || 'Column', decimals: Number($('[data-f=decimals]', fs).value),
      visible: $('[data-f=visible]', fs).checked, script: $('[data-f=script]', fs).value,
    }));
    const body = {
      latencyWarnMs: n('latencyWarnMs'), latencyCritMs: n('latencyCritMs'), lossWarnPct: n('lossWarnPct'), lossCritPct: n('lossCritPct'),
      retentionDays: n('retentionDays'), allowExec: f.allowExec.checked, asnLookup: f.asnLookup.checked,
      agentToken: f.agentToken.value || null, aliases, columns,
      smtp: { host: f.smtp_host.value, port: n('smtp_port'), user: f.smtp_user.value, password: f.smtp_password.value, security: f.smtp_security.value, from: f.smtp_from.value },
    };
    s = await put('/settings', body); store.settings = s;
    document.dispatchEvent(new CustomEvent('tm-settings'));
    if (announce) toast('Settings saved', 'info');
  }

  load().catch(e => { root.innerHTML = `<div class="empty bad">${esc(e.message)}</div>`; });
  return { destroy() { dead = true; } };
}

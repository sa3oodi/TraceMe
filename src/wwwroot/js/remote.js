import { get, post } from './api.js';
import { $, esc, toast } from './util.js';

const sleep = ms => new Promise(r => setTimeout(r, ms));
const isLocal = () => ['127.0.0.1', 'localhost', '[::1]'].includes(location.hostname);

/** Waits for the restarted server, then reloads. */
async function afterRestart(msg) {
  toast(msg, 'info', 20000);
  await sleep(1500);
  for (let i = 0; i < 60; i++) {
    try { await get('/system'); location.reload(); return; } catch (e) { if (e.message === 'Authentication required') { location.reload(); return; } }
    await sleep(1000);
  }
  toast('TraceMe did not come back. Start it again from the Start menu.', 'warn', 15000);
}

/** The "Remote access" panel of the settings page: view TraceMe from a phone or another computer on the same network. */
export async function mountRemote(box) {
  let r, qrAddr = '', qrToken = true, reveal = false;
  async function load() {
    try { r = await get('/system/remote'); } catch (e) { box.innerHTML = `<div class="mute">${esc(e.message)}</div>`; return; }
    if (!qrAddr) qrAddr = (r.addresses.find(a => a.primary) || r.addresses[0] || {}).address || '';
    draw();
  }

  function draw() {
    const intro = `<p class="mute" style="margin:0">Open TraceMe on your phone (or another computer) while it is on the same Wi-Fi / network as this PC. Traffic is plain HTTP and protected by an access token, so use it only on a network you trust, and never forward the port on your router.</p>`;
    if (!r.active) {
      if (!r.managed) { box.innerHTML = `${intro}<div class="mute">The listen address was set by start-up options and cannot be changed here.</div>`; return; }
      box.innerHTML = `${intro}
        <div class="row"><button class="primary" type="button" id="rOn">Turn on remote access…</button>
          <span class="mute">TraceMe restarts once${r.firewall.canManage ? ' and opens the Windows Firewall for private networks' : ''}.</span></div>
        ${r.firewall.canManage ? '' : '<div class="mute">Not running as administrator: you will have to allow the connection in Windows Firewall yourself.</div>'}`;
      $('#rOn', box).onclick = enable;
      return;
    }
    const sel = r.addresses.length > 1
      ? `<label class="f" style="max-width:360px">Address of this PC<select id="rAddr">${r.addresses.map(a => `<option value="${esc(a.address)}" ${a.address === qrAddr ? 'selected' : ''}>${esc(a.address)} — ${esc(a.name)}${a.virtual ? ' (virtual)' : ''}</option>`).join('')}</select></label>` : '';
    const cur = r.addresses.find(a => a.address === qrAddr);
    const url = cur ? cur.url : '';
    const q = `/api/system/remote/qr?addr=${encodeURIComponent(qrAddr)}${qrToken ? '&token=1' : ''}&_=${Date.now() % 100000}`;
    box.innerHTML = `${intro}
      <div class="rgrid">
        <div class="col" style="gap:10px">
          <div><b class="good">Remote access is on.</b> On your phone, scan the code${qrToken ? ' (it signs you in)' : ''} or open:</div>
          ${url ? `<div class="mono" style="font-size:16px;word-break:break-all"><a href="${esc(url)}">${esc(url)}</a></div>` : '<div class="bad">No network address found. Connect this PC to Wi-Fi or Ethernet.</div>'}
          ${sel}
          <label class="ck"><input type="checkbox" id="rQrTok" ${qrToken ? 'checked' : ''}> Put the access token in the QR code (anyone who sees the code can sign in)</label>
          <div class="row"><span class="mute">Access token</span> <span class="mono" id="rTok">${reveal ? esc(r.token) : '••••••••••••••••'}</span>
            <button type="button" class="sm" id="rShow">${reveal ? 'Hide' : 'Show'}</button><button type="button" class="sm" id="rCopy">Copy</button><button type="button" class="sm" id="rNew">New token</button></div>
          <div class="row"><span class="mute">Windows Firewall</span>
            ${r.firewall.exists ? '<span class="good">allowed for private networks</span>' : '<span class="bad">no rule yet</span>'}
            ${r.firewall.canManage ? `<button type="button" class="sm" id="rFw">${r.firewall.exists ? 'Remove rule' : 'Allow now'}</button>` : '<span class="mute">(needs administrator)</span>'}</div>
          <div class="mute">If the phone cannot connect: check it is on the same Wi-Fi, that Windows calls this network “Private”, and that no guest-network isolation is enabled on your router.</div>
          <div class="row">${r.managed ? '<button type="button" class="danger" id="rOff">Turn off remote access</button>' : '<span class="mute">Set by start-up options; change them to turn it off.</span>'}</div>
        </div>
        ${cur ? `<div class="qrbox"><img src="${q}" alt="QR code to open TraceMe on your phone" width="200" height="200"></div>` : ''}
      </div>`;
    $('#rAddr', box)?.addEventListener('change', e => { qrAddr = e.target.value; draw(); });
    $('#rQrTok', box).onchange = e => { qrToken = e.target.checked; draw(); };
    $('#rShow', box).onclick = () => { reveal = !reveal; draw(); };
    $('#rCopy', box).onclick = async () => { try { await navigator.clipboard.writeText(r.token); toast('Token copied', 'info', 1500); } catch { toast('Copy is not available here; use Show and copy it by hand.', 'warn'); } };
    $('#rNew', box).onclick = newToken;
    $('#rFw', box)?.addEventListener('click', async () => {
      try { await post('/system/remote/firewall', { allow: !r.firewall.exists }); toast(r.firewall.exists ? 'Firewall rule removed' : 'Windows Firewall now allows private networks', 'info'); load(); } catch (e) { toast(e.message, 'warn'); }
    });
    $('#rOff', box)?.addEventListener('click', disable);
  }

  async function enable() {
    if (!confirm('Turn on remote access?\n\nTraceMe will restart and listen on your local network. Anyone on that network who has the access token can view and control TraceMe. The connection is not encrypted, so only use this on a network you trust.')) return;
    try {
      const res = await post('/system/remote', { enabled: true });
      if (res.note) toast(res.note, 'warn', 15000);
      await afterRestart('Restarting TraceMe with remote access…');
    } catch (e) { toast(e.message, 'warn'); }
  }
  async function disable() {
    if (!confirm('Turn off remote access? Devices other than this PC will lose access.')) return;
    try {
      await post('/system/remote', { enabled: false });
      if (!isLocal()) { toast('Remote access is off. This device can no longer connect.', 'info', 30000); return; }
      await afterRestart('Restarting TraceMe…');
    } catch (e) { toast(e.message, 'warn'); }
  }
  async function newToken() {
    if (!confirm('Create a new access token? Every device that is signed in (including your phone) must sign in again.')) return;
    try { await post('/system/remote/token'); if (!isLocal()) { toast('New token created. Sign in again with the new token.', 'info', 30000); return; } await afterRestart('Restarting with the new token…'); }
    catch (e) { toast(e.message, 'warn'); }
  }

  await load();
}

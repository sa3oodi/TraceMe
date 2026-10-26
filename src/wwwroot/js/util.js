export const $ = (s, r = document) => r.querySelector(s);
export const $$ = (s, r = document) => [...r.querySelectorAll(s)];
export const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export const store = {
  system: {}, settings: { latencyWarnMs: 100, latencyCritMs: 250, lossWarnPct: 1, lossCritPct: 5, columns: [] },
  targets: [],
};

/** Offset between this browser and the server clock, so live windows line up with stored timestamps. */
export const clock = { offset: 0 };
export const now = () => Date.now() + clock.offset;

export function mosFrom(avg, jitter, loss) {
  if (avg == null) return null;
  const eff = avg + (jitter ?? 0) * 2 + 10;
  let r = eff < 160 ? 93.2 - eff / 40 : 93.2 - (eff - 120) / 10;
  r = Math.max(r - loss * 2.5, 0);
  return Math.round((1 + 0.035 * r + 0.000007 * r * (r - 60) * (100 - r)) * 100) / 100;
}

export function lsGet(key, def) { try { const v = localStorage.getItem('tm.' + key); return v == null ? def : JSON.parse(v); } catch { return def; } }
export function lsSet(key, val) { try { localStorage.setItem('tm.' + key, JSON.stringify(val)); } catch { /* storage unavailable */ } }

export const fmtMs = (v, d = 1) => v == null ? '–' : (v >= 100 ? v.toFixed(0) : v.toFixed(d));
export const fmtPct = (v, d = 1) => v == null ? '–' : v.toFixed(v === 0 ? 0 : d) + '%';
export const pad = n => String(n).padStart(2, '0');
export function fmtTime(t, full = false) {
  const d = new Date(t);
  const hms = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  return full ? `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${hms}` : hms;
}
export function fmtDuration(ms) {
  const s = Math.round(ms / 1000);
  if (s < 90) return s + ' s';
  if (s < 5400) return Math.round(s / 60) + ' min';
  if (s < 129600) return (s / 3600).toFixed(1) + ' h';
  return (s / 86400).toFixed(1) + ' d';
}

export function latClass(ms) {
  if (ms == null) return 'mute';
  const s = store.settings;
  return ms < s.latencyWarnMs ? 'good' : ms < s.latencyCritMs ? 'warn' : 'bad';
}
export function lossClass(p) {
  if (p == null) return 'mute';
  const s = store.settings;
  return p < s.lossWarnPct ? 'good' : p < s.lossCritPct ? 'warn' : 'bad';
}
export function mosClass(m) { return m == null ? 'mute' : m >= 4 ? 'good' : m >= 3.1 ? 'warn' : 'bad'; }
/** Overall health of a target for the status dot. */
export function health(t) {
  if (t.status === 'error') return 'bad';
  if (t.status === 'paused' || t.status === 'stopped' || t.avg == null) return '';
  const l = lossClass(t.lossPct), a = latClass(t.avg);
  return l === 'bad' || a === 'bad' ? 'bad' : l === 'warn' || a === 'warn' ? 'warn' : 'good';
}

export const debounce = (fn, ms) => { let h; return (...a) => { clearTimeout(h); h = setTimeout(() => fn(...a), ms); }; };
export function throttle(fn, ms) {
  let last = 0, timer = null, pending;
  return (...a) => {
    pending = a; const now = Date.now();
    if (now - last >= ms) { last = now; fn(...a); }
    else if (!timer) timer = setTimeout(() => { timer = null; last = Date.now(); fn(...pending); }, ms - (now - last));
  };
}

export function toast(msg, sev = 'info', ms = 6000) {
  const el = document.createElement('div');
  el.className = 'toast ' + sev; el.textContent = msg; el.setAttribute('role', 'status');
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), ms);
  el.onclick = () => el.remove();
}

export function download(name, content, type = 'text/plain') {
  const blob = content instanceof Blob ? content : new Blob([content], { type });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

/** Small popup menu anchored at an element or pointer position. items: [{label, fn, disabled, html}] */
export function menu(anchor, items) {
  const m = $('#menu'); m.innerHTML = '';
  for (const it of items) {
    if (it.sep) { m.appendChild(Object.assign(document.createElement('hr'), { style: 'border:0;border-top:1px solid var(--line);margin:4px 0' })); continue; }
    const b = document.createElement('button'); b.textContent = it.label; b.disabled = !!it.disabled;
    b.onclick = () => { m.hidden = true; it.fn?.(); };
    m.appendChild(b);
  }
  const r = anchor.getBoundingClientRect ? anchor.getBoundingClientRect() : { left: anchor.x, bottom: anchor.y, right: anchor.x };
  m.hidden = false;
  const w = m.offsetWidth, h = m.offsetHeight;
  m.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.left)) + 'px';
  m.style.top = Math.max(8, Math.min(innerHeight - h - 8, r.bottom + 4)) + 'px';
}
export function popover(anchor, html, onMount) {
  const m = $('#menu'); m.innerHTML = html;
  const r = anchor.getBoundingClientRect();
  m.hidden = false;
  m.style.left = Math.max(8, Math.min(innerWidth - m.offsetWidth - 8, r.left)) + 'px';
  m.style.top = Math.min(innerHeight - m.offsetHeight - 8, r.bottom + 4) + 'px';
  onMount?.(m);
}
document.addEventListener('pointerdown', e => { const m = $('#menu'); if (!m.hidden && !m.contains(e.target)) m.hidden = true; }, true);
document.addEventListener('keydown', e => { if (e.key === 'Escape') $('#menu').hidden = true; });

/** Opens the shared <dialog>. Resolves with the form's submit value or null when cancelled. */
export function openDialog(html, { onMount, onSubmit } = {}) {
  const d = $('#dlg');
  d.innerHTML = `<form method="dialog">${html}</form>`;
  const form = d.querySelector('form');
  return new Promise(resolve => {
    let result = null;
    form.addEventListener('submit', async e => {
      const submitter = e.submitter?.value;
      if (submitter === 'cancel') { result = null; return; }
      if (onSubmit) {
        e.preventDefault();
        try { const r = await onSubmit(new FormData(form), submitter); if (r !== false) { result = r ?? true; d.close(); } }
        catch (err) { toast(err.message || String(err), 'warn'); }
        return;
      }
      result = submitter || true;
    });
    d.addEventListener('close', () => resolve(result), { once: true });
    d.showModal();
    onMount?.(d, form);
  });
}
export const closeDialog = () => { const d = $('#dlg'); if (d.open) d.close(); };

export function copyText(t) { navigator.clipboard?.writeText(t).then(() => toast('Copied ' + t), () => toast('Copy failed', 'warn')); }

export function applyTheme() {
  const t = lsGet('theme', 'auto');
  if (t === 'auto') document.documentElement.removeAttribute('data-theme'); else document.documentElement.setAttribute('data-theme', t);
}

/** Replaces an element's markup only when it changed; returns true when it did (so callers can re-bind handlers). */
export function setHtml(el, html) {
  if (el._html === html) return false;
  el._html = html; el.innerHTML = html; return true;
}

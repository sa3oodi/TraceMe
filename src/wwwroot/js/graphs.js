import { fmtTime, fmtMs, fmtDuration, store, pad } from './util.js';

const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

function prep(c) {
  const dpr = window.devicePixelRatio || 1, w = c.clientWidth, h = c.clientHeight;
  const pw = Math.round(w * dpr), ph = Math.round(h * dpr);
  if (c.width !== pw || c.height !== ph) { c.width = pw; c.height = ph; }
  const g = c.getContext('2d');
  g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, w, h);
  return { g, w, h };
}

export function niceCeil(v) {
  if (!(v > 0)) return 10;
  const p = Math.pow(10, Math.floor(Math.log10(v))), m = v / p;
  return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10) * p;
}

/** Compact latency sparkline. series: numbers, null = lost probe. */
export function drawSpark(c, series, { max } = {}) {
  const { g, w, h } = prep(c);
  const vals = series.filter(v => v != null);
  const top = max || Math.max(5, (vals.length ? Math.max(...vals) : 0) * 1.15);
  const n = series.length; if (!n) return;
  const x = i => n < 2 ? w / 2 : 1 + (w - 2) * i / (n - 1);
  const y = v => h - 2 - (h - 4) * Math.min(1, v / top);
  g.fillStyle = css('--graph-loss');
  series.forEach((v, i) => { if (v == null) g.fillRect(Math.round(x(i)) - 1, 0, 2, h); });
  g.strokeStyle = css('--graph-line'); g.lineWidth = 1.3; g.beginPath();
  let pen = false;
  series.forEach((v, i) => { if (v == null) { pen = false; return; } pen ? g.lineTo(x(i), y(v)) : g.moveTo(x(i), y(v)); pen = true; });
  g.stroke();
}

const STEPS = [1, 5, 10, 15, 30, 60, 300, 600, 900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400, 2 * 86400, 7 * 86400].map(s => s * 1000);
function fmtTick(t, step) {
  const d = new Date(t);
  if (step < 60000) return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  if (step < 86400000) return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

const MARKER_COLORS = { route: '#d97706', alert: '#dc2626', comment: '#2563eb', error: '#dc2626', info: '#64748b' };

/**
 * Latency timeline for one hop: min–max band, average line, loss bars, threshold lines, event markers,
 * hover tooltip and drag-to-select. A second canvas below shows jitter on the same time axis.
 */
export class Timeline {
  constructor(wrap, { onSelect } = {}) {
    this.wrap = wrap; this.main = wrap.querySelector('canvas.main'); this.jit = wrap.querySelector('canvas.jit');
    this.tip = Object.assign(document.createElement('div'), { className: 'tip', hidden: true }); wrap.appendChild(this.tip);
    this.onSelect = onSelect; this.data = null; this.sel = null; this.drag = null; this.hoverX = null; this.markerHits = [];
    this.pad = { l: 50, r: 10, t: 24, b: 22 };
    const c = this.main;
    c.addEventListener('pointerdown', e => this.down(e));
    c.addEventListener('pointermove', e => this.move(e));
    c.addEventListener('pointerup', e => this.up(e));
    c.addEventListener('pointerleave', () => { if (!this.drag) { this.hoverX = null; this.tip.hidden = true; this.draw(); } });
    c.addEventListener('dblclick', () => this.onSelect?.(null));
    this.ro = new ResizeObserver(() => this.draw()); this.ro.observe(c);
  }
  destroy() { this.ro.disconnect(); this.tip.remove(); }
  setData(d) { this.data = d; this.draw(); }
  setSelection(s) { this.sel = s; this.draw(); }

  geo() {
    const { g, w, h } = prep(this.main), p = this.pad;
    return { g, w, h, pw: w - p.l - p.r, ph: h - p.t - p.b };
  }
  tAt(px) { const d = this.data, { pw } = this.geo(); return d.from + (px - this.pad.l) / pw * (d.to - d.from); }

  local(e) { const r = this.main.getBoundingClientRect(); return { x: e.clientX - r.left, y: e.clientY - r.top }; }
  down(e) {
    if (!this.data || e.button !== 0) return;
    const { x } = this.local(e);
    this.main.setPointerCapture(e.pointerId);
    this.drag = { x0: x, x1: x };
  }
  move(e) {
    if (!this.data) return;
    const { x, y } = this.local(e);
    if (this.drag) { this.drag.x1 = x; this.draw(); return; }
    this.hoverX = x; this.draw(); this.showTip(x, y);
  }
  up(e) {
    if (!this.drag) return;
    const { x0, x1 } = this.drag; this.drag = null;
    this.main.releasePointerCapture?.(e.pointerId);
    if (Math.abs(x1 - x0) >= 5) {
      const a = Math.max(this.data.from, this.tAt(Math.min(x0, x1))), b = Math.min(this.data.to, this.tAt(Math.max(x0, x1)));
      if (b > a) this.onSelect?.({ from: Math.round(a), to: Math.round(b) });
    }
    this.draw();
  }

  bucketAt(x) {
    const d = this.data; if (!d?.buckets?.length) return null;
    const t = this.tAt(x); let best = null, bd = Infinity;
    for (const b of d.buckets) { const dist = Math.abs(b[0] + d.bucketMs / 2 - t); if (dist < bd) { bd = dist; best = b; } }
    return bd <= Math.max(d.bucketMs * 1.5, (d.to - d.from) / 120) ? best : null;
  }

  showTip(x, y) {
    const d = this.data; let html = null;
    const m = this.markerHits.find(h => Math.abs(h.x - x) < 7 && y < this.pad.t + 6);
    if (m) html = `${fmtTime(m.m.t, true)}  [${m.m.type}]\n${m.m.text}`;
    else {
      const b = this.bucketAt(x);
      if (b) {
        const loss = b[1] ? (b[1] - b[2]) / b[1] * 100 : 0;
        const span = d.bucketMs <= 1500 ? fmtTime(b[0], true) : `${fmtTime(b[0], true)} +${fmtDuration(d.bucketMs)}`;
        html = `${span}\navg ${fmtMs(b[4])} ms   min ${fmtMs(b[3])}   max ${fmtMs(b[5])}\nloss ${loss.toFixed(loss ? 1 : 0)}%   jitter ${fmtMs(b[6])} ms   (${b[1]} samples)`;
      } else html = fmtTime(this.tAt(x), true);
    }
    this.tip.textContent = html; this.tip.hidden = false;
    const wr = this.wrap.getBoundingClientRect(), cr = this.main.getBoundingClientRect();
    const tx = Math.min(x + 14, this.main.clientWidth - this.tip.offsetWidth - 4);
    this.tip.style.left = (cr.left - wr.left + Math.max(4, tx)) + 'px';
    this.tip.style.top = (cr.top - wr.top + Math.max(4, y - this.tip.offsetHeight - 10)) + 'px';
  }

  draw() {
    const { g, w, h, pw, ph } = this.geo(), p = this.pad, d = this.data;
    const mute = css('--mute'), grid = css('--graph-grid');
    g.font = '11px "Segoe UI", system-ui, sans-serif'; g.textBaseline = 'middle';
    if (!d || !d.buckets) { g.fillStyle = mute; g.textAlign = 'center'; g.fillText('Loading…', w / 2, h / 2); this.drawJitter(); return; }
    const { from, to, buckets, bucketMs } = d, span = to - from;
    const x = t => p.l + (t - from) / span * pw;
    const maxV = buckets.reduce((m, b) => Math.max(m, b[5] ?? 0), 0);
    const yMax = niceCeil(Math.max(10, maxV * 1.12));
    const y = v => p.t + ph - Math.min(1, v / yMax) * ph;

    // grid + y axis
    g.textAlign = 'right'; g.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const v = yMax * i / 4, yy = Math.round(y(v)) + .5;
      g.strokeStyle = grid; g.beginPath(); g.moveTo(p.l, yy); g.lineTo(w - p.r, yy); g.stroke();
      g.fillStyle = mute; g.fillText(fmtMs(v, v < 10 ? 1 : 0), p.l - 6, yy);
    }
    g.textAlign = 'left'; g.fillText('ms', 6, 8); g.textAlign = 'right';
    // x axis
    const target = Math.max(2, Math.floor(pw / 110));
    const step = STEPS.find(s => span / s <= target) || STEPS[STEPS.length - 1];
    g.textAlign = 'center';
    for (let t = Math.ceil(from / step) * step; t <= to; t += step) {
      const xx = Math.round(x(t)) + .5;
      g.strokeStyle = grid; g.beginPath(); g.moveTo(xx, p.t); g.lineTo(xx, p.t + ph); g.stroke();
      g.fillStyle = mute; g.fillText(fmtTick(t, step), xx, h - 9);
    }
    // thresholds
    const s = store.settings;
    g.setLineDash([5, 4]);
    for (const [v, col] of [[s.latencyWarnMs, css('--warn')], [s.latencyCritMs, css('--bad')]]) {
      if (v > yMax) continue;
      g.strokeStyle = col; g.globalAlpha = .6; g.beginPath(); g.moveTo(p.l, y(v)); g.lineTo(w - p.r, y(v)); g.stroke(); g.globalAlpha = 1;
    }
    g.setLineDash([]);

    const bw = Math.max(1.5, bucketMs / span * pw);
    // loss
    g.fillStyle = css('--graph-loss');
    for (const b of buckets) {
      const lost = b[1] - b[2]; if (lost <= 0) continue;
      g.globalAlpha = Math.min(1, .25 + .75 * lost / b[1]);
      g.fillRect(x(b[0]), p.t, bw, ph);
    }
    g.globalAlpha = 1;
    // min–max band
    g.fillStyle = css('--graph-band');
    for (const b of buckets) {
      if (b[2] === 0) continue;
      const y1 = y(b[5]), y2 = y(b[3]);
      g.fillRect(x(b[0]), y1, bw, Math.max(1.5, y2 - y1));
    }
    // average line
    g.strokeStyle = css('--graph-line'); g.lineWidth = 1.6; g.lineJoin = 'round'; g.beginPath();
    let prevT = null;
    for (const b of buckets) {
      if (b[2] === 0) { prevT = null; continue; }
      const xx = x(b[0]) + bw / 2, yy = y(b[4]);
      if (prevT != null && b[0] - prevT <= bucketMs * 3) g.lineTo(xx, yy); else g.moveTo(xx, yy);
      prevT = b[0];
    }
    g.stroke();
    if (bw >= 6) { // single points are visible only at high zoom
      g.fillStyle = css('--graph-line');
      for (const b of buckets) if (b[2] > 0) { g.beginPath(); g.arc(x(b[0]) + bw / 2, y(b[4]), 2, 0, 7); g.fill(); }
    }
    // markers
    this.markerHits = [];
    for (const m of d.markers || []) {
      if (m.t < from || m.t > to) continue;
      const xx = x(m.t);
      g.fillStyle = MARKER_COLORS[m.type] || MARKER_COLORS.info;
      g.beginPath(); g.moveTo(xx - 4, 3); g.lineTo(xx + 4, 3); g.lineTo(xx, 12); g.closePath(); g.fill();
      g.globalAlpha = .35; g.fillRect(Math.round(xx), 12, 1, ph + p.t - 12); g.globalAlpha = 1;
      this.markerHits.push({ x: xx, m });
    }
    // selection
    const selPx = this.drag ? [Math.min(this.drag.x0, this.drag.x1), Math.max(this.drag.x0, this.drag.x1)]
      : this.sel ? [x(this.sel.from), x(this.sel.to)] : null;
    if (selPx) {
      const a = Math.max(p.l, selPx[0]), b = Math.min(w - p.r, selPx[1]);
      g.fillStyle = css('--accent'); g.globalAlpha = .14; g.fillRect(a, p.t, b - a, ph); g.globalAlpha = 1;
      g.strokeStyle = css('--accent'); g.lineWidth = 1; g.strokeRect(a + .5, p.t + .5, b - a, ph - 1);
    }
    // hover
    if (this.hoverX != null && !this.drag && this.hoverX >= p.l && this.hoverX <= w - p.r) {
      g.strokeStyle = mute; g.lineWidth = 1; g.globalAlpha = .7; g.beginPath(); g.moveTo(Math.round(this.hoverX) + .5, p.t); g.lineTo(Math.round(this.hoverX) + .5, p.t + ph); g.stroke(); g.globalAlpha = 1;
    }
    if (!buckets.length) { g.fillStyle = mute; g.textAlign = 'center'; g.fillText('No samples in this time range', w / 2, p.t + ph / 2); }
    this.drawJitter();
  }

  drawJitter() {
    if (!this.jit) return;
    const { g, w, h } = prep(this.jit), p = this.pad, d = this.data;
    g.font = '11px "Segoe UI", system-ui, sans-serif'; g.textBaseline = 'middle';
    g.fillStyle = css('--mute'); g.textAlign = 'right'; g.fillText('jitter', p.l - 6, h / 2);
    if (!d?.buckets?.length) return;
    const pw = w - p.l - p.r, span = d.to - d.from;
    const maxJ = Math.max(1, ...d.buckets.map(b => b[6] ?? 0));
    const bw = Math.max(1.5, d.bucketMs / span * pw);
    g.fillStyle = css('--accent'); g.globalAlpha = .65;
    for (const b of d.buckets) {
      if (b[6] == null) continue;
      const hh = Math.max(1, (h - 8) * b[6] / maxJ);
      g.fillRect(p.l + (b[0] - d.from) / span * pw, h - 4 - hh, bw, hh);
    }
    g.globalAlpha = 1; g.fillStyle = css('--mute'); g.textAlign = 'left'; g.fillText(fmtMs(maxJ) + ' ms', p.l + 4, 8);
  }

  /** Renders the timeline (and jitter strip) with a title into a PNG blob. */
  async toPng(title) {
    const a = this.main, b = this.jit, dpr = window.devicePixelRatio || 1;
    const off = document.createElement('canvas'); const head = 30 * dpr;
    off.width = a.width; off.height = a.height + (b ? b.height : 0) + head;
    const g = off.getContext('2d');
    g.fillStyle = css('--panel') || '#fff'; g.fillRect(0, 0, off.width, off.height);
    g.fillStyle = css('--ink'); g.font = `${14 * dpr}px "Segoe UI", sans-serif`; g.textBaseline = 'middle';
    g.fillText(title, 12 * dpr, head / 2);
    g.drawImage(a, 0, head); if (b) g.drawImage(b, 0, head + a.height);
    return new Promise(res => off.toBlob(res, 'image/png'));
  }
}

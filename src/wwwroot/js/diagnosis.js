import { esc, fmtMs, fmtPct } from './util.js';

const SIDE = {
  none: ['✔', 'good', 'Your connection looks fine'],
  yours: ['✖', 'bad', 'The problem is on your side'],
  isp: ['✖', 'bad', 'The problem is your ISP'],
  internet: ['⚠', 'warn', 'The problem is on the internet route'],
  server: ['⚠', 'warn', 'It is the server, not you'],
};

/** Headline icon, colour class and title for a diagnosis result. */
export function headline(d) {
  if (!d || d.code === 'insufficient') return ['…', '', 'Collecting data…'];
  if (d.code === 'burst') return ['⚠', 'warn', 'A short loss burst — clean now'];
  if (d.code === 'no_response') return ['⚠', 'warn', 'Nothing is answering'];
  if (d.code === 'latency') return ['⚠', d.status === 'bad' ? 'bad' : 'warn', 'Latency is high'];
  const [icon, cls, title] = SIDE[d.side] || ['…', '', 'Checking…'];
  // jitter without loss on your side is worth a warning, not an alarm
  return [icon, d.status === 'warn' && cls === 'bad' ? 'warn' : cls, title];
}

export function sideChip(d) {
  const [, cls, title] = headline(d);
  return `<span class="chip ${cls}">${esc(title)}</span>`;
}

const STATUS_NAME = { good: 'OK', warn: 'Unstable', bad: 'Problem', unknown: 'No data' };

/** The path "You → router → ISP → internet → server" with the culprit segment outlined. */
export function pathStrip(d) {
  if (!d?.segments?.length) return '<div class="mute">The path appears once the first traces finish.</div>';
  const nodes = d.segments.map(s => `<div class="node ${s.status} ${s.culprit ? 'culprit' : ''}" title="${esc(STATUS_NAME[s.status] || '')}">
      <b>${esc(s.name)}</b><span>${s.fromHop === s.toHop ? 'hop ' + s.fromHop : `hops ${s.fromHop}–${s.toHop}`}</span>
      <span>${s.avg == null ? 'no replies' : fmtMs(s.avg) + ' ms'} · ${fmtPct(s.lossPct)} loss</span></div>`);
  return `<div class="pathstrip"><div class="node you"><b>You</b><span>this PC</span></div>${nodes.map(n => `<div class="arrow">→</div>${n}`).join('')}</div>`;
}

/** Large verdict card. */
export function verdictCard(d, { advice = true, title } = {}) {
  const [icon, cls, head] = headline(d);
  const ev = (d?.evidence || []).map(e => `<li>${esc(e)}</li>`).join('');
  const adv = advice && d?.code && !['ok', 'insufficient'].includes(d.code) ? (d.advice || []).map(a => `<li>${esc(a)}</li>`).join('') : '';
  return `<div class="panel verdict ${cls}"><div class="ico" aria-hidden="true">${icon}</div><div class="grow">
    ${title ? `<div class="mute" style="font-size:12px">${esc(title)}</div>` : ''}
    <h2>${esc(head)}</h2><div>${esc(d?.headline || '')}</div>
    ${ev ? `<ul class="mute">${ev}</ul>` : ''}
    ${adv ? `<details style="margin-top:8px" ${d.status === 'bad' ? 'open' : ''}><summary>What you can do</summary><ul>${adv}</ul></details>` : ''}
    ${d?.confidence && d.code !== 'insufficient' ? `<div class="mute" style="font-size:12px;margin-top:6px">Confidence: ${esc(d.confidence)} · ${d.samples} samples${d.mos ? ' · MOS ' + d.mos : ''}</div>` : ''}
  </div></div>`;
}

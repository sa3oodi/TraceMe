/** Alert sounds synthesised with WebAudio, so no audio files have to ship with the app. */
let ctx = null;
let enabled = true;
export const SOUNDS = ['sonar', 'bell', 'buzzer', 'goblet', 'tibetan'];

export function setSoundEnabled(v) { enabled = v; }
export function unlockAudio() {
  try { ctx ??= new (window.AudioContext || window.webkitAudioContext)(); if (ctx.state === 'suspended') ctx.resume(); } catch { /* no audio */ }
}
addEventListener('pointerdown', unlockAudio, { once: true });
addEventListener('keydown', unlockAudio, { once: true });

function tone(freq, start, dur, type = 'sine', gain = 0.25, endFreq) {
  const o = ctx.createOscillator(), g = ctx.createGain();
  o.type = type; o.frequency.setValueAtTime(freq, ctx.currentTime + start);
  if (endFreq) o.frequency.exponentialRampToValueAtTime(endFreq, ctx.currentTime + start + dur);
  g.gain.setValueAtTime(0.0001, ctx.currentTime + start);
  g.gain.exponentialRampToValueAtTime(gain, ctx.currentTime + start + 0.02);
  g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + start + dur);
  o.connect(g).connect(ctx.destination); o.start(ctx.currentTime + start); o.stop(ctx.currentTime + start + dur + 0.05);
}

export function playSound(name = 'sonar') {
  if (!enabled) return false;
  unlockAudio();
  if (!ctx || ctx.state !== 'running') return false;
  switch (name) {
    case 'bell': tone(880, 0, 1.4, 'sine', 0.25); tone(1760, 0, 0.9, 'sine', 0.1); tone(2640, 0, 0.5, 'sine', 0.05); break;
    case 'buzzer': tone(160, 0, 0.18, 'square', 0.12); tone(160, 0.25, 0.18, 'square', 0.12); tone(160, 0.5, 0.18, 'square', 0.12); break;
    case 'goblet': tone(660, 0, 0.5, 'triangle', 0.25); tone(990, 0.12, 0.8, 'triangle', 0.18); break;
    case 'tibetan': tone(220, 0, 2.2, 'sine', 0.3); tone(332, 0, 1.6, 'sine', 0.12); break;
    default: tone(1200, 0, 1.0, 'sine', 0.25, 700); tone(1200, 0.55, 0.8, 'sine', 0.12, 700); // sonar
  }
  return true;
}

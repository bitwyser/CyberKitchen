/*
   totp.js - TOTP / HOTP Authenticator (RFC 6238 / RFC 4226)
   Generate 2FA codes from a shared secret (Base32/Hex/UTF-8), SHA-1/256/512,
   6-8 digits. Time-based mode shows a live countdown to the next code;
   counter-based mode uses an explicit counter. Web Crypto HMAC, offline.
*/
(function () {
  'use strict';
  var ENC = new TextEncoder();
  var B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function hexToBytes(h) { h = h.replace(/[^0-9a-fA-F]/g, ''); if (h.length % 2) h = '0' + h; var a = new Uint8Array(h.length / 2); for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
  function base32ToBytes(s) {
    s = s.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
    var out = [], buf = 0, bits = 0;
    for (var i = 0; i < s.length; i++) { var v = B32.indexOf(s[i]); if (v < 0) throw new Error('Invalid Base32 character: ' + s[i]); buf = (buf << 5) | v; bits += 5; if (bits >= 8) { out.push((buf >>> (bits - 8)) & 255); bits -= 8; } }
    return new Uint8Array(out);
  }
  function bytesToBase32(b) {
    var r = '', buf = 0, bits = 0;
    for (var i = 0; i < b.length; i++) { buf = (buf << 8) | b[i]; bits += 8; while (bits >= 5) { r += B32[(buf >>> (bits - 5)) & 31]; bits -= 5; } }
    if (bits) r += B32[(buf << (5 - bits)) & 31];
    while (r.length % 8) r += '=';
    return r;
  }
  function secretBytes(v, fmt) { v = (v || '').trim(); if (!v) return null; if (fmt === 'hex') return hexToBytes(v); if (fmt === 'utf8') return ENC.encode(v); return base32ToBytes(v); }

  // RFC 4226 HMAC-based one-time password; returns Promise<string of `digits` chars>
  function hotp(keyBytes, counter, algo, digits) {
    var buf = new Uint8Array(8), c = counter;
    for (var i = 7; i >= 0; i--) { buf[i] = c & 0xff; c = Math.floor(c / 256); }
    return crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: { name: algo } }, false, ['sign'])
      .then(function (k) { return crypto.subtle.sign('HMAC', k, buf); })
      .then(function (sig) {
        var h = new Uint8Array(sig), off = h[h.length - 1] & 0x0f;
        var bin = ((h[off] & 0x7f) << 24) | ((h[off + 1] & 0xff) << 16) | ((h[off + 2] & 0xff) << 8) | (h[off + 3] & 0xff);
        var code = (bin % Math.pow(10, digits)).toString();
        while (code.length < digits) code = '0' + code;
        return code;
      });
  }

  function b64uEnc(str) { var b = ENC.encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  var I_CLOCK = '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>';
  var I_KEY = '<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3M17 6l3 0 0 3M14 9l2 2"/>';
  var I_SHUF = '<path d="M18 4l3 3-3 3M21 7H8a4 4 0 0 0-4 4M6 20l-3-3 3-3M3 17h12a4 4 0 0 0 4-4"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  function rndBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }

  CK.registerTool('totp', function (root, ctx) {
    var ui = CK.ui, el = CK.el, mode = 'totp';
    function o(a) { return { value: a[0], label: a[1] }; }

    root.appendChild(ui.head('TOTP / HOTP Authenticator', 'RFC 6238'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_CLOCK);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(I_SHUF, 'Random secret', doRandom));
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    // Left: 2x2 of Mode / Algorithm over Digits / (Period or Counter). Right: secret format.
    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col2' });
    var colR = el('div', { class: 'col' });

    var modeSel = ui.select([['totp', 'Time-based (TOTP)'], ['hotp', 'Counter-based (HOTP)']].map(o), function (v) { mode = v; applyMode(); regen(); }, 'totp');
    var algoSel = ui.select([['SHA-1', 'SHA-1'], ['SHA-256', 'SHA-256'], ['SHA-512', 'SHA-512']].map(o), function () { updateSel(); regen(); }, 'SHA-1');
    var digitsSel = ui.select([['6', '6 digits'], ['7', '7 digits'], ['8', '8 digits']].map(o), function () { updateSel(); regen(); }, '6');

    var periodInput = el('input', { class: 'inp sm', type: 'number', min: '5', max: '300', value: '30' });
    periodInput.addEventListener('input', function () { updateSel(); regen(); });
    var periodField = ui.field('Time step (seconds)', periodInput);
    var counterInput = el('input', { class: 'inp sm', type: 'number', min: '0', value: '0' });
    counterInput.addEventListener('input', function () { updateSel(); regen(); });
    var counterField = ui.field('Counter', counterInput); counterField.style.display = 'none';
    var stepCell = el('div'); stepCell.appendChild(periodField); stepCell.appendChild(counterField);

    colL.appendChild(ui.field('Mode', modeSel)); colL.appendChild(ui.field('Algorithm', algoSel));
    colL.appendChild(ui.field('Digits', digitsSel)); colL.appendChild(stepCell);

    var fmtSel = ui.select([['base32', 'Base32'], ['hex', 'Hexadecimal'], ['utf8', 'UTF-8']].map(o), function () { regen(); }, 'base32');
    colR.appendChild(ui.field('Secret format', fmtSel));

    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'SHARED SECRET', icon: I_KEY, placeholder: 'Base32 secret, e.g. JBSWY3DPEHPK3PXP', primaries: [{ label: 'Generate', cls: 'enc', onClick: doGenerate }], actions: ['copy', 'paste', 'clear'], onInput: regen });
    var outP = ui.textPanel({ title: 'ONE-TIME CODE', icon: I_CLOCK, placeholder: 'Code appears here...', readonly: true, actions: ['copy'] });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    // Live countdown: progress bar + seconds-remaining label, placed above the
    // code so it does not collide with the char-count pill in the corner
    var barWrap = el('div', { style: 'display:flex; align-items:center; gap:10px;' });
    var bar = el('div', { class: 'strength' }); bar.style.flex = '1'; var barSpan = el('span'); bar.appendChild(barSpan);
    var secLabel = el('span', { style: "font-family:'SF Mono','Consolas',monospace; font-size:12px; font-weight:800; min-width:38px; text-align:right;" });
    barWrap.appendChild(bar); barWrap.appendChild(secLabel);
    outP.panel.insertBefore(barWrap, outP.ta);

    function algo() { return algoSel.value; }
    function digits() { return +digitsSel.value; }
    function period() { return Math.max(5, +periodInput.value || 30); }

    function applyMode() {
      var t = mode === 'totp';
      periodField.style.display = t ? '' : 'none';
      counterField.style.display = t ? 'none' : '';
      barWrap.style.display = t ? '' : 'none';
      updateSel();
    }
    function updateSel() {
      var base = (mode === 'totp' ? 'TOTP' : 'HOTP') + ' · ' + algo() + ' · ' + digits() + ' digits';
      ui.setSel(strip, base, mode === 'totp' ? period() + 's' : 'HOTP',
        mode === 'totp' ? 'Time-based one-time password, ' + period() + '-second step' : 'Counter-based one-time password, counter ' + (+counterInput.value || 0));
    }

    var lastCounter = null;
    // Recompute and paint the code (async). For TOTP called on counter rollover; for HOTP on demand.
    function regen() {
      var bytes;
      try { bytes = secretBytes(inP.ta.value, fmtSel.value); } catch (e) { outP.ta.value = ''; return; }
      if (!bytes || !bytes.length) { outP.ta.value = ''; return; }
      var counter = mode === 'totp' ? Math.floor(Date.now() / 1000 / period()) : (+counterInput.value || 0);
      return hotp(bytes, counter, algo(), digits()).then(function (code) { outP.ta.value = code; }).catch(function () { outP.ta.value = ''; });
    }
    function doGenerate() {
      var bytes;
      try { bytes = secretBytes(inP.ta.value, fmtSel.value); } catch (e) { ctx.toast(e.message, 'error'); return; }
      if (!bytes || !bytes.length) { ctx.toast('Enter a secret first', 'warn'); return; }
      lastCounter = null; // force a repaint on the next tick too
      return regen().then(function () { ctx.toast('Code generated', 'success'); });
    }
    function doRandom() {
      inP.ta.value = bytesToBase32(rndBytes(20));
      fmtSel.value = 'base32';
      regen(); ctx.toast('Random secret generated (Base32)', 'success');
    }
    function doShare() { CK.copy(location.href.split('#')[0] + '#tool=totp&s=' + b64uEnc(JSON.stringify({ m: mode, a: algo(), d: digitsSel.value, p: periodInput.value, c: counterInput.value, f: fmtSel.value, sec: inP.ta.value }))); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; mode = 'totp'; modeSel.value = 'totp'; algoSel.value = 'SHA-1'; digitsSel.value = '6'; periodInput.value = '30'; counterInput.value = '0'; fmtSel.value = 'base32'; applyMode(); ctx.toast('Reset complete', 'success'); }

    // Live tick: keep the countdown current and roll the code over on each new step
    setInterval(function () {
      if (root.hidden || mode !== 'totp') return;
      // Only run the countdown once a code exists (a secret has been entered)
      if (!inP.ta.value.trim() || !outP.ta.value) { barSpan.style.width = '0%'; secLabel.textContent = ''; return; }
      var p = period(), now = Date.now() / 1000;
      var counter = Math.floor(now / p), remain = Math.ceil(p - (now % p));
      var color = remain <= 5 ? 'var(--err)' : remain <= 10 ? 'var(--warn)' : 'var(--acc)';
      barSpan.style.width = Math.max(0, Math.min(100, (remain / p) * 100)) + '%';
      barSpan.style.background = color;
      secLabel.textContent = remain + 's';
      secLabel.style.color = color;
      strip.desc.textContent = 'Valid for ' + remain + 's of ' + p + 's · ' + algo() + ' · ' + digits() + ' digits';
      if (counter !== lastCounter) { lastCounter = counter; regen(); }
    }, 250);

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); mode = st.m || 'totp'; modeSel.value = mode; algoSel.value = st.a || 'SHA-1'; digitsSel.value = st.d || '6'; periodInput.value = st.p || '30'; counterInput.value = st.c || '0'; fmtSel.value = st.f || 'base32'; inP.ta.value = st.sec || ''; } catch (e) { } }
    applyMode(); regen();
  });
})();

/*
   aes.js - AES Encrypt / Decrypt (crypto-js, full parity)
   Key + IV with UTF-8/Hex/Base64 formats and per-field random generators,
   modes CBC/ECB/CFB/OFB/CTR, 5 padding schemes, format selectors, Share URL.
*/
(function () {
  'use strict';
  var C = window.CryptoJS;

  function toWA(str, fmt) {
    if (!str) return C.lib.WordArray.create();
    if (fmt === 'hex') return C.enc.Hex.parse(str.replace(/\s/g, ''));
    if (fmt === 'base64') return C.enc.Base64.parse(str.trim());
    return C.enc.Utf8.parse(str);
  }
  function waToStr(wa, fmt) {
    if (fmt === 'hex') return wa.toString(C.enc.Hex);
    if (fmt === 'base64') return wa.toString(C.enc.Base64);
    return wa.toString(C.enc.Utf8);
  }
  function keyBytes(val, fmt) {
    if (!val) return 0;
    if (fmt === 'hex') return val.replace(/\s/g, '').length / 2;
    if (fmt === 'base64') { var s = val.replace(/\s/g, ''); var pad = /==$/.test(s) ? 2 : /=$/.test(s) ? 1 : 0; return Math.floor(s.length * 3 / 4) - pad; }
    return new TextEncoder().encode(val).length;
  }
  var MODES = { CBC: C.mode.CBC, ECB: C.mode.ECB, CFB: C.mode.CFB, OFB: C.mode.OFB, CTR: C.mode.CTR };
  var PADS = { Pkcs7: C.pad.Pkcs7, ZeroPadding: C.pad.ZeroPadding, Iso10126: C.pad.Iso10126, AnsiX923: C.pad.Ansix923, NoPadding: C.pad.NoPadding };

  var I_KEY = '<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3M17 6l3 0 0 3M14 9l2 2"/>';
  var I_LOCK = '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/>';
  var I_SHUF = '<path d="M18 4l3 3-3 3M21 7H8a4 4 0 0 0-4 4M6 20l-3-3 3-3M3 17h12a4 4 0 0 0 4-4"/>';
  var I_SWAP = '<path d="M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';
  var I_CHECK = '<path d="M20 6 9 17l-5-5"/>';
  var I_DETECT = '<path d="m12 3 1.9 4.6L18 9l-4.1 1.4L12 15l-1.9-4.6L6 9l4.1-1.4zM19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9z"/>';

  function detectFmt(s) {
    var c = s.trim(), clean = c.replace(/\s/g, '');
    if (/^[0-9a-fA-F\s]+$/.test(c) && clean.length % 2 === 0 && clean.length >= 2) return 'hex';
    if (/^[A-Za-z0-9+/=\s]+$/.test(c) && clean.length % 4 === 0 && clean.length >= 4) { try { atob(clean); return 'base64'; } catch (e) { } }
    return 'utf8';
  }
  function fmtByteLen(s, fmt) {
    if (fmt === 'hex') return s.replace(/[^0-9a-fA-F]/g, '').length / 2;
    if (fmt === 'base64') { try { return atob(s.trim().replace(/\s/g, '')).length; } catch (e) { return null; } }
    return new TextEncoder().encode(s).length;
  }
  function fmtLabelOf(fmt) { return fmt === 'hex' ? 'Hexadecimal' : fmt === 'base64' ? 'Base64' : 'UTF-8'; }

  function rndBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }
  function bytesToFmt(bytes, fmt) {
    if (fmt === 'hex') { var h = ''; for (var i = 0; i < bytes.length; i++) h += bytes[i].toString(16).padStart(2, '0'); return h; }
    if (fmt === 'base64') { var s = ''; for (var j = 0; j < bytes.length; j++) s += String.fromCharCode(bytes[j]); return btoa(s); }
    var u = ''; for (var k = 0; k < bytes.length; k++) u += String.fromCharCode(33 + (bytes[k] % 94)); return u; // printable UTF-8
  }
  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  CK.registerTool('aes', function (root, ctx) {
    var ui = CK.ui, el = CK.el;

    root.appendChild(ui.head('AES Encrypt / Decrypt', 'crypto-js'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_KEY);
    strip.acts.appendChild(ui.iconBtn(I_CHECK, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(I_DETECT, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(I_SWAP, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    function fmtOpt(v) { return { value: v, label: v === 'utf8' ? 'UTF-8' : v === 'hex' ? 'Hexadecimal' : 'Base64' }; }
    function o(a) { return { value: a[0], label: a[1] }; }

    // Main grid: left column is a 2x2 sub-grid (Key/Mode over IV/Padding); right column is the formats
    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col2 kv-mp' });
    var colR = el('div', { class: 'col' });

    var keyInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Encryption key' });
    var keyFmt = ui.select(['utf8', 'hex', 'base64'].map(fmtOpt), function () { updateSel(); }, 'utf8');
    var keyGen = ui.iconBtn(I_SHUF, 'Random key', function () { keyInput.value = bytesToFmt(rndBytes(32), keyFmt.value); updateSel(); });
    var keyWrap = el('div', { style: 'display:flex; gap:5px; align-items:center;' });
    keyInput.style.flex = '1'; keyFmt.style.width = 'auto'; keyWrap.appendChild(keyInput); keyWrap.appendChild(keyFmt); keyWrap.appendChild(keyGen);
    var keyField = ui.field('Key', keyWrap);

    var ivInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Initialization vector (16 bytes)' });
    var ivFmt = ui.select(['utf8', 'hex', 'base64'].map(fmtOpt), null, 'hex');
    var ivGen = ui.iconBtn(I_SHUF, 'Random initialization vector', function () { ivInput.value = bytesToFmt(rndBytes(16), ivFmt.value); });
    var ivWrap = el('div', { style: 'display:flex; gap:5px; align-items:center;' });
    ivInput.style.flex = '1'; ivFmt.style.width = 'auto'; ivWrap.appendChild(ivInput); ivWrap.appendChild(ivFmt); ivWrap.appendChild(ivGen);
    var ivField = ui.field('Initialization Vector', ivWrap);

    var modeSel = ui.select([['CBC', 'Cipher Block Chaining'], ['ECB', 'Electronic Codebook'], ['CFB', 'Cipher Feedback'], ['OFB', 'Output Feedback'], ['CTR', 'Counter']].map(o), function () { updateSel(); }, 'CBC');
    var padSel = ui.select([['Pkcs7', 'PKCS#7'], ['ZeroPadding', 'Zero padding'], ['Iso10126', 'ISO 10126'], ['AnsiX923', 'ANSI X9.23'], ['NoPadding', 'No padding']].map(o), null, 'Pkcs7');
    var padF = ui.field('Padding', padSel);
    var ptFmt = ui.select([['utf8', 'UTF-8'], ['base64', 'Base64'], ['hex', 'Hexadecimal']].map(o), null, 'utf8');
    var ctFmt = ui.select([['base64', 'Base64'], ['hex', 'Hexadecimal']].map(o), null, 'base64');
    // Left sub-grid, row-flow order: Key, Mode (row 1), IV, Padding (row 2)
    colL.appendChild(keyField); colL.appendChild(ui.field('Mode', modeSel));
    colL.appendChild(ivField); colL.appendChild(padF);
    // Right column: Input format, Output format
    colR.appendChild(ui.field('Input format', ptFmt));
    colR.appendChild(ui.field('Output format', ctFmt));

    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: I_KEY, placeholder: 'Plaintext to encrypt, or ciphertext to decrypt...', primaries: [{ label: 'Encrypt', cls: 'enc', onClick: doEncrypt }, { label: 'Decrypt', cls: 'dec', onClick: doDecrypt }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'input.txt' });
    var outP = ui.textPanel({ title: 'OUTPUT', icon: I_LOCK, placeholder: 'Result appears here...', actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'output.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearVerify() { outP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearVerify);
    outP.ta.addEventListener('input', clearVerify);

    keyInput.addEventListener('input', updateSel);
    function updateSel() {
      var kb = keyBytes(keyInput.value, keyFmt.value);
      var size = kb === 0 ? '256' : kb === 16 ? '128' : kb === 24 ? '192' : kb === 32 ? '256' : '?';
      var mode = modeSel.value;
      ivField.style.visibility = mode === 'ECB' ? 'hidden' : '';
      padF.style.visibility = /CFB|OFB|CTR/.test(mode) ? 'hidden' : '';
      ui.setSel(strip, 'AES-' + size + '-' + mode, kb ? kb + ' bytes' : 'default', size === '?' ? 'Key must be 16, 24, or 32 bytes for AES-128/192/256' : 'AES-' + size + ' in ' + mode + ' mode');
    }
    function opts() { var oo = { mode: MODES[modeSel.value], padding: PADS[padSel.value] }; if (modeSel.value !== 'ECB') oo.iv = toWA(ivInput.value, ivFmt.value); return oo; }
    function doEncrypt() {
      try {
        if (!keyInput.value) throw new Error('Key required');
        if (!inP.ta.value) throw new Error('Plaintext is empty');
        var kb = keyBytes(keyInput.value, keyFmt.value);
        if (kb !== 16 && kb !== 24 && kb !== 32) throw new Error('Key must be 16, 24, or 32 bytes (got ' + kb + ')');
        if (modeSel.value !== 'ECB' && !ivInput.value) throw new Error('IV required for ' + modeSel.value);
        var res = C.AES.encrypt(toWA(inP.ta.value, ptFmt.value), toWA(keyInput.value, keyFmt.value), opts());
        outP.ta.value = res.ciphertext.toString(ctFmt.value === 'hex' ? C.enc.Hex : C.enc.Base64);
        clearVerify(); ctx.toast('Encrypted (' + modeSel.value + ')', 'success');
      } catch (e) { ctx.toast(e.message, 'error'); }
    }
    function doDecrypt() {
      try {
        if (!keyInput.value) throw new Error('Key required');
        if (!inP.ta.value) throw new Error('Input is empty');
        var res = C.AES.decrypt({ ciphertext: toWA(inP.ta.value, ctFmt.value) }, toWA(keyInput.value, keyFmt.value), opts());
        if (res.sigBytes <= 0) throw new Error('wrong key, IV, mode or padding');
        var out = waToStr(res, ptFmt.value);
        if (!out && res.sigBytes > 0) throw new Error('decrypted bytes are not valid ' + ptFmt.value);
        outP.ta.value = out; clearVerify(); ctx.toast('Decrypted', 'success');
      } catch (e) { ctx.toast('Decryption failed: ' + e.message, 'error'); }
    }
    function doSwap() { inP.ta.value = outP.ta.value; outP.ta.value = ''; clearVerify(); ctx.toast('Output moved to input', 'success'); }
    function doVerify() {
      clearVerify();
      if (!keyInput.value) { ctx.toast('Key required', 'warn'); return; }
      var a = inP.ta.value, b = outP.ta.value;
      if (!a || !b) { ctx.toast('Both panels need content', 'warn'); return; }
      var kw = toWA(keyInput.value, keyFmt.value);
      function enc(src) { try { return C.AES.encrypt(toWA(src, ptFmt.value), kw, opts()).ciphertext.toString(ctFmt.value === 'hex' ? C.enc.Hex : C.enc.Base64); } catch (e) { return null; } }
      function dec(src) { try { var r = C.AES.decrypt({ ciphertext: toWA(src, ctFmt.value) }, kw, opts()); return r.sigBytes > 0 ? waToStr(r, ptFmt.value) : null; } catch (e) { return null; } }
      var match = (enc(a) === b.trim()) || (dec(a) === b) || (enc(b) === a.trim()) || (dec(b) === a);
      outP.ta.classList.add(match ? 'verify-match' : 'verify-fail');
      ctx.toast(match ? 'Match: input and output are a valid AES pair' : 'No match', match ? 'success' : 'error');
    }
    function doDetect() {
      var s = inP.ta.value.trim();
      if (!s) { ctx.toast('Enter data in the input first', 'warn'); return; }
      var fmt = detectFmt(s);
      ptFmt.value = fmt;
      if (fmt !== 'utf8') ctFmt.value = fmt;
      var len = fmtByteLen(s, fmt), guessed = '';
      if (fmt !== 'utf8' && len != null && len > 0) { modeSel.value = (len % 16 === 0) ? 'CBC' : 'CTR'; guessed = ', guessed ' + modeSel.value + ' mode (best-effort)'; }
      updateSel();
      ctx.toast('AES · detected ' + fmtLabelOf(fmt) + ' input' + guessed, 'success');
    }
    function doShare() { var st = { k: keyInput.value, kf: keyFmt.value, iv: ivInput.value, ivf: ivFmt.value, m: modeSel.value, p: padSel.value, cf: ctFmt.value, pf: ptFmt.value, pt: inP.ta.value, ct: outP.ta.value }; CK.copy(location.href.split('#')[0] + '#tool=aes&s=' + b64uEnc(JSON.stringify(st))); }
    function doReset() { keyInput.value = ''; ivInput.value = ''; inP.ta.value = ''; outP.ta.value = ''; keyFmt.value = 'utf8'; ivFmt.value = 'hex'; modeSel.value = 'CBC'; padSel.value = 'Pkcs7'; ctFmt.value = 'base64'; ptFmt.value = 'utf8'; updateSel(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); keyInput.value = st.k || ''; keyFmt.value = st.kf || 'utf8'; ivInput.value = st.iv || ''; ivFmt.value = st.ivf || 'hex'; modeSel.value = st.m || 'CBC'; padSel.value = st.p || 'Pkcs7'; ctFmt.value = st.cf || 'base64'; ptFmt.value = st.pf || 'utf8'; inP.ta.value = st.pt || ''; outP.ta.value = st.ct || ''; } catch (e) { } }
    updateSel();
  });
})();

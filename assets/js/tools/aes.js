/*
   aes.js - AES Encrypt / Decrypt (crypto-js, full parity)
   Raw key + IV with UTF-8/Hex/Base64 formats and random generators,
   modes CBC/ECB/CFB/OFB/CTR, 5 padding schemes, Base64/Hex output,
   UTF-8/Base64/Hex plaintext, Share URL.
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
  var I_GEN = '<path d="M16 3h5v5M21 3l-7 7M8 21H3v-5M3 21l7-7"/>';
  var I_SWAP = '<path d="M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  function rndHex(n) { var b = crypto.getRandomValues(new Uint8Array(n)), s = ''; for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; }
  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  CK.registerTool('aes', function (root, ctx) {
    var ui = CK.ui, el = CK.el;

    root.appendChild(ui.head('AES Encrypt / Decrypt', 'crypto-js'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_KEY);
    strip.acts.appendChild(ui.iconBtn(I_GEN, 'Random key', genKey));
    strip.acts.appendChild(ui.iconBtn(I_SWAP, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var form = el('div', { class: 'cfg-form' });
    // Key
    var keyInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Encryption key' });
    var keyFmt = ui.select(['utf8', 'hex', 'base64'].map(fmtOpt), function () { updateSel(); }, 'utf8');
    var keyGen = ui.miniBtn('Gen', function () { genKey(); });
    var keyWrap = el('div', { style: 'display:flex; gap:5px; align-items:center;' });
    keyInput.style.flex = '1'; keyFmt.style.width = 'auto'; keyWrap.appendChild(keyInput); keyWrap.appendChild(keyFmt); keyWrap.appendChild(keyGen);
    var keyField = ui.field('Key', keyWrap); keyField.style.flex = '2'; keyField.style.minWidth = '260px';
    form.appendChild(keyField);
    // IV
    var ivInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'IV (16 bytes)' });
    var ivFmt = ui.select(['utf8', 'hex', 'base64'].map(fmtOpt), null, 'hex');
    var ivGen = ui.miniBtn('Gen', function () { ivInput.value = rndHex(16); ivFmt.value = 'hex'; });
    var ivWrap = el('div', { style: 'display:flex; gap:5px; align-items:center;' });
    ivInput.style.flex = '1'; ivFmt.style.width = 'auto'; ivWrap.appendChild(ivInput); ivWrap.appendChild(ivFmt); ivWrap.appendChild(ivGen);
    var ivField = ui.field('IV', ivWrap); ivField.style.flex = '2'; ivField.style.minWidth = '240px';
    form.appendChild(ivField);
    // Mode / Padding / formats
    var modeSel = ui.select([['CBC', 'CBC'], ['ECB', 'ECB'], ['CFB', 'CFB'], ['OFB', 'OFB'], ['CTR', 'CTR']].map(function (a) { return { value: a[0], label: a[1] }; }), function () { updateSel(); }, 'CBC');
    form.appendChild(ui.field('Mode', modeSel));
    var padSel = ui.select([['Pkcs7', 'PKCS#7'], ['ZeroPadding', 'Zero'], ['Iso10126', 'ISO 10126'], ['AnsiX923', 'ANSI X9.23'], ['NoPadding', 'No padding']].map(function (a) { return { value: a[0], label: a[1] }; }), null, 'Pkcs7');
    form.appendChild(ui.field('Padding', padSel));
    var ctFmt = ui.select([['base64', 'Base64'], ['hex', 'Hex']].map(function (a) { return { value: a[0], label: a[1] }; }), null, 'base64');
    form.appendChild(ui.field('Ciphertext', ctFmt));
    var ptFmt = ui.select([['utf8', 'UTF-8'], ['base64', 'Base64'], ['hex', 'Hex']].map(function (a) { return { value: a[0], label: a[1] }; }), null, 'utf8');
    form.appendChild(ui.field('Plaintext', ptFmt));
    cfg.appendChild(form);
    root.appendChild(cfg);

    function fmtOpt(v) { return { value: v, label: v === 'utf8' ? 'UTF-8' : v === 'hex' ? 'Hex' : 'Base64' }; }

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'PLAINTEXT', icon: I_KEY, placeholder: 'Text to encrypt...', primary: { label: 'Encrypt', cls: 'enc', onClick: doEncrypt }, actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'plaintext.txt' });
    var outP = ui.textPanel({ title: 'CIPHERTEXT', icon: I_LOCK, placeholder: 'Ciphertext, or paste to decrypt...', primary: { label: 'Decrypt', cls: 'dec', onClick: doDecrypt }, actions: ['copy', 'clear', 'download'], downloadName: 'ciphertext.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    keyInput.addEventListener('input', updateSel);
    function genKey() { keyInput.value = rndHex(32); keyFmt.value = 'hex'; updateSel(); }
    function updateSel() {
      var kb = keyBytes(keyInput.value, keyFmt.value);
      var size = kb === 16 ? '128' : kb === 24 ? '192' : kb === 32 ? '256' : '?';
      var mode = modeSel.value;
      ivField.style.display = mode === 'ECB' ? 'none' : '';
      padField(); // toggle padding visibility for stream modes
      ui.setSel(strip, 'AES-' + size + '-' + mode, kb ? kb + ' bytes' : 'no key', size === '?' ? 'Key must be 16, 24, or 32 bytes for AES-128/192/256' : 'AES-' + size + ' in ' + mode + ' mode');
    }
    function padField() {
      var streamMode = /CFB|OFB|CTR/.test(modeSel.value);
      padSel.parentNode.style.display = streamMode ? 'none' : '';
    }
    function opts() {
      var o = { mode: MODES[modeSel.value], padding: PADS[padSel.value] };
      if (modeSel.value !== 'ECB') o.iv = toWA(ivInput.value, ivFmt.value);
      return o;
    }
    function doEncrypt() {
      try {
        if (!keyInput.value) throw new Error('Key required');
        if (!inP.ta.value) throw new Error('Plaintext is empty');
        var kb = keyBytes(keyInput.value, keyFmt.value);
        if (kb !== 16 && kb !== 24 && kb !== 32) throw new Error('Key must be 16, 24, or 32 bytes (got ' + kb + ')');
        if (modeSel.value !== 'ECB' && !ivInput.value) throw new Error('IV required for ' + modeSel.value);
        var res = C.AES.encrypt(toWA(inP.ta.value, ptFmt.value), toWA(keyInput.value, keyFmt.value), opts());
        outP.ta.value = res.ciphertext.toString(ctFmt.value === 'hex' ? C.enc.Hex : C.enc.Base64);
        ctx.toast('Encrypted (' + modeSel.value + ')', 'success');
      } catch (e) { ctx.toast(e.message, 'error'); }
    }
    function doDecrypt() {
      try {
        if (!keyInput.value) throw new Error('Key required');
        if (!outP.ta.value) throw new Error('Ciphertext is empty');
        var ctWA = toWA(outP.ta.value, ctFmt.value);
        var res = C.AES.decrypt({ ciphertext: ctWA }, toWA(keyInput.value, keyFmt.value), opts());
        var out = waToStr(res, ptFmt.value);
        if (!out && res.sigBytes > 0) throw new Error('Decrypted bytes are not valid ' + ptFmt.value);
        if (res.sigBytes <= 0) throw new Error('Decryption failed: wrong key, IV, mode or padding');
        inP.ta.value = out;
        ctx.toast('Decrypted', 'success');
      } catch (e) { ctx.toast('Decryption failed: ' + e.message, 'error'); }
    }
    function doSwap() { var a = inP.ta.value; inP.ta.value = outP.ta.value; outP.ta.value = a; ctx.toast('Panels swapped', 'success'); }
    function doShare() {
      var st = { k: keyInput.value, kf: keyFmt.value, iv: ivInput.value, ivf: ivFmt.value, m: modeSel.value, p: padSel.value, cf: ctFmt.value, pf: ptFmt.value, pt: inP.ta.value, ct: outP.ta.value };
      CK.copy(location.href.split('#')[0] + '#tool=aes&s=' + b64uEnc(JSON.stringify(st)));
    }
    function doReset() { keyInput.value = ''; ivInput.value = ''; inP.ta.value = ''; outP.ta.value = ''; keyFmt.value = 'utf8'; ivFmt.value = 'hex'; modeSel.value = 'CBC'; padSel.value = 'Pkcs7'; ctFmt.value = 'base64'; ptFmt.value = 'utf8'; updateSel(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); keyInput.value = st.k || ''; keyFmt.value = st.kf || 'utf8'; ivInput.value = st.iv || ''; ivFmt.value = st.ivf || 'hex'; modeSel.value = st.m || 'CBC'; padSel.value = st.p || 'Pkcs7'; ctFmt.value = st.cf || 'base64'; ptFmt.value = st.pf || 'utf8'; inP.ta.value = st.pt || ''; outP.ta.value = st.ct || ''; } catch (e) { } }
    updateSel();

    return {
      reset: doReset,
      onKey: function (e) { if (!(e.ctrlKey || e.metaKey)) return; var k = String(e.key).toLowerCase(); if (k === 'e') { e.preventDefault(); doEncrypt(); } else if (k === 'd') { e.preventDefault(); doDecrypt(); } }
    };
  });
})();

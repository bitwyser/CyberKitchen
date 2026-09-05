/*
   kdf.js - Key Derivation (PBKDF2 / scrypt)
   Turn a password + salt into a derived key. PBKDF2 uses Web Crypto
   (SHA-1/256/384/512). scrypt (RFC 7914) is implemented here, using crypto-js
   for the internal PBKDF2-HMAC-SHA256 and hand-written Salsa20/8 mixing.
   Fully offline.
*/
(function () {
  'use strict';
  var ENC = new TextEncoder();
  var C = window.CryptoJS;

  function hexToBytes(h) { h = h.replace(/[^0-9a-fA-F]/g, ''); if (h.length % 2) h = '0' + h; var a = new Uint8Array(h.length / 2); for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
  function b64ToBytes(s) { s = s.trim().replace(/\s/g, ''); var bin = atob(s), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  function toHex(b) { var s = ''; for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; }
  function toB64(b) { var s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
  function inputBytes(v, fmt) { v = v || ''; if (fmt === 'hex') return hexToBytes(v); if (fmt === 'base64') return b64ToBytes(v); return ENC.encode(v); }
  function rndBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }

  /* ---- crypto-js bridges for scrypt's internal PBKDF2-HMAC-SHA256 ---- */
  function waFromBytes(bytes) { var words = []; for (var i = 0; i < bytes.length; i++) words[i >>> 2] |= (bytes[i] & 0xff) << (24 - (i % 4) * 8); return C.lib.WordArray.create(words, bytes.length); }
  function bytesFromWa(wa) { var b = new Uint8Array(wa.sigBytes); for (var i = 0; i < wa.sigBytes; i++) b[i] = (wa.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff; return b; }
  function pbkdf2Sha256(passBytes, saltBytes, iterations, dkLen) {
    var dk = C.PBKDF2(waFromBytes(passBytes), waFromBytes(saltBytes), { keySize: Math.ceil(dkLen / 4), iterations: iterations, hasher: C.algo.SHA256 });
    return bytesFromWa(dk).subarray(0, dkLen);
  }

  /* ---- scrypt core (RFC 7914) ---- */
  function bytesToWords(b) { var dv = new DataView(b.buffer, b.byteOffset, b.byteLength), w = new Uint32Array(b.length / 4); for (var i = 0; i < w.length; i++) w[i] = dv.getUint32(i * 4, true); return w; }
  function wordsToBytes(w) { var b = new Uint8Array(w.length * 4), dv = new DataView(b.buffer); for (var i = 0; i < w.length; i++) dv.setUint32(i * 4, w[i], true); return b; }
  function R(a, b) { return (a << b) | (a >>> (32 - b)); }
  function salsa20_8(B) {
    var x = B.slice(), i;
    for (i = 8; i > 0; i -= 2) {
      x[4] ^= R(x[0] + x[12], 7); x[8] ^= R(x[4] + x[0], 9); x[12] ^= R(x[8] + x[4], 13); x[0] ^= R(x[12] + x[8], 18);
      x[9] ^= R(x[5] + x[1], 7); x[13] ^= R(x[9] + x[5], 9); x[1] ^= R(x[13] + x[9], 13); x[5] ^= R(x[1] + x[13], 18);
      x[14] ^= R(x[10] + x[6], 7); x[2] ^= R(x[14] + x[10], 9); x[6] ^= R(x[2] + x[14], 13); x[10] ^= R(x[6] + x[2], 18);
      x[3] ^= R(x[15] + x[11], 7); x[7] ^= R(x[3] + x[15], 9); x[11] ^= R(x[7] + x[3], 13); x[15] ^= R(x[11] + x[7], 18);
      x[1] ^= R(x[0] + x[3], 7); x[2] ^= R(x[1] + x[0], 9); x[3] ^= R(x[2] + x[1], 13); x[0] ^= R(x[3] + x[2], 18);
      x[6] ^= R(x[5] + x[4], 7); x[7] ^= R(x[6] + x[5], 9); x[4] ^= R(x[7] + x[6], 13); x[5] ^= R(x[4] + x[7], 18);
      x[11] ^= R(x[10] + x[9], 7); x[8] ^= R(x[11] + x[10], 9); x[9] ^= R(x[8] + x[11], 13); x[10] ^= R(x[9] + x[8], 18);
      x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9); x[14] ^= R(x[13] + x[12], 13); x[15] ^= R(x[14] + x[13], 18);
    }
    for (i = 0; i < 16; i++) B[i] = (B[i] + x[i]) >>> 0;
  }
  function blockMix(B, r) {
    var X = new Uint32Array(16); X.set(B.subarray((2 * r - 1) * 16, (2 * r - 1) * 16 + 16));
    var Y = new Uint32Array(B.length), i, k;
    for (i = 0; i < 2 * r; i++) {
      for (k = 0; k < 16; k++) X[k] ^= B[i * 16 + k];
      salsa20_8(X);
      Y.set(X, i * 16);
    }
    for (i = 0; i < r; i++) for (k = 0; k < 16; k++) { B[i * 16 + k] = Y[(i * 2) * 16 + k]; B[(r + i) * 16 + k] = Y[(i * 2 + 1) * 16 + k]; }
  }
  function romix(B, N, r) {
    var X = B.slice(), V = new Array(N), i, k;
    for (i = 0; i < N; i++) { V[i] = X.slice(); blockMix(X, r); }
    for (i = 0; i < N; i++) { var j = (X[(2 * r - 1) * 16] >>> 0) % N; for (k = 0; k < X.length; k++) X[k] ^= V[j][k]; blockMix(X, r); }
    B.set(X);
  }
  function scrypt(passBytes, saltBytes, N, r, p, dkLen) {
    var B = pbkdf2Sha256(passBytes, saltBytes, 1, p * 128 * r);
    var all = bytesToWords(B), wpb = 32 * r;
    for (var i = 0; i < p; i++) romix(all.subarray(i * wpb, (i + 1) * wpb), N, r);
    return pbkdf2Sha256(passBytes, wordsToBytes(all), 1, dkLen);
  }

  function pbkdf2Web(passBytes, saltBytes, iterations, hash, dkLen) {
    return crypto.subtle.importKey('raw', passBytes, 'PBKDF2', false, ['deriveBits'])
      .then(function (k) { return crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: iterations, hash: hash }, k, dkLen * 8); })
      .then(function (buf) { return new Uint8Array(buf); });
  }

  function b64uEnc(str) { var b = ENC.encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  var I_KEY = '<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3M17 6l3 0 0 3M14 9l2 2"/>';
  var I_LOCK = '<path d="M6 10V7a6 6 0 0 1 12 0v3M5 10h14v10H5z"/>';
  var I_SHUF = '<path d="M18 4l3 3-3 3M21 7H8a4 4 0 0 0-4 4M6 20l-3-3 3-3M3 17h12a4 4 0 0 0 4-4"/>';
  var I_CHECK = '<path d="M20 6 9 17l-5-5"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';
  var ITERS = [100000, 310000, 600000];

  CK.registerTool('kdf', function (root, ctx) {
    var ui = CK.ui, el = CK.el, algo = 'pbkdf2';
    function o(a) { return { value: a[0], label: a[1] }; }

    root.appendChild(ui.head('Key Derivation', 'PBKDF2 / scrypt'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_KEY);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(I_CHECK, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'bc-left' });
    var colR = el('div', { class: 'col' });

    // Parameters column (left): Algorithm, then Hash (PBKDF2) or scrypt params below it
    var paramsWrap = el('div', { class: 'col' });
    var algoSel = ui.select([['pbkdf2', 'PBKDF2'], ['scrypt', 'scrypt']].map(o), function (v) { algo = v; applyAlgo(); updateSel(); }, 'pbkdf2');
    paramsWrap.appendChild(ui.field('Algorithm', algoSel));

    // Hash (PBKDF2) directly below Algorithm
    var hashSel = ui.select([['SHA-256', 'SHA-256'], ['SHA-512', 'SHA-512'], ['SHA-384', 'SHA-384'], ['SHA-1', 'SHA-1']].map(o), function () { updateSel(); }, 'SHA-256');
    var hashField = ui.field('Hash', hashSel);
    paramsWrap.appendChild(hashField);

    // scrypt params (shown below Algorithm in place of Hash)
    var scWrap = el('div', { class: 'col' }); scWrap.style.display = 'none';
    var scRow = el('div', { style: 'display:flex; gap:8px; align-items:flex-end; flex-wrap:wrap;' });
    var nSel = ui.select([['14', '16384 (2^14)'], ['15', '32768 (2^15)'], ['16', '65536 (2^16)'], ['12', '4096 (2^12)'], ['10', '1024 (2^10)']].map(o), function () { updateSel(); }, '14'); nSel.style.width = 'auto';
    var rInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '32', value: '8' }); rInput.style.width = '64px';
    var pInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '16', value: '1' }); pInput.style.width = '64px';
    rInput.addEventListener('input', updateSel); pInput.addEventListener('input', updateSel);
    scRow.appendChild(ui.field('Cost (N)', nSel)); scRow.appendChild(ui.field('Block (r)', rInput)); scRow.appendChild(ui.field('Parallel (p)', pInput));
    scWrap.appendChild(scRow);
    paramsWrap.appendChild(scWrap);

    // Salt column (right): Salt, then Iterations (PBKDF2) below it
    var saltWrap = el('div', { class: 'col' });
    var saltInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Salt' });
    var saltFmt = ui.select([['base64', 'Base64'], ['hex', 'Hexadecimal'], ['utf8', 'UTF-8']].map(o), null, 'base64');
    var saltGen = ui.iconBtn(I_SHUF, 'Random salt', function () { saltInput.value = saltFmt.value === 'hex' ? toHex(rndBytes(16)) : saltFmt.value === 'utf8' ? toHex(rndBytes(16)) : toB64(rndBytes(16)); if (saltFmt.value === 'utf8') saltFmt.value = 'hex'; });
    var saltRow = el('div', { style: 'display:flex; gap:5px; align-items:center; overflow:hidden;' });
    saltInput.style.flex = '1'; saltInput.style.minWidth = '0'; saltFmt.style.width = 'auto';
    saltRow.appendChild(saltInput); saltRow.appendChild(saltFmt); saltRow.appendChild(saltGen);
    saltWrap.appendChild(ui.field('Salt', saltRow));

    // Iterations (PBKDF2) directly below Salt
    var iters = 310000;
    var iterBtns = {}, iterRow = el('div', { style: 'display:flex; gap:5px; align-items:center; flex-wrap:wrap;' });
    ITERS.forEach(function (v) { var b = el('button', { class: 'eb' }); b.textContent = (v / 1000) + 'k'; b.addEventListener('click', function () { iters = v; iterCustom.value = ''; markIters(); updateSel(); }); iterBtns[v] = b; iterRow.appendChild(b); });
    var iterCustom = el('input', { class: 'inp sm', type: 'number', min: '1', placeholder: 'Custom' }); iterCustom.style.width = '90px';
    iterCustom.addEventListener('input', function () { if (iterCustom.value !== '') { var n = +iterCustom.value; if (n >= 1) iters = n; } markIters(); updateSel(); });
    iterRow.appendChild(iterCustom);
    var iterField = ui.field('Iterations', iterRow);
    saltWrap.appendChild(iterField);

    colL.appendChild(paramsWrap); colL.appendChild(saltWrap);

    var lenInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '1024', value: '32' }); lenInput.style.width = '90px';
    lenInput.addEventListener('input', updateSel);
    colR.appendChild(ui.field('Output length (bytes)', lenInput));
    var outFmt = ui.select([['hex', 'Hexadecimal'], ['base64', 'Base64']].map(o), null, 'hex');
    colR.appendChild(ui.field('Output format', outFmt));

    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'PASSWORD', icon: I_KEY, placeholder: 'Password to derive a key from...', primaries: [{ label: 'Derive', cls: 'enc', onClick: doDerive }], actions: ['copy', 'paste', 'clear'] });
    var outP = ui.textPanel({ title: 'DERIVED KEY', icon: I_LOCK, placeholder: 'Derived key appears here...', readonly: true, actions: ['copy', 'download'], downloadName: 'derived-key.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);
    CK.attachStrength(inP);

    function clearVerify() { inP.ta.classList.remove('verify-match', 'verify-fail'); outP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearVerify);
    outP.ta.addEventListener('input', clearVerify);

    function markIters() { ITERS.forEach(function (v) { iterBtns[v].classList.toggle('active', iters === v && iterCustom.value === ''); }); }
    function applyAlgo() { var sc = algo === 'scrypt'; hashField.style.display = sc ? 'none' : ''; iterField.style.display = sc ? 'none' : ''; scWrap.style.display = sc ? '' : 'none'; }
    function updateSel() {
      if (algo === 'scrypt') { var N = Math.pow(2, +nSel.value); ui.setSel(strip, 'scrypt', 'RFC7914', 'scrypt · N=' + N.toLocaleString() + ' r=' + (+rInput.value || 8) + ' p=' + (+pInput.value || 1) + ' · ' + (+lenInput.value || 32) + '-byte key · memory-hard'); }
      else ui.setSel(strip, 'PBKDF2 · ' + hashSel.value, 'PBKDF2', 'PBKDF2-HMAC-' + hashSel.value + ' · ' + iters.toLocaleString() + ' iterations · ' + (+lenInput.value || 32) + '-byte key'); }

    function saltBytes() { return inputBytes(saltInput.value, saltFmt.value); }
    function dkLen() { return Math.max(1, Math.min(1024, +lenInput.value || 32)); }
    function fmtOut(b) { return outFmt.value === 'base64' ? toB64(b) : toHex(b); }

    // returns Promise<Uint8Array>
    function derive() {
      var pw = inP.ta.value;
      if (!pw) return Promise.reject(new Error('Password is empty'));
      var salt = saltBytes();
      if (!salt.length) return Promise.reject(new Error('Salt is required'));
      if (algo === 'scrypt') {
        var N = Math.pow(2, +nSel.value), r = Math.max(1, +rInput.value || 8), p = Math.max(1, +pInput.value || 1);
        return new Promise(function (resolve, reject) {
          setTimeout(function () { try { resolve(scrypt(ENC.encode(pw), salt, N, r, p, dkLen())); } catch (e) { reject(e); } }, 10);
        });
      }
      return pbkdf2Web(ENC.encode(pw), salt, iters, hashSel.value, dkLen());
    }
    function doDerive() {
      var t0 = performance.now();
      return derive().then(function (b) { outP.ta.value = fmtOut(b); clearVerify(); ctx.toast('Derived in ' + Math.round(performance.now() - t0) + ' ms', 'success'); })
        .catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    function doVerify() {
      clearVerify();
      var want = outP.ta.value.trim();
      if (!want) { ctx.toast('Put a derived key in the output to verify', 'warn'); return; }
      return derive().then(function (b) {
        var got = fmtOut(b), match = got.toLowerCase() === want.toLowerCase() || toHex(b) === want.toLowerCase() || toB64(b) === want;
        CK.flashVerify(match, inP.ta, outP.ta);
        ctx.toast(match ? 'Match: the key derives from this password' : 'No match', match ? 'success' : 'error');
      }).catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    function doShare() { CK.copy(location.href.split('#')[0] + '#tool=kdf&s=' + b64uEnc(JSON.stringify({ a: algo, it: iters, h: hashSel.value, N: nSel.value, r: rInput.value, p: pInput.value, sf: saltFmt.value, salt: saltInput.value, dk: lenInput.value, of: outFmt.value }))); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; algo = 'pbkdf2'; algoSel.value = 'pbkdf2'; iters = 310000; iterCustom.value = ''; hashSel.value = 'SHA-256'; nSel.value = '14'; rInput.value = '8'; pInput.value = '1'; saltInput.value = ''; saltFmt.value = 'base64'; lenInput.value = '32'; outFmt.value = 'hex'; applyAlgo(); markIters(); updateSel(); clearVerify(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); algo = st.a || 'pbkdf2'; algoSel.value = algo; iters = st.it || 310000; if (ITERS.indexOf(iters) < 0) iterCustom.value = iters; hashSel.value = st.h || 'SHA-256'; nSel.value = st.N || '14'; rInput.value = st.r || '8'; pInput.value = st.p || '1'; saltFmt.value = st.sf || 'base64'; saltInput.value = st.salt || ''; lenInput.value = st.dk || '32'; outFmt.value = st.of || 'hex'; } catch (e) { } }
    if (!saltInput.value) saltInput.value = toB64(rndBytes(16));
    applyAlgo(); markIters(); updateSel();
  });
})();

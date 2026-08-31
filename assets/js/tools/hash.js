/*
   hash.js - Cryptographic Hash
   Select one algorithm (MD5, SHA-1, RIPEMD-160, CRC32, SHA-2, SHA-3, Keccak),
   optional HMAC, input UTF-8/Hex/Base64, output hex/HEX/Base64/Base64URL.
   Input-driven panels with Hash, plus Verify / Detect / Swap / Share / Reset.
*/
(function () {
  'use strict';
  var ENC = new TextEncoder();
  function toHex(b) { b = new Uint8Array(b); var s = ''; for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; }
  function hexToBytes(h) { h = h.replace(/[^0-9a-fA-F]/g, ''); var a = new Uint8Array(h.length / 2); for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
  function unb64(s) { s = s.trim().replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; var bin = atob(s), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  function b64(b) { b = new Uint8Array(b); var s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
  function concat(a, b) { var o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; }
  function webBytes(algo, b) { return crypto.subtle.digest(algo, b).then(function (h) { return new Uint8Array(h); }); }
  function P(hex) { return Promise.resolve(hexToBytes(hex)); }
  function b64uEnc(str) { var b = ENC.encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  // hb: bytes -> Promise<Uint8Array>; block = HMAC block size; bytes = digest length
  var ALGOS = [
    { id: 'md5', label: 'MD5', group: 'Legacy', badge: 'RFC1321', bytes: 16, block: 64, hb: function (b) { return P(HashLib.md5(b)); } },
    { id: 'sha1', label: 'SHA-1', group: 'Legacy', badge: 'SHA-1', bytes: 20, block: 64, hb: function (b) { return webBytes('SHA-1', b); } },
    { id: 'ripemd160', label: 'RIPEMD-160', group: 'Legacy', badge: 'RIPEMD', bytes: 20, block: 64, hb: function (b) { return P(HashLib.ripemd160(b)); } },
    { id: 'crc32', label: 'CRC32', group: 'Legacy', badge: 'Checksum', bytes: 4, block: 0, hmac: false, hb: function (b) { return P(HashLib.crc32(b)); } },
    { id: 'sha256', label: 'SHA-256', group: 'SHA-2', badge: 'SHA-2', bytes: 32, block: 64, hb: function (b) { return webBytes('SHA-256', b); } },
    { id: 'sha384', label: 'SHA-384', group: 'SHA-2', badge: 'SHA-2', bytes: 48, block: 128, hb: function (b) { return webBytes('SHA-384', b); } },
    { id: 'sha512', label: 'SHA-512', group: 'SHA-2', badge: 'SHA-2', bytes: 64, block: 128, hb: function (b) { return webBytes('SHA-512', b); } },
    { id: 'sha3-224', label: 'SHA3-224', group: 'SHA-3', badge: 'SHA-3', bytes: 28, block: 144, hb: function (b) { return P(HashLib.sha3(224, b)); } },
    { id: 'sha3-256', label: 'SHA3-256', group: 'SHA-3', badge: 'SHA-3', bytes: 32, block: 136, hb: function (b) { return P(HashLib.sha3(256, b)); } },
    { id: 'sha3-384', label: 'SHA3-384', group: 'SHA-3', badge: 'SHA-3', bytes: 48, block: 104, hb: function (b) { return P(HashLib.sha3(384, b)); } },
    { id: 'sha3-512', label: 'SHA3-512', group: 'SHA-3', badge: 'SHA-3', bytes: 64, block: 72, hb: function (b) { return P(HashLib.sha3(512, b)); } },
    { id: 'keccak-256', label: 'Keccak-256', group: 'SHA-3', badge: 'Keccak', bytes: 32, block: 136, hb: function (b) { return P(HashLib.keccak(256, b)); } }
  ];
  function get(id) { for (var i = 0; i < ALGOS.length; i++) if (ALGOS[i].id === id) return ALGOS[i]; return null; }
  var GROUPS = ['Legacy', 'SHA-2', 'SHA-3'];
  var BY_LEN = { 4: 'crc32', 16: 'md5', 20: 'sha1', 28: 'sha3-224', 32: 'sha256', 48: 'sha384', 64: 'sha512' };

  function hmac(algo, keyBytes, msgBytes) {
    var bs = algo.block;
    return (keyBytes.length > bs ? algo.hb(keyBytes) : Promise.resolve(keyBytes)).then(function (k0) {
      var k = new Uint8Array(bs), ipad = new Uint8Array(bs), opad = new Uint8Array(bs), i; k.set(k0);
      for (i = 0; i < bs; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
      return algo.hb(concat(ipad, msgBytes)).then(function (inner) { return algo.hb(concat(opad, inner)); });
    });
  }
  function fmtHex(hx, fmt) { if (fmt === 'HEX') return hx.toUpperCase(); if (fmt === 'base64') return b64(hexToBytes(hx)); if (fmt === 'base64url') return b64(hexToBytes(hx)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); return hx; }
  function outByteLen(s) { s = s.trim().replace(/\s/g, ''); if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return s.length / 2; try { return unb64(s).length; } catch (e) { return null; } }

  var I_HASH = '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>';
  var I_FILE = '<path d="M14 3v5h5M6 3h9l5 5v13H6z"/>';
  var I_CHECK = '<path d="M20 6 9 17l-5-5"/>';
  var I_DETECT = '<path d="m12 3 1.9 4.6L18 9l-4.1 1.4L12 15l-1.9-4.6L6 9l4.1-1.4zM19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9z"/>';
  var I_SWAP = '<path d="M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';
  var I_SHUF = '<path d="M18 4l3 3-3 3M21 7H8a4 4 0 0 0-4 4M6 20l-3-3 3-3M3 17h12a4 4 0 0 0 4-4"/>';
  function rndBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }
  function bytesToFmt(bytes, fmt) {
    if (fmt === 'hex') { var h = ''; for (var i = 0; i < bytes.length; i++) h += bytes[i].toString(16).padStart(2, '0'); return h; }
    if (fmt === 'base64') return b64(bytes);
    var u = ''; for (var k = 0; k < bytes.length; k++) u += String.fromCharCode(33 + (bytes[k] % 94)); return u;
  }

  CK.registerTool('hash', function (root, ctx) {
    var ui = CK.ui, el = CK.el, current = 'sha256';
    function o(a) { return { value: a[0], label: a[1] }; }

    root.appendChild(ui.head('Cryptographic Hash', ALGOS.length + ' algorithms'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_HASH);
    strip.acts.appendChild(ui.iconBtn(I_DETECT, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(I_CHECK, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(I_SWAP, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    // Left column split into two sub-columns: algorithm picker | HMAC. Right column: formats.
    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'hash-left' });
    var colR = el('div', { class: 'col' });

    var groups = GROUPS.map(function (g) { return { label: g, items: ALGOS.filter(function (a) { return a.group === g; }).map(function (a) { return { id: a.id, label: a.label, title: a.label }; }) }; });
    var pk = ui.picker(groups, select);
    pk.el.classList.add('stacked');
    var pickWrap = el('div'); pickWrap.appendChild(pk.el);

    // HMAC sub-column
    var hmacWrap = el('div', { class: 'col' });
    var hmacCb = el('input', { type: 'checkbox' });
    var hmacSwitch = el('label', { class: 'switch' });
    hmacSwitch.appendChild(hmacCb); hmacSwitch.appendChild(el('span', { class: 'track' })); hmacSwitch.appendChild(el('span', {}, 'HMAC Mode'));
    hmacWrap.appendChild(hmacSwitch);
    var keyInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'HMAC key' });
    var keyFmt = ui.select([['utf8', 'UTF-8'], ['hex', 'Hexadecimal'], ['base64', 'Base64']].map(o), null, 'utf8');
    var keyGen = ui.iconBtn(I_SHUF, 'Random HMAC key', genKey);
    var keyWrap = el('div', { style: 'display:flex; gap:5px; align-items:center; overflow:hidden;' });
    keyInput.style.flex = '1'; keyInput.style.minWidth = '0'; keyFmt.style.width = 'auto'; keyWrap.appendChild(keyInput); keyWrap.appendChild(keyFmt); keyWrap.appendChild(keyGen);
    var keyField = ui.field('HMAC key', keyWrap); keyField.style.display = 'none';
    hmacWrap.appendChild(keyField);
    hmacCb.addEventListener('change', function () { keyField.style.display = hmacCb.checked ? '' : 'none'; });

    colL.appendChild(pickWrap); colL.appendChild(hmacWrap);

    var inFmt = ui.select([['utf8', 'UTF-8'], ['hex', 'Hexadecimal'], ['base64', 'Base64']].map(o), null, 'utf8');
    var outFmt = ui.select([['hex', 'Hexadecimal (lower)'], ['HEX', 'Hexadecimal (UPPER)'], ['base64', 'Base64'], ['base64url', 'Base64 URL-safe']].map(o), null, 'hex');
    colR.appendChild(ui.field('Input format', inFmt));
    colR.appendChild(ui.field('Output format', outFmt));

    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    function genKey() { var a = get(current); keyInput.value = bytesToFmt(rndBytes(a.bytes || 32), keyFmt.value); if (!hmacCb.checked) { hmacCb.checked = true; keyField.style.display = ''; } }

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: I_FILE, placeholder: 'Text to hash...', primaries: [{ label: 'Hash', cls: 'enc', onClick: doHash }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'input.txt' });
    var outP = ui.textPanel({ title: 'OUTPUT', icon: I_HASH, placeholder: 'Digest appears here...', actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'digest.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearVerify() { outP.ta.classList.remove('verify-match', 'verify-fail'); inP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearVerify);
    outP.ta.addEventListener('input', clearVerify);

    function select(id) { var a = get(id); if (!a) return; current = id; pk.setActive(id); ui.setSel(strip, a.label, a.badge, a.label + ' digest, ' + a.bytes + ' bytes'); }
    function inputBytes() { var v = inP.ta.value; if (!v) return null; if (inFmt.value === 'hex') return hexToBytes(v); if (inFmt.value === 'base64') { try { return unb64(v); } catch (e) { return null; } } return ENC.encode(v); }
    function keyBytes() { var v = keyInput.value; if (keyFmt.value === 'hex') return hexToBytes(v); if (keyFmt.value === 'base64') { try { return unb64(v); } catch (e) { return new Uint8Array(); } } return ENC.encode(v); }
    // returns Promise<hex> for the current algorithm (HMAC-aware)
    function digest(bytes) {
      var a = get(current);
      if (hmacCb.checked && keyInput.value) { if (a.hmac === false) return Promise.reject(new Error(a.label + ' does not support HMAC')); return hmac(a, keyBytes(), bytes).then(toHex); }
      return a.hb(bytes).then(toHex);
    }

    function doHash() {
      var bytes = inputBytes();
      if (!bytes) { ctx.toast('Input is empty', 'warn'); return; }
      return digest(bytes).then(function (hx) { outP.ta.value = fmtHex(hx, outFmt.value); clearVerify(); ctx.toast('Hashed (' + get(current).label + (hmacCb.checked && keyInput.value ? ' HMAC' : '') + ')', 'success'); })
        .catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    function doVerify() {
      clearVerify();
      var bytes = inputBytes();
      if (!bytes || !outP.ta.value) { ctx.toast('Both panels need content', 'warn'); return; }
      var want = outP.ta.value.trim();
      digest(bytes).then(function (hx) {
        var got = fmtHex(hx, outFmt.value);
        var match = (want.toLowerCase() === got.toLowerCase()) || (want.toLowerCase() === hx.toLowerCase());
        CK.flashVerify(match, inP.ta, outP.ta);
        ctx.toast(match ? 'Match: output is the ' + get(current).label + ' of the input' : 'No match', match ? 'success' : 'error');
      }).catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    function doDetect() {
      var s = outP.ta.value.trim();
      if (!s) { ctx.toast('Put a digest in the output first', 'warn'); return; }
      var len = outByteLen(s), id = len ? BY_LEN[len] : null;
      if (id) { select(id); ctx.toast('Guessed ' + get(id).label + ' (' + len + ' bytes, best-effort)', 'success'); }
      else ctx.toast('Could not detect the hash length', 'warn');
    }
    function doSwap() { inP.ta.value = outP.ta.value; outP.ta.value = ''; clearVerify(); ctx.toast('Output moved to input', 'success'); }
    function doShare() { var st = { a: current, inf: inFmt.value, outf: outFmt.value, hm: hmacCb.checked ? 1 : 0, kf: keyFmt.value, k: keyInput.value, in: inP.ta.value, out: outP.ta.value }; CK.copy(location.href.split('#')[0] + '#tool=hash&s=' + b64uEnc(JSON.stringify(st))); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; keyInput.value = ''; hmacCb.checked = false; keyField.style.display = 'none'; inFmt.value = 'utf8'; outFmt.value = 'hex'; keyFmt.value = 'utf8'; clearVerify(); select('sha256'); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); if (st.a) current = st.a; inFmt.value = st.inf || 'utf8'; outFmt.value = st.outf || 'hex'; keyFmt.value = st.kf || 'utf8'; keyInput.value = st.k || ''; hmacCb.checked = !!st.hm; keyField.style.display = hmacCb.checked ? '' : 'none'; inP.ta.value = st.in || ''; outP.ta.value = st.out || ''; } catch (e) { } }
    select(current);
  });
})();

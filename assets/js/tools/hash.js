/*
   hash.js - Hash Generator
   MD5, SHA-1, RIPEMD-160, CRC32, SHA-256/384/512, SHA3-224/256/384/512,
   Keccak-256. HMAC (any algorithm), input UTF-8/Hex/Base64, output
   hex/HEX/Base64/Base64URL, file hashing, and compare-against-expected.
*/
(function () {
  'use strict';
  var ENC = new TextEncoder();
  function toHex(b) { b = new Uint8Array(b); var s = ''; for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; }
  function hexToBytes(h) { h = h.replace(/[^0-9a-fA-F]/g, ''); var a = new Uint8Array(h.length / 2); for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
  function unb64(s) { var bin = atob(s.trim().replace(/\s/g, '')); var a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  function b64(b) { b = new Uint8Array(b); var s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
  function concat(a, b) { var o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; }
  function webBytes(algo, b) { return crypto.subtle.digest(algo, b).then(function (h) { return new Uint8Array(h); }); }
  function P(hex) { return Promise.resolve(hexToBytes(hex)); }

  // hashBytes: bytes -> Promise<Uint8Array>; block = HMAC block size (bytes)
  var ALGOS = [
    { id: 'md5', label: 'MD5', group: 'Legacy', block: 64, hb: function (b) { return P(HashLib.md5(b)); } },
    { id: 'sha1', label: 'SHA-1', group: 'Legacy', block: 64, hb: function (b) { return webBytes('SHA-1', b); } },
    { id: 'ripemd160', label: 'RIPEMD-160', group: 'Legacy', block: 64, hb: function (b) { return P(HashLib.ripemd160(b)); } },
    { id: 'crc32', label: 'CRC32', group: 'Legacy', block: 0, hmac: false, hb: function (b) { return P(HashLib.crc32(b)); } },
    { id: 'sha256', label: 'SHA-256', group: 'SHA-2', block: 64, hb: function (b) { return webBytes('SHA-256', b); } },
    { id: 'sha384', label: 'SHA-384', group: 'SHA-2', block: 128, hb: function (b) { return webBytes('SHA-384', b); } },
    { id: 'sha512', label: 'SHA-512', group: 'SHA-2', block: 128, hb: function (b) { return webBytes('SHA-512', b); } },
    { id: 'sha3-224', label: 'SHA3-224', group: 'SHA-3', block: 144, hb: function (b) { return P(HashLib.sha3(224, b)); } },
    { id: 'sha3-256', label: 'SHA3-256', group: 'SHA-3', block: 136, hb: function (b) { return P(HashLib.sha3(256, b)); } },
    { id: 'sha3-384', label: 'SHA3-384', group: 'SHA-3', block: 104, hb: function (b) { return P(HashLib.sha3(384, b)); } },
    { id: 'sha3-512', label: 'SHA3-512', group: 'SHA-3', block: 72, hb: function (b) { return P(HashLib.sha3(512, b)); } },
    { id: 'keccak-256', label: 'Keccak-256', group: 'SHA-3', block: 136, hb: function (b) { return P(HashLib.keccak(256, b)); } }
  ];

  function hmac(algo, keyBytes, msgBytes) {
    var bs = algo.block;
    return (keyBytes.length > bs ? algo.hb(keyBytes) : Promise.resolve(keyBytes)).then(function (k0) {
      var k = new Uint8Array(bs), ipad = new Uint8Array(bs), opad = new Uint8Array(bs), i;
      k.set(k0);
      for (i = 0; i < bs; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
      return algo.hb(concat(ipad, msgBytes)).then(function (inner) { return algo.hb(concat(opad, inner)).then(toHex); });
    });
  }
  function fmtHex(hx, fmt) { if (fmt === 'HEX') return hx.toUpperCase(); if (fmt === 'base64') return b64(hexToBytes(hx)); if (fmt === 'base64url') return b64(hexToBytes(hx)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); return hx; }

  var I_HASH = '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>';
  var I_FILE = '<path d="M14 3v5h5M6 3h9l5 5v13H6z"/>';

  CK.registerTool('hash', function (root, ctx) {
    var ui = CK.ui, el = CK.el, fileBytes = null, fileName = '';

    root.appendChild(ui.head('Hash Generator', ALGOS.length + ' algorithms'));

    var cfg = ui.configPanel();
    var form = el('div', { class: 'cfg-form' });
    var inFmt = ui.select([['utf8', 'UTF-8'], ['hex', 'Hex'], ['base64', 'Base64']].map(o), function () { compute(); }, 'utf8');
    form.appendChild(ui.field('Input format', inFmt));
    var outFmt = ui.select([['hex', 'Hex (lower)'], ['HEX', 'Hex (UPPER)'], ['base64', 'Base64'], ['base64url', 'Base64URL']].map(o), function () { compute(); }, 'hex');
    form.appendChild(ui.field('Output format', outFmt));
    var hmacTog = ui.toggle('HMAC', false, function () { updateHmac(); compute(); });
    form.appendChild(ui.field('Mode', hmacTog.wrap));
    var keyInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'HMAC key' });
    var keyFmt = ui.select([['utf8', 'UTF-8'], ['hex', 'Hex'], ['base64', 'Base64']].map(o), function () { compute(); }, 'utf8');
    var keyWrap = el('div', { style: 'display:flex; gap:5px;' }); keyInput.style.flex = '1'; keyFmt.style.width = 'auto'; keyWrap.appendChild(keyInput); keyWrap.appendChild(keyFmt);
    var keyField = ui.field('HMAC key', keyWrap); keyField.style.flex = '2'; keyField.style.minWidth = '240px';
    form.appendChild(keyField);
    var cmpInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Paste a digest to compare' });
    var cmpField = ui.field('Compare', cmpInput); cmpField.style.flex = '2'; cmpField.style.minWidth = '240px';
    form.appendChild(cmpField);
    cfg.appendChild(form);
    root.appendChild(cfg);
    function o(a) { return { value: a[0], label: a[1] }; }

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: I_FILE, placeholder: 'Type or paste text to hash...', actions: ['copy', 'paste', 'clear'], onInput: function () { fileBytes = null; fileName = ''; compute(); } });
    // File button + hidden input
    var fileInput = el('input', { type: 'file' }); fileInput.style.display = 'none';
    var fileBtn = ui.miniBtn('File', function () { fileInput.click(); });
    inP.panel.querySelector('.tb').appendChild(fileBtn);
    inP.panel.appendChild(fileInput);
    fileInput.addEventListener('change', function () {
      var f = fileInput.files[0]; if (!f) return;
      f.arrayBuffer().then(function (buf) { fileBytes = new Uint8Array(buf); fileName = f.name; inP.ta.value = '[file: ' + f.name + ', ' + fileBytes.length + ' bytes]'; compute(); ctx.toast('Loaded ' + f.name, 'success'); });
    });
    io.appendChild(inP.panel);

    var panel = el('div', { class: 'panel io-p' });
    var hdr = el('div', { class: 'panel-hdr' }); hdr.innerHTML = CK.iconSvg(I_HASH, 12) + ' DIGESTS';
    panel.appendChild(hdr);
    var body = el('div', { style: 'overflow:auto; flex:1;' }); panel.appendChild(body);
    io.appendChild(panel); root.appendChild(io);

    var rows = {}, lastGroup = null;
    ALGOS.forEach(function (a) {
      if (a.group !== lastGroup) { body.appendChild(el('div', { class: 'pk-label', style: 'text-align:left; padding:8px 0 2px;' }, a.group)); lastGroup = a.group; }
      var r = el('div', { class: 'row-out' });
      var k = el('span', { class: 'k' }, a.label);
      var v = el('span', { class: 'v' }, '-');
      var cp = ui.miniBtn('Copy', function () { CK.copy(v.textContent); });
      r.appendChild(k); r.appendChild(v); r.appendChild(cp);
      body.appendChild(r); rows[a.id] = { v: v, r: r };
    });

    function updateHmac() { keyField.style.display = hmacTog.cb.checked ? '' : 'none'; }
    function inputBytes() {
      if (fileBytes) return fileBytes;
      var v = inP.ta.value; if (!v) return null;
      if (inFmt.value === 'hex') return hexToBytes(v);
      if (inFmt.value === 'base64') { try { return unb64(v); } catch (e) { return null; } }
      return ENC.encode(v);
    }
    function keyBytes() { var v = keyInput.value; if (keyFmt.value === 'hex') return hexToBytes(v); if (keyFmt.value === 'base64') { try { return unb64(v); } catch (e) { return new Uint8Array(); } } return ENC.encode(v); }

    function compute() {
      var bytes = inputBytes();
      if (!bytes) { ALGOS.forEach(function (a) { rows[a.id].v.textContent = '-'; mark(a.id, null); }); return; }
      var useHmac = hmacTog.cb.checked && keyInput.value, kb = keyBytes();
      ALGOS.forEach(function (a) {
        var p;
        if (useHmac && a.hmac === false) { rows[a.id].v.textContent = '(no HMAC)'; mark(a.id, null); return; }
        p = useHmac ? hmac(a, kb, bytes) : a.hb(bytes).then(toHex);
        p.then(function (hx) { rows[a.id].v.textContent = fmtHex(hx, outFmt.value); markCompare(a.id, hx); })
          .catch(function () { rows[a.id].v.textContent = 'error'; });
      });
    }
    function mark(id, cls) { var r = rows[id].r; r.classList.remove('cmp-hit'); if (cls) r.classList.add(cls); }
    function markCompare(id, hx) {
      var want = cmpInput.value.trim(); mark(id, null);
      if (!want) return;
      var got = fmtHex(hx, outFmt.value);
      if (want.toLowerCase() === got.toLowerCase() || want.toLowerCase() === hx.toLowerCase()) mark(id, 'cmp-hit');
    }
    cmpInput.addEventListener('input', compute);

    updateHmac(); compute();
    return { reset: function () { inP.ta.value = ''; keyInput.value = ''; cmpInput.value = ''; hmacTog.cb.checked = false; inFmt.value = 'utf8'; outFmt.value = 'hex'; keyFmt.value = 'utf8'; fileBytes = null; updateHmac(); compute(); ctx.toast('Reset complete', 'success'); } };
  });
})();

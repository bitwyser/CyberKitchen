/*
   checksum.js - File Checksum
   Drop or choose a local file and compute CRC32, MD5, SHA-1, SHA-2 and SHA-3
   digests. Verify a published checksum (bare hash, "hash  filename" or
   "ALGO (file) = hash"); the algorithm is found from the checksum length.
   The file is read in the browser and never uploaded.
*/
(function () {
  'use strict';
  function toHex(b) { b = new Uint8Array(b); var s = ''; for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; }
  function hexToBytes(h) { var a = new Uint8Array(h.length / 2); for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
  function b64(b) { var s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
  function unb64(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; var bin = atob(s), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  function web(algo) { return function (b) { return crypto.subtle.digest(algo, b).then(toHex); }; }
  function lib(fn) { return function (b) { return Promise.resolve(fn(b)); }; }

  // hx: bytes -> Promise<hex>
  var ALGOS = [
    { id: 'crc32', label: 'CRC32', bytes: 4, hx: lib(function (b) { return HashLib.crc32(b); }) },
    { id: 'md5', label: 'MD5', bytes: 16, hx: lib(function (b) { return HashLib.md5(b); }) },
    { id: 'sha1', label: 'SHA-1', bytes: 20, hx: web('SHA-1') },
    { id: 'sha256', label: 'SHA-256', bytes: 32, hx: web('SHA-256') },
    { id: 'sha384', label: 'SHA-384', bytes: 48, hx: web('SHA-384') },
    { id: 'sha512', label: 'SHA-512', bytes: 64, hx: web('SHA-512') },
    { id: 'sha3-256', label: 'SHA3-256', bytes: 32, hx: lib(function (b) { return HashLib.sha3(256, b); }) },
    { id: 'sha3-512', label: 'SHA3-512', bytes: 64, hx: lib(function (b) { return HashLib.sha3(512, b); }) }
  ];
  var DEFAULTS = ['md5', 'sha1', 'sha256', 'sha512'];
  function get(id) { for (var i = 0; i < ALGOS.length; i++) if (ALGOS[i].id === id) return ALGOS[i]; return null; }

  function fmtSize(n) {
    var u = ['bytes', 'KB', 'MB', 'GB'], i = 0, v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i ? v.toFixed(v < 10 ? 2 : 1) + ' ' + u[i] + ' (' + n.toLocaleString() + ' bytes)' : n.toLocaleString() + ' bytes');
  }
  // Published checksum -> lowercase hex, or null. Accepts a bare hash (hex or
  // Base64), GNU "hash  filename" and BSD "ALGO (file) = hash" lines.
  function parseExpected(v) {
    v = v.trim(); if (!v) return null;
    var bsd = /\)\s*=\s*([0-9A-Za-z+/_-]+={0,2})\s*$/.exec(v);
    var tok = bsd ? bsd[1] : v.split(/\s+/)[0].replace(/^\*/, '');
    if (/^[0-9a-fA-F]+$/.test(tok) && tok.length % 2 === 0) return tok.toLowerCase();
    // Base64: the shortest supported checksum (CRC32) is 8 characters
    if (tok.length < 8 || !/^[0-9A-Za-z+/_-]+={0,2}$/.test(tok)) return null;
    try { var b = unb64(tok); return b.length ? toHex(b) : null; } catch (e) { return null; }
  }

  var I_SUM = '<path d="M14 3v5h5M6 3h9l5 5v13H6z"/><path d="m9 14 2 2 4-4"/>';
  var I_FILE = '<path d="M14 3v5h5M6 3h9l5 5v13H6z"/>';
  var I_HASH = '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>';
  var I_UPLOAD = '<path d="M12 16V4M7 9l5-5 5 5M5 20h14"/>';
  var I_CHECK = '<path d="M20 6 9 17l-5-5"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';
  var IC_CLEAR = '<path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 13a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-13"/>';

  CK.registerTool('checksum', function (root, ctx) {
    var ui = CK.ui, el = CK.el, iconSvg = CK.iconSvg;
    function o(a) { return { value: a[0], label: a[1] }; }

    root.appendChild(ui.head('File Checksum', 'local file'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_SUM);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(I_CHECK, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col' });
    var colR = el('div', { class: 'col' });
    // Algorithms: toggle buttons, several can be on, all on one wrapping line
    var chosen = DEFAULTS.slice(), algoBtns = {};
    var algoRow = el('div', { style: 'display:flex; flex-wrap:wrap; gap:5px; align-items:center;' });
    ALGOS.forEach(function (a) {
      var b = el('button', { class: 'eb', title: a.label + ' (' + a.bytes + ' bytes)' }); b.textContent = a.label;
      b.addEventListener('click', function () { toggleAlgo(a.id); });
      algoBtns[a.id] = b; algoRow.appendChild(b);
    });
    var expInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Paste a published checksum, then Verify (Enter)' });
    colL.appendChild(ui.field('Algorithms', algoRow)); colL.appendChild(ui.field('Expected checksum', expInput));
    var outFmt = ui.select([['hex', 'Hexadecimal (lower)'], ['HEX', 'Hexadecimal (UPPER)'], ['base64', 'Base64']].map(o), render, 'hex');
    colR.appendChild(ui.field('Output format', outFmt));
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    // File panel: drop zone (styled like the text areas so Verify can colour it)
    var inP = el('div', { class: 'panel io-p' });
    var hdr = el('div', { class: 'panel-hdr', html: iconSvg(I_FILE, 12) + ' ' });
    hdr.appendChild(document.createTextNode('FILE'));
    var fill = el('span', { class: 'fill' }), tb = el('span', { class: 'tb' });
    var picker = el('input', { type: 'file', style: 'display:none' });
    tb.appendChild(ui.iconBtn(I_UPLOAD, 'Choose file', function () { picker.click(); }));
    var clrBtn = ui.iconBtn(IC_CLEAR, 'Clear', clearFile); tb.appendChild(clrBtn);
    hdr.appendChild(fill); hdr.appendChild(tb);
    var drop = el('div', { class: 'ta cs-drop', tabindex: '0', role: 'button', 'aria-label': 'Choose a file to hash' });
    inP.appendChild(hdr); inP.appendChild(drop); inP.appendChild(picker);
    var outP = ui.textPanel({ title: 'CHECKSUMS', icon: I_HASH, placeholder: 'Checksums appear here...', readonly: true, actions: ['copy', 'download'], downloadName: 'checksums.txt' });
    io.appendChild(inP); io.appendChild(outP.panel);
    root.appendChild(io);

    var file = null, bytes = null, digests = {}, busy = 0;

    function clearVerify() { drop.classList.remove('verify-match', 'verify-fail'); outP.ta.classList.remove('verify-match', 'verify-fail'); }
    function showDrop(state) {
      drop.innerHTML = '';
      drop.appendChild(el('span', { html: iconSvg(file ? I_FILE : I_UPLOAD, 26) }));
      if (!file) {
        drop.appendChild(el('span', { class: 'cs-name' }, 'Drop a file here, or click to choose'));
      } else {
        var nm = el('span', { class: 'cs-name' }); nm.textContent = file.name; drop.appendChild(nm);
        var meta = el('span', { class: 'cs-meta' });
        meta.textContent = fmtSize(file.size) + (file.type ? ' · ' + file.type : '') + (file.lastModified ? ' · ' + new Date(file.lastModified).toLocaleString() : '');
        drop.appendChild(meta);
        drop.appendChild(el('span', { class: 'cs-hint' }, state === 'busy' ? 'Hashing...' : 'Click or drop to choose another file'));
      }
      clrBtn.disabled = !file;
    }
    function updateSel() {
      var names = chosen.map(function (id) { return get(id).label; });
      ui.setSel(strip, 'File Checksum', chosen.length + (chosen.length === 1 ? ' algorithm' : ' algorithms'),
        (names.length ? names.join(', ') : 'No algorithm selected') + ' of a local file.');
    }
    function markAlgos() { ALGOS.forEach(function (a) { algoBtns[a.id].classList.toggle('active', chosen.indexOf(a.id) >= 0); }); }
    function toggleAlgo(id) {
      var i = chosen.indexOf(id);
      if (i >= 0) chosen.splice(i, 1); else chosen.push(id);
      chosen.sort(function (x, y) { return ALGOS.indexOf(get(x)) - ALGOS.indexOf(get(y)); });
      markAlgos(); updateSel();
      if (bytes) compute(chosen).then(render);
    }

    function fmt(hx) { return outFmt.value === 'HEX' ? hx.toUpperCase() : outFmt.value === 'base64' ? b64(hexToBytes(hx)) : hx; }
    function render() {
      if (!bytes) { outP.ta.value = ''; return; }
      outP.ta.value = chosen.filter(function (id) { return digests[id]; }).map(function (id) { return (get(id).label + '         ').slice(0, 10) + fmt(digests[id]); }).join('\n');
    }
    // Digest the current file with each algorithm not yet cached
    function compute(ids) {
      var gen = busy, todo = ids.filter(function (id) { return !digests[id]; });
      return todo.reduce(function (p, id) {
        return p.then(function () {
          if (gen !== busy) return;
          return get(id).hx(bytes).then(function (hx) { if (gen === busy) digests[id] = hx; });
        });
      }, Promise.resolve());
    }

    function load(f) {
      if (!f) return;
      busy++; var gen = busy;
      file = f; bytes = null; digests = {}; outP.ta.value = ''; clearVerify(); showDrop('busy');
      var t0 = Date.now();
      f.arrayBuffer().then(function (buf) {
        if (gen !== busy) return;
        bytes = new Uint8Array(buf);
        // Let the "Hashing..." state paint before the synchronous hashes run
        return new Promise(function (r) { setTimeout(r, 30); }).then(function () { return compute(chosen); }).then(function () {
          if (gen !== busy) return;
          render(); showDrop();
          ctx.toast('Hashed ' + f.name + ' in ' + ((Date.now() - t0) / 1000).toFixed(2) + ' s', 'success');
          if (expInput.value.trim()) doVerify();
        });
      }).catch(function () {
        if (gen !== busy) return;
        file = null; bytes = null; showDrop();
        ctx.toast('Could not read the file (it may be too large for the browser)', 'error');
      });
    }
    function clearFile() { busy++; file = null; bytes = null; digests = {}; picker.value = ''; outP.ta.value = ''; clearVerify(); showDrop(); }

    function doVerify() {
      clearVerify();
      var raw = expInput.value.trim();
      if (!raw) { ctx.toast('Paste the expected checksum first', 'warn'); return; }
      if (!bytes) { ctx.toast('Choose a file first', 'warn'); return; }
      var want = parseExpected(raw);
      if (!want) { CK.flashVerify(false, drop, outP.ta); ctx.toast('That is not a hex or Base64 checksum', 'error'); return; }
      // Check every algorithm with this digest length, selected or not
      var cands = ALGOS.filter(function (a) { return a.bytes * 2 === want.length; }).map(function (a) { return a.id; });
      if (!cands.length) { CK.flashVerify(false, drop, outP.ta); ctx.toast('No match: ' + want.length / 2 + ' bytes is not a supported checksum length', 'error'); return; }
      compute(cands).then(function () {
        var hit = cands.filter(function (id) { return digests[id] === want; })[0];
        CK.flashVerify(!!hit, drop, outP.ta);
        ctx.toast(hit ? 'Match: ' + get(hit).label + ' of ' + file.name : 'No match (checked ' + cands.map(function (id) { return get(id).label; }).join(', ') + ')', hit ? 'success' : 'error');
      });
    }
    function doReset() {
      clearFile(); expInput.value = ''; chosen = DEFAULTS.slice(); outFmt.value = 'hex';
      markAlgos(); updateSel(); ctx.toast('Reset complete', 'success');
    }

    picker.addEventListener('change', function () { load(picker.files[0]); });
    drop.addEventListener('click', function () { picker.click(); });
    drop.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); picker.click(); } });
    drop.addEventListener('dragover', function (e) { e.preventDefault(); drop.classList.add('drag'); });
    drop.addEventListener('dragleave', function () { drop.classList.remove('drag'); });
    drop.addEventListener('drop', function (e) { e.preventDefault(); drop.classList.remove('drag'); if (e.dataTransfer && e.dataTransfer.files[0]) load(e.dataTransfer.files[0]); });
    expInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') doVerify(); });
    expInput.addEventListener('input', clearVerify);

    markAlgos(); updateSel(); showDrop();
  });
})();

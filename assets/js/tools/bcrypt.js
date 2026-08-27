/*
   bcrypt.js - Bcrypt hash / verify (vendored bcryptjs). Offline.
   Cost presets + custom, auto or custom salt (with random generator),
   Full-hash / Hash-only / JSON output. Verify / Detect / Swap / Share / Reset.
*/
(function () {
  'use strict';
  function lib() { if (typeof bcrypt !== 'undefined') return bcrypt; if (typeof dcodeIO !== 'undefined' && dcodeIO.bcrypt) return dcodeIO.bcrypt; return null; }
  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }
  function parseBcrypt(h) { var m = /^\$(2[abxy]?)\$(\d{2})\$([./A-Za-z0-9]{53})$/.exec(h); if (!m) return null; return { version: m[1], cost: parseInt(m[2], 10), salt: m[3].slice(0, 22), hashPart: m[3].slice(22) }; }

  var I_FISH = '<path d="M6.5 12c3-5 8-5 11 0-3 5-8 5-11 0zM15 11.5v.01"/>';
  var I_HASH = '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>';
  var I_CHECK = '<path d="M20 6 9 17l-5-5"/>';
  var I_DETECT = '<path d="m12 3 1.9 4.6L18 9l-4.1 1.4L12 15l-1.9-4.6L6 9l4.1-1.4zM19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9z"/>';
  var I_INSPECT = '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>';
  var I_SWAP = '<path d="M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';
  var I_SHUF = '<path d="M18 4l3 3-3 3M21 7H8a4 4 0 0 0-4 4M6 20l-3-3 3-3M3 17h12a4 4 0 0 0 4-4"/>';
  var COSTS = [10, 12, 14];

  CK.registerTool('bcrypt', function (root, ctx) {
    var ui = CK.ui, el = CK.el, cost = 10;
    function o(a) { return { value: a[0], label: a[1] }; }

    root.appendChild(ui.head('Bcrypt', 'hash + verify'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_FISH);
    strip.acts.appendChild(ui.iconBtn(I_DETECT, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(I_CHECK, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(I_SWAP, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    // Left column split: cost | custom salt. Right column: output.
    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'bc-left' });
    var colR = el('div', { class: 'col' });

    // Cost: 3 presets + custom input, all on one line
    var costBtns = {}, costRow = el('div', { style: 'display:flex; gap:5px; align-items:center;' });
    COSTS.forEach(function (v) {
      var b = el('button', { class: 'eb' }); b.textContent = v;
      b.addEventListener('click', function () { cost = v; custInput.value = ''; markCost(); updateSel(); });
      costBtns[v] = b; costRow.appendChild(b);
    });
    var custInput = el('input', { class: 'inp sm', type: 'number', min: '4', max: '31', placeholder: 'Custom' });
    custInput.style.width = '84px';
    custInput.addEventListener('input', function () { if (custInput.value !== '') { var n = +custInput.value; if (n >= 4 && n <= 31) cost = n; } markCost(); updateSel(); });
    costRow.appendChild(custInput);
    var costWrap = el('div'); costWrap.appendChild(ui.field('Cost (rounds)', costRow));

    // Custom salt (switch + salt input with random generator)
    var saltWrap = el('div', { class: 'col' });
    var saltCb = el('input', { type: 'checkbox' });
    var saltSwitch = el('label', { class: 'switch' });
    saltSwitch.appendChild(saltCb); saltSwitch.appendChild(el('span', { class: 'track' })); saltSwitch.appendChild(el('span', {}, 'Custom salt'));
    saltWrap.appendChild(saltSwitch);
    var saltInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: '$2a$10$22-char-salt' });
    var saltGen = ui.iconBtn(I_SHUF, 'Random salt', function () { var b = lib(); if (!b) { ctx.toast('bcrypt library not loaded', 'error'); return; } saltInput.value = b.genSaltSync(cost); });
    var saltRow = el('div', { style: 'display:flex; gap:5px; align-items:center; overflow:hidden;' });
    saltInput.style.flex = '1'; saltInput.style.minWidth = '0'; saltRow.appendChild(saltInput); saltRow.appendChild(saltGen);
    var saltField = ui.field('Salt', saltRow); saltField.style.display = 'none';
    saltWrap.appendChild(saltField);
    saltCb.addEventListener('change', function () { saltField.style.display = saltCb.checked ? '' : 'none'; });

    colL.appendChild(costWrap); colL.appendChild(saltWrap);

    var outSel = ui.select([['full', 'Full hash'], ['hashonly', 'Hash only'], ['json', 'JSON']].map(o), null, 'full');
    colR.appendChild(ui.field('Output', outSel));

    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'PASSWORD', icon: I_FISH, placeholder: 'Password to hash...', primaries: [{ label: 'Hash', cls: 'enc', onClick: doHash }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'password.txt' });
    var outP = ui.textPanel({ title: 'BCRYPT HASH', icon: I_HASH, placeholder: 'Hash output, or paste a $2 hash to verify...', primaries: [{ label: 'Inspect', cls: 'dec', onClick: doInspect }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'bcrypt.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearV() { outP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearV);
    outP.ta.addEventListener('input', clearV);
    function markCost() { COSTS.forEach(function (v) { costBtns[v].classList.toggle('active', cost === v && custInput.value === ''); }); }
    function updateSel() { ui.setSel(strip, 'bcrypt cost ' + cost, '2^' + cost, 'Blowfish-based hashing, ' + Math.pow(2, cost).toLocaleString() + ' iterations'); }
    function formatOut(hash) {
      if (outSel.value === 'hashonly') return hash.slice(-31);
      if (outSel.value === 'json') { var p = parseBcrypt(hash) || {}; return JSON.stringify({ algorithm: 'bcrypt', version: '$' + (p.version || ''), cost: p.cost, salt: p.salt, hash: p.hashPart, full: hash }, null, 2); }
      return hash;
    }

    function doHash() {
      var b = lib(); if (!b) { ctx.toast('bcrypt library not loaded', 'error'); return; }
      var pw = inP.ta.value; if (!pw) { ctx.toast('Password is empty', 'warn'); return; }
      var t0 = performance.now();
      function done(err, hash) {
        if (err) { ctx.toast('Hash failed: ' + err.message, 'error'); return; }
        outP.ta.value = formatOut(hash); clearV();
        ctx.toast('Hashed in ' + Math.round(performance.now() - t0) + ' ms', 'success');
      }
      if (saltCb.checked) {
        var salt = saltInput.value.trim();
        if (!/^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{22}/.test(salt)) { ctx.toast('Custom salt must look like $2a$10$ + 22 chars', 'error'); return; }
        try { done(null, b.hashSync(pw, salt)); } catch (e) { done(e); }
      } else { b.hash(pw, cost, done); }
    }
    function doVerify() {
      var b = lib(); if (!b) { ctx.toast('bcrypt library not loaded', 'error'); return; }
      var pw = inP.ta.value, hash = outP.ta.value.trim();
      if (!pw) { ctx.toast('Enter the password on the left', 'warn'); return; }
      if (!/^\$2[abxy]?\$/.test(hash)) { ctx.toast('Output is not a full bcrypt hash', 'error'); return; }
      b.compare(pw, hash, function (err, ok) { if (err) { ctx.toast('Verify failed: ' + err.message, 'error'); return; } clearV(); outP.ta.classList.add(ok ? 'verify-match' : 'verify-fail'); ctx.toast(ok ? 'Match: password is correct' : 'No match', ok ? 'success' : 'error'); });
    }
    function doDetect() {
      var p = parseBcrypt(outP.ta.value.trim());
      if (!p) { ctx.toast('Output is not a bcrypt hash', 'warn'); return; }
      cost = p.cost; if (COSTS.indexOf(cost) < 0) { custInput.value = cost; } else { custInput.value = ''; }
      markCost(); updateSel();
      ctx.toast('Detected bcrypt $' + p.version + ', cost ' + p.cost, 'success');
    }
    function doInspect() {
      var h = outP.ta.value.trim();
      if (!h) { ctx.toast('No hash in the output panel', 'warn'); return; }
      var p = parseBcrypt(h);
      if (!p) { ctx.toast('Output is not a valid bcrypt hash', 'error'); return; }
      outP.ta.value = [
        'Algorithm:  bcrypt',
        'Version:    $' + p.version,
        'Cost:       ' + p.cost + ' (2^' + p.cost + ' = ' + Math.pow(2, p.cost).toLocaleString() + ' iterations)',
        'Salt:       ' + p.salt,
        'Hash part:  ' + p.hashPart,
        'Full hash:  ' + h,
        'Total len:  ' + h.length + ' chars'
      ].join('\n');
      clearV(); ctx.toast('Hash inspected', 'success');
    }
    function doSwap() { inP.ta.value = outP.ta.value; outP.ta.value = ''; clearV(); ctx.toast('Output moved to input', 'success'); }
    function doShare() { var st = { c: cost, out: outSel.value, cs: saltCb.checked ? 1 : 0, salt: saltInput.value, pw: inP.ta.value, h: outP.ta.value }; CK.copy(location.href.split('#')[0] + '#tool=bcrypt&s=' + b64uEnc(JSON.stringify(st))); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; cost = 10; custInput.value = ''; outSel.value = 'full'; saltCb.checked = false; saltInput.value = ''; saltField.style.display = 'none'; clearV(); markCost(); updateSel(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); cost = st.c || 10; if (COSTS.indexOf(cost) < 0) custInput.value = cost; outSel.value = st.out || 'full'; saltCb.checked = !!st.cs; saltField.style.display = saltCb.checked ? '' : 'none'; saltInput.value = st.salt || ''; inP.ta.value = st.pw || ''; outP.ta.value = st.h || ''; } catch (e) { } }
    markCost(); updateSel();
  });
})();

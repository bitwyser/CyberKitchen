/*
   argon2.js - Argon2 hash / verify (vendored argon2-browser, WASM inlined).
   Variant d/i/id, memory/iterations/parallelism/hash length, custom salt with
   random generator, Encoded / Hash-only / JSON output.
   Verify / Detect / Swap / Share / Reset; Inspect on the output panel.
*/
(function () {
  'use strict';
  var VARIANTS = {
    d: { label: 'argon2d', badge: 'GPU hardened', desc: 'Data-dependent, maximizes GPU resistance' },
    i: { label: 'argon2i', badge: 'Timing safe', desc: 'Data-independent, timing-safe' },
    id: { label: 'argon2id', badge: 'RFC 9106', desc: 'Hybrid of d and i, recommended default' }
  };
  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }
  function parseArgon2(h) { var m = /^\$argon2([a-z]+)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$(.+)$/.exec(h); if (!m) return null; return { variant: m[1], version: +m[2], mem: +m[3], time: +m[4], par: +m[5], salt: m[6], hash: m[7] }; }
  // Rough timing estimate from the memory (MiB) x iterations product (carried over from the standalone tool)
  function timingGuide(memKiB, t) {
    var score = (memKiB / 1024) * t;
    return score <= 8 ? { msg: 'under 100 ms', badge: 'fast' }
      : score <= 32 ? { msg: '~100 to 300 ms', badge: 'good' }
      : score <= 128 ? { msg: '~300 ms to 1 s', badge: 'moderate' }
      : score <= 512 ? { msg: '~1 to 3 s', badge: 'slow' }
      : { msg: '3 s or more', badge: 'very slow' };
  }

  var I_DROP = '<path d="M12 3c3 4 5 6.5 5 10a5 5 0 0 1-10 0c0-3.5 2-6 5-10z"/>';
  var I_HASH = '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>';
  var I_CHECK = '<path d="M20 6 9 17l-5-5"/>';
  var I_DETECT = '<path d="m12 3 1.9 4.6L18 9l-4.1 1.4L12 15l-1.9-4.6L6 9l4.1-1.4zM19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9z"/>';
  var I_SWAP = '<path d="M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';
  var I_SHUF = '<path d="M18 4l3 3-3 3M21 7H8a4 4 0 0 0-4 4M6 20l-3-3 3-3M3 17h12a4 4 0 0 0 4-4"/>';

  CK.registerTool('argon2', function (root, ctx) {
    var ui = CK.ui, el = CK.el, variant = 'id';
    function o(a) { return { value: a[0], label: a[1] }; }

    root.appendChild(ui.head('Argon2', 'hash + verify'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_DROP);
    strip.desc.style.whiteSpace = 'normal'; // let the full timing guidance wrap instead of truncating
    strip.acts.appendChild(ui.iconBtn(I_DETECT, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(I_CHECK, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(I_SWAP, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    // Left column split into 4 sub-columns: variant | memory + time | parallelism + hash length | custom salt. Right column: output format only.
    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'argon-left' });
    var cfgWrap = el('div', { class: 'col' });
    var memWrap = el('div', { class: 'col' });
    var parWrap = el('div', { class: 'col' });
    var saltWrap = el('div', { class: 'col' });
    var colR = el('div', { class: 'col' });

    // Variant dropdown
    var varSel = ui.select([['id', 'argon2id'], ['i', 'argon2i'], ['d', 'argon2d']].map(o), function (v) { variant = v; updateSel(); }, 'id');
    cfgWrap.appendChild(ui.field('Variant', varSel));

    var memInput = el('input', { class: 'inp sm', type: 'number', min: '256', max: '1048576', step: '256', value: '4096', placeholder: 'KiB' });
    var timeInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '20', value: '3', placeholder: 'n' });
    var parInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '16', value: '1' });
    var lenInput = el('input', { class: 'inp sm', type: 'number', min: '16', max: '64', value: '32' });

    // Memory cost: 4 presets + custom KiB input, all on one line
    var MEMS = [[1024, '1 MB'], [4096, '4 MB'], [16384, '16 MB'], [65536, '64 MB']];
    var memBtns = {}, memRow = el('div', { style: 'display:flex; gap:5px; align-items:center; flex-wrap:wrap;' });
    MEMS.forEach(function (a) {
      var b = el('button', { class: 'eb' }); b.textContent = a[1];
      b.addEventListener('click', function () { memInput.value = a[0]; updateSel(); });
      memBtns[a[0]] = b; memRow.appendChild(b);
    });
    memInput.style.width = '92px'; memRow.appendChild(memInput);
    memInput.addEventListener('input', updateSel);
    function markMem() { MEMS.forEach(function (a) { memBtns[a[0]].classList.toggle('active', +memInput.value === a[0]); }); }
    memWrap.appendChild(ui.field('Memory cost', memRow));

    // Time cost (iterations): 5 presets + custom input, all on one line
    var TIMES = [1, 2, 3, 4, 5];
    var timeBtns = {}, timeRow = el('div', { style: 'display:flex; gap:5px; align-items:center; flex-wrap:wrap;' });
    TIMES.forEach(function (t) {
      var b = el('button', { class: 'eb' }); b.textContent = t;
      b.addEventListener('click', function () { timeInput.value = t; updateSel(); });
      timeBtns[t] = b; timeRow.appendChild(b);
    });
    timeInput.style.width = '72px'; timeRow.appendChild(timeInput);
    timeInput.addEventListener('input', updateSel);
    function markTime() { TIMES.forEach(function (t) { timeBtns[t].classList.toggle('active', +timeInput.value === t); }); }
    memWrap.appendChild(ui.field('Time cost (iterations)', timeRow));

    // Second sub-column: Parallelism + Hash length
    parWrap.appendChild(ui.field('Parallelism', parInput));
    parWrap.appendChild(ui.field('Hash length (bytes)', lenInput));

    // Custom salt (middle sub-column)
    var saltCb = el('input', { type: 'checkbox' });
    var saltSwitch = el('label', { class: 'switch' });
    saltSwitch.appendChild(saltCb); saltSwitch.appendChild(el('span', { class: 'track' })); saltSwitch.appendChild(el('span', {}, 'Custom salt'));
    saltWrap.appendChild(saltSwitch);
    var saltInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Salt (min 8 chars)' });
    var saltGen = ui.iconBtn(I_SHUF, 'Random salt', function () { var b = crypto.getRandomValues(new Uint8Array(16)), s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); saltInput.value = btoa(s).replace(/=+$/, ''); });
    var saltRow = el('div', { style: 'display:flex; gap:5px; align-items:center; overflow:hidden;' });
    saltInput.style.flex = '1'; saltInput.style.minWidth = '0'; saltRow.appendChild(saltInput); saltRow.appendChild(saltGen);
    var saltField = ui.field('Salt', saltRow); saltField.style.display = 'none';
    saltWrap.appendChild(saltField);
    saltCb.addEventListener('change', function () { saltField.style.display = saltCb.checked ? '' : 'none'; });

    colL.appendChild(cfgWrap); colL.appendChild(memWrap); colL.appendChild(parWrap); colL.appendChild(saltWrap);

    var outSel = ui.select([['encoded', 'Encoded'], ['hashonly', 'Hash only'], ['json', 'JSON']].map(o), null, 'encoded');
    colR.appendChild(ui.field('Output', outSel));

    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);
    function markVar() { varSel.value = variant; }

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'PASSWORD', icon: I_DROP, placeholder: 'Password to hash...', primaries: [{ label: 'Hash', cls: 'enc', onClick: doHash }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'password.txt' });
    var outP = ui.textPanel({ title: 'ENCODED HASH', icon: I_HASH, placeholder: 'Encoded $argon2 hash, or paste one to verify...', primaries: [{ label: 'Inspect', cls: 'dec', onClick: doInspect }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'argon2.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);
    CK.attachStrength(inP);

    function clearV() { outP.ta.classList.remove('verify-match', 'verify-fail'); inP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearV);
    outP.ta.addEventListener('input', clearV);
    function updateSel() {
      markVar(); markMem(); markTime();
      var v = VARIANTS[variant], mem = Math.max(256, +memInput.value || 4096), t = Math.max(1, +timeInput.value || 3);
      var memStr = mem >= 1024 ? ((mem / 1024) % 1 === 0 ? (mem / 1024) + ' MB' : (mem / 1024).toFixed(1) + ' MB') : mem + ' KiB';
      var g = timingGuide(mem, t);
      ui.setSel(strip, v.label, v.badge, v.desc + ' · ' + memStr + ' × t=' + t + ' · estimated ' + g.msg + ' (' + g.badge + ')');
    }
    function params() { return { mem: Math.max(256, +memInput.value || 4096), time: Math.max(1, +timeInput.value || 3), par: Math.max(1, +parInput.value || 1), len: Math.max(16, Math.min(64, +lenInput.value || 32)) }; }
    function argonType() { return { d: argon2.ArgonType.Argon2d, i: argon2.ArgonType.Argon2i, id: argon2.ArgonType.Argon2id }[variant]; }
    function formatOut(res) {
      if (outSel.value === 'hashonly') return res.encoded.split('$').pop();
      if (outSel.value === 'json') { var p = parseArgon2(res.encoded) || {}; return JSON.stringify({ algorithm: 'argon2' + p.variant, version: p.version, memoryKiB: p.mem, iterations: p.time, parallelism: p.par, salt: p.salt, hash: p.hash, encoded: res.encoded }, null, 2); }
      return res.encoded;
    }

    function doHash() {
      if (typeof argon2 === 'undefined') { ctx.toast('Argon2 library not loaded', 'error'); return; }
      var pw = inP.ta.value; if (!pw) { ctx.toast('Password is empty', 'warn'); return; }
      var p = params(), t0 = performance.now(), salt;
      if (saltCb.checked) { var sv = saltInput.value; if (sv.length < 8) { ctx.toast('Custom salt must be at least 8 characters', 'error'); return; } salt = new TextEncoder().encode(sv); }
      else salt = crypto.getRandomValues(new Uint8Array(16));
      ctx.toast('Hashing (' + VARIANTS[variant].label + ', ' + p.mem + ' KiB)...', 'success');
      return argon2.hash({ pass: pw, salt: salt, time: p.time, mem: p.mem, parallelism: p.par, hashLen: p.len, type: argonType() })
        .then(function (res) { outP.ta.value = formatOut(res); clearV(); ctx.toast('Hashed in ' + Math.round(performance.now() - t0) + ' ms', 'success'); })
        .catch(function (e) { ctx.toast('Hash failed: ' + (e.message || e), 'error'); });
    }
    function doVerify() {
      if (typeof argon2 === 'undefined') { ctx.toast('Argon2 library not loaded', 'error'); return; }
      var pw = inP.ta.value, hash = outP.ta.value.trim();
      if (!pw) { ctx.toast('Enter the password on the left', 'warn'); return; }
      if (!/^\$argon2/.test(hash)) { ctx.toast('Output is not an encoded $argon2 hash', 'error'); return; }
      argon2.verify({ pass: pw, encoded: hash })
        .then(function () { clearV(); CK.flashVerify(true, inP.ta, outP.ta); ctx.toast('Match: password is correct', 'success'); })
        .catch(function () { clearV(); CK.flashVerify(false, inP.ta, outP.ta); ctx.toast('No match', 'error'); });
    }
    function doDetect() {
      var p = parseArgon2(outP.ta.value.trim());
      if (!p) { ctx.toast('Output is not an encoded $argon2 hash', 'warn'); return; }
      if (VARIANTS[p.variant]) variant = p.variant;
      memInput.value = p.mem; timeInput.value = p.time; parInput.value = p.par; updateSel();
      ctx.toast('Detected argon2' + p.variant + ', m=' + p.mem + ' t=' + p.time + ' p=' + p.par, 'success');
    }
    function doInspect() {
      var h = outP.ta.value.trim();
      if (!h) { ctx.toast('No hash in the output panel', 'warn'); return; }
      var p = parseArgon2(h);
      if (!p) { ctx.toast('Output is not a valid $argon2 hash', 'error'); return; }
      outP.ta.value = [
        'Algorithm:   argon2' + p.variant,
        'Version:     ' + p.version,
        'Memory:      ' + p.mem + ' KiB',
        'Iterations:  ' + p.time,
        'Parallelism: ' + p.par,
        'Salt (b64):  ' + p.salt,
        'Hash (b64):  ' + p.hash,
        'Encoded:     ' + h
      ].join('\n');
      clearV(); ctx.toast('Hash inspected', 'success');
    }
    function doSwap() { inP.ta.value = outP.ta.value; outP.ta.value = ''; clearV(); ctx.toast('Output moved to input', 'success'); }
    function doShare() { var st = { v: variant, m: memInput.value, t: timeInput.value, p: parInput.value, l: lenInput.value, out: outSel.value, cs: saltCb.checked ? 1 : 0, salt: saltInput.value, pw: inP.ta.value, h: outP.ta.value }; CK.copy(location.href.split('#')[0] + '#tool=argon2&s=' + b64uEnc(JSON.stringify(st))); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; variant = 'id'; memInput.value = '4096'; timeInput.value = '3'; parInput.value = '1'; lenInput.value = '32'; outSel.value = 'encoded'; saltCb.checked = false; saltInput.value = ''; saltField.style.display = 'none'; updateSel(); clearV(); ctx.toast('Reset complete', 'success'); }

    var mm = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (mm) { try { var st = JSON.parse(b64uDec(mm[1])); if (st.v) variant = st.v; memInput.value = st.m || '4096'; timeInput.value = st.t || '3'; parInput.value = st.p || '1'; lenInput.value = st.l || '32'; outSel.value = st.out || 'encoded'; saltCb.checked = !!st.cs; saltField.style.display = saltCb.checked ? '' : 'none'; saltInput.value = st.salt || ''; inP.ta.value = st.pw || ''; outP.ta.value = st.h || ''; } catch (e) { } }
    updateSel();
  });
})();

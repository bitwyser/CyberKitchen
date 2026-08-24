/*
   argon2.js - Argon2 hash / verify tool
   Uses vendored argon2-browser (window.argon2, WASM inlined). Offline.
*/
(function () {
  'use strict';

  var VARIANTS = {
    d: { label: 'argon2d', badge: 'GPU hardened', desc: 'Data-dependent, maximizes GPU resistance' },
    i: { label: 'argon2i', badge: 'Timing safe', desc: 'Data-independent, timing-safe' },
    id: { label: 'argon2id', badge: 'RFC 9106', desc: 'Hybrid of d and i, recommended default' }
  };

  var I_DROP = '<path d="M12 3c3 4 5 6.5 5 10a5 5 0 0 1-10 0c0-3.5 2-6 5-10z"/>';
  var I_HASH = '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('argon2', function (root, ctx) {
    var ui = CK.ui, el = CK.el, variant = 'id';

    root.appendChild(ui.head('Argon2', 'hash + verify'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_DROP);
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);
    var varPk = ui.picker([{ label: 'Variant', items: [{ id: 'd', label: 'argon2d' }, { id: 'i', label: 'argon2i' }, { id: 'id', label: 'argon2id' }] }], function (id) { variant = id; varPk.setActive(id); updateSel(); });
    cfg.appendChild(varPk.el);

    var form = el('div', { class: 'cfg-form' });
    var memInput = el('input', { class: 'inp sm', type: 'number', min: '256', max: '1048576', step: '256', value: '4096' });
    var timeInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '20', value: '3' });
    var parInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '16', value: '1' });
    form.appendChild(ui.field('Memory (KiB)', memInput));
    form.appendChild(ui.field('Iterations', timeInput));
    form.appendChild(ui.field('Parallelism', parInput));
    cfg.appendChild(form);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'PASSWORD', icon: I_DROP, placeholder: 'Password to hash...', primary: { label: 'Hash', cls: 'enc', onClick: doHash }, actions: ['copy', 'paste', 'clear'] });
    var outP = ui.textPanel({ title: 'ENCODED HASH', icon: I_HASH, placeholder: 'Encoded $argon2 hash, or paste one to verify...', primary: { label: 'Verify', cls: 'dec', onClick: doVerify }, actions: ['copy', 'clear', 'download'], downloadName: 'argon2.txt', onInput: clearV });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearV() { outP.ta.classList.remove('verify-match', 'verify-fail'); }
    function updateSel() { varPk.setActive(variant); var v = VARIANTS[variant]; ui.setSel(strip, v.label, v.badge, v.desc); }
    function params() {
      return { mem: Math.max(256, +memInput.value || 4096), time: Math.max(1, +timeInput.value || 3), par: Math.max(1, +parInput.value || 1) };
    }
    function argonType() { return { d: argon2.ArgonType.Argon2d, i: argon2.ArgonType.Argon2i, id: argon2.ArgonType.Argon2id }[variant]; }

    function doHash() {
      if (typeof argon2 === 'undefined') { ctx.toast('Argon2 library not loaded', 'error'); return; }
      var pw = inP.ta.value; if (!pw) { ctx.toast('Password is empty', 'warn'); return; }
      var p = params(), salt = crypto.getRandomValues(new Uint8Array(16)), t0 = performance.now();
      ctx.toast('Hashing (' + VARIANTS[variant].label + ', ' + p.mem + ' KiB)...', 'success');
      argon2.hash({ pass: pw, salt: salt, time: p.time, mem: p.mem, parallelism: p.par, hashLen: 32, type: argonType() })
        .then(function (res) { outP.ta.value = res.encoded; clearV(); ctx.toast('Hashed in ' + Math.round(performance.now() - t0) + ' ms', 'success'); })
        .catch(function (e) { ctx.toast('Hash failed: ' + (e.message || e), 'error'); });
    }
    function doVerify() {
      if (typeof argon2 === 'undefined') { ctx.toast('Argon2 library not loaded', 'error'); return; }
      var pw = inP.ta.value, hash = outP.ta.value.trim();
      if (!pw) { ctx.toast('Enter the password on the left', 'warn'); return; }
      if (!/^\$argon2/.test(hash)) { ctx.toast('Right panel is not an encoded $argon2 hash', 'error'); return; }
      argon2.verify({ pass: pw, encoded: hash })
        .then(function () { clearV(); outP.ta.classList.add('verify-match'); ctx.toast('Match: password is correct', 'success'); })
        .catch(function () { clearV(); outP.ta.classList.add('verify-fail'); ctx.toast('No match', 'error'); });
    }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; variant = 'id'; memInput.value = '4096'; timeInput.value = '3'; parInput.value = '1'; updateSel(); clearV(); ctx.toast('Reset complete', 'success'); }

    updateSel();
    return {
      reset: doReset,
      onKey: function (e) { if (!(e.ctrlKey || e.metaKey)) return; var k = String(e.key).toLowerCase(); if (k === 'e') { e.preventDefault(); doHash(); } }
    };
  });
})();

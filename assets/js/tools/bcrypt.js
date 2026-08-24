/*
   bcrypt.js - Bcrypt hash / verify tool
   Uses vendored bcryptjs (window.bcrypt / dcodeIO.bcrypt). Offline.
*/
(function () {
  'use strict';

  function lib() { if (typeof bcrypt !== 'undefined') return bcrypt; if (typeof dcodeIO !== 'undefined' && dcodeIO.bcrypt) return dcodeIO.bcrypt; return null; }

  var I_FISH = '<path d="M6.5 12c3-5 8-5 11 0-3 5-8 5-11 0zM15 11.5v.01"/>';
  var I_HASH = '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('bcrypt', function (root, ctx) {
    var ui = CK.ui, cost = 10;

    root.appendChild(ui.head('Bcrypt', 'hash + verify'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_FISH);
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);
    var costPk = ui.picker([{ label: 'Cost (rounds)', items: [{ id: '8', label: '8' }, { id: '10', label: '10' }, { id: '12', label: '12' }, { id: '14', label: '14' }] }], function (id) { cost = +id; costPk.setActive(id); updateSel(); });
    cfg.appendChild(costPk.el);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'PASSWORD', icon: I_FISH, placeholder: 'Password to hash...', primary: { label: 'Hash', cls: 'enc', onClick: doHash }, actions: ['copy', 'paste', 'clear'] });
    var outP = ui.textPanel({ title: 'BCRYPT HASH', icon: I_HASH, placeholder: 'Hash output, or paste a $2 hash to verify...', primary: { label: 'Verify', cls: 'dec', onClick: doVerify }, actions: ['copy', 'clear', 'download'], downloadName: 'bcrypt.txt', onInput: clearV });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearV() { outP.ta.classList.remove('verify-match', 'verify-fail'); }
    function updateSel() { costPk.setActive('' + cost); ui.setSel(strip, 'bcrypt cost ' + cost, '2^' + cost, 'Blowfish-based password hashing, ' + Math.pow(2, cost) + ' iterations'); }

    function doHash() {
      var b = lib(); if (!b) { ctx.toast('bcrypt library not loaded', 'error'); return; }
      var pw = inP.ta.value; if (!pw) { ctx.toast('Password is empty', 'warn'); return; }
      var t0 = performance.now();
      ctx.toast('Hashing (cost ' + cost + ')...', 'success');
      b.hash(pw, cost, function (err, hash) {
        if (err) { ctx.toast('Hash failed: ' + err.message, 'error'); return; }
        outP.ta.value = hash; clearV();
        ctx.toast('Hashed in ' + Math.round(performance.now() - t0) + ' ms', 'success');
      });
    }
    function doVerify() {
      var b = lib(); if (!b) { ctx.toast('bcrypt library not loaded', 'error'); return; }
      var pw = inP.ta.value, hash = outP.ta.value.trim();
      if (!pw) { ctx.toast('Enter the password on the left', 'warn'); return; }
      if (!/^\$2[aby]?\$/.test(hash)) { ctx.toast('Right panel is not a bcrypt hash', 'error'); return; }
      b.compare(pw, hash, function (err, ok) {
        if (err) { ctx.toast('Verify failed: ' + err.message, 'error'); return; }
        clearV(); outP.ta.classList.add(ok ? 'verify-match' : 'verify-fail');
        ctx.toast(ok ? 'Match: password is correct' : 'No match', ok ? 'success' : 'error');
      });
    }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; cost = 10; updateSel(); clearV(); ctx.toast('Reset complete', 'success'); }

    updateSel();
    return {
      reset: doReset,
      onKey: function (e) { if (!(e.ctrlKey || e.metaKey)) return; var k = String(e.key).toLowerCase(); if (k === 'e') { e.preventDefault(); doHash(); } }
    };
  });
})();

/*
   bcrypt.js - Bcrypt hash / verify (vendored bcryptjs). Offline.
   Cost 8-14, auto or custom salt, Full-hash or Hash-only output.
*/
(function () {
  'use strict';
  function lib() { if (typeof bcrypt !== 'undefined') return bcrypt; if (typeof dcodeIO !== 'undefined' && dcodeIO.bcrypt) return dcodeIO.bcrypt; return null; }

  var I_FISH = '<path d="M6.5 12c3-5 8-5 11 0-3 5-8 5-11 0zM15 11.5v.01"/>';
  var I_HASH = '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('bcrypt', function (root, ctx) {
    var ui = CK.ui, el = CK.el, cost = 10;

    root.appendChild(ui.head('Bcrypt', 'hash + verify'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_FISH);
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);
    var costPk = ui.picker([{ label: 'Cost (rounds)', items: [{ id: '8', label: '8' }, { id: '10', label: '10' }, { id: '12', label: '12' }, { id: '14', label: '14' }] }], function (id) { cost = +id; costPk.setActive(id); updateSel(); });
    cfg.appendChild(costPk.el);

    var form = el('div', { class: 'cfg-form' });
    var outSel = ui.select([['full', 'Full hash'], ['hashonly', 'Hash only']].map(function (a) { return { value: a[0], label: a[1] }; }), null, 'full');
    form.appendChild(ui.field('Output', outSel));
    var saltTog = ui.toggle('Custom salt', false, function () { saltField.style.display = saltTog.cb.checked ? '' : 'none'; });
    form.appendChild(ui.field('Salt', saltTog.wrap));
    var saltInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: '$2a$10$22-char-salt' });
    var saltField = ui.field('Custom salt', saltInput); saltField.style.display = 'none'; saltField.style.flex = '1'; saltField.style.minWidth = '260px';
    form.appendChild(saltField);
    cfg.appendChild(form);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'PASSWORD', icon: I_FISH, placeholder: 'Password to hash...', primary: { label: 'Hash', cls: 'enc', onClick: doHash }, actions: ['copy', 'paste', 'clear'] });
    var outP = ui.textPanel({ title: 'BCRYPT HASH', icon: I_HASH, placeholder: 'Hash output, or paste a $2 hash to verify...', primary: { label: 'Verify', cls: 'dec', onClick: doVerify }, actions: ['copy', 'clear', 'download'], downloadName: 'bcrypt.txt', onInput: clearV });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearV() { outP.ta.classList.remove('verify-match', 'verify-fail'); }
    function updateSel() { costPk.setActive('' + cost); ui.setSel(strip, 'bcrypt cost ' + cost, '2^' + cost, 'Blowfish-based hashing, ' + Math.pow(2, cost) + ' iterations'); }

    function doHash() {
      var b = lib(); if (!b) { ctx.toast('bcrypt library not loaded', 'error'); return; }
      var pw = inP.ta.value; if (!pw) { ctx.toast('Password is empty', 'warn'); return; }
      var t0 = performance.now();
      function done(err, hash) {
        if (err) { ctx.toast('Hash failed: ' + err.message, 'error'); return; }
        outP.ta.value = outSel.value === 'hashonly' ? hash.slice(-31) : hash; clearV();
        ctx.toast('Hashed in ' + Math.round(performance.now() - t0) + ' ms', 'success');
      }
      if (saltTog.cb.checked) {
        var salt = saltInput.value.trim();
        if (!/^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{22}/.test(salt)) { ctx.toast('Custom salt must look like $2a$10$ + 22 chars', 'error'); return; }
        try { done(null, b.hashSync(pw, salt)); } catch (e) { done(e); }
      } else { b.hash(pw, cost, done); }
    }
    function doVerify() {
      var b = lib(); if (!b) { ctx.toast('bcrypt library not loaded', 'error'); return; }
      var pw = inP.ta.value, hash = outP.ta.value.trim();
      if (!pw) { ctx.toast('Enter the password on the left', 'warn'); return; }
      if (!/^\$2[aby]?\$/.test(hash)) { ctx.toast('Right panel is not a full bcrypt hash', 'error'); return; }
      b.compare(pw, hash, function (err, ok) { if (err) { ctx.toast('Verify failed: ' + err.message, 'error'); return; } clearV(); outP.ta.classList.add(ok ? 'verify-match' : 'verify-fail'); ctx.toast(ok ? 'Match: password is correct' : 'No match', ok ? 'success' : 'error'); });
    }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; cost = 10; outSel.value = 'full'; saltTog.cb.checked = false; saltInput.value = ''; saltField.style.display = 'none'; updateSel(); clearV(); ctx.toast('Reset complete', 'success'); }

    updateSel();
    return { reset: doReset, onKey: function (e) { if ((e.ctrlKey || e.metaKey) && String(e.key).toLowerCase() === 'e') { e.preventDefault(); doHash(); } } };
  });
})();

/*
   password.js - Password Generator tool
   Cryptographically secure (Web Crypto getRandomValues). Pure JS, offline.
*/
(function () {
  'use strict';

  var SETS = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    digits: '0123456789',
    symbols: '!@#$%^&*()-_=+[]{};:,.<>?/'
  };
  var AMBIG = /[Il1O0o|`]/g;

  function randInt(max) {
    // unbiased integer in [0, max)
    var limit = Math.floor(0x100000000 / max) * max, a = new Uint32Array(1);
    do { crypto.getRandomValues(a); } while (a[0] >= limit);
    return a[0] % max;
  }
  function shuffle(arr) { for (var i = arr.length - 1; i > 0; i--) { var j = randInt(i + 1); var t = arr[i]; arr[i] = arr[j]; arr[j] = t; } return arr; }

  var I_KEY = '<rect x="4" y="4" width="16" height="16" rx="3"/><circle cx="9" cy="9" r="1.2"/><circle cx="15" cy="15" r="1.2"/><circle cx="15" cy="9" r="1.2"/><circle cx="9" cy="15" r="1.2"/>';
  var I_GEN = '<path d="M4 12h16M12 4v16M6.3 6.3l11.4 11.4M17.7 6.3 6.3 17.7"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('password', function (root, ctx) {
    var ui = CK.ui, el = CK.el;

    root.appendChild(ui.head('Password Generator', 'secure'));

    var cfg = ui.configPanel();
    var form = el('div', { class: 'cfg-form' });

    var lenRange = el('input', { type: 'range', min: '4', max: '64', value: '16' });
    var lenVal = el('span', { class: 'range-val' }, '16');
    var lenRow = el('div', { class: 'range-row', style: 'min-width:220px' });
    lenRow.appendChild(lenRange); lenRow.appendChild(lenVal);
    form.appendChild(ui.field('Length', lenRow));

    var countInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '50', value: '1' });
    form.appendChild(ui.field('Count', countInput));

    function toggle(label, key, checked) {
      var wrap = el('label', { class: 'toggle-row' });
      var cb = el('input', { type: 'checkbox' }); cb.checked = checked; cb.dataset.set = key;
      wrap.appendChild(cb); wrap.appendChild(document.createTextNode(label));
      return { wrap: wrap, cb: cb };
    }
    var tUpper = toggle('A-Z', 'upper', true);
    var tLower = toggle('a-z', 'lower', true);
    var tDigit = toggle('0-9', 'digits', true);
    var tSym = toggle('!@#', 'symbols', true);
    var tAmbig = toggle('Exclude ambiguous', 'ambig', false);
    var togWrap = el('div', { style: 'display:flex; flex-wrap:wrap; gap:12px; align-items:center;' });
    [tUpper, tLower, tDigit, tSym, tAmbig].forEach(function (t) { togWrap.appendChild(t.wrap); });
    form.appendChild(ui.field('Character sets', togWrap));
    cfg.appendChild(form);
    root.appendChild(cfg);

    var io = ui.ioRow(true);
    var panel = el('div', { class: 'panel io-p' });
    var hdr = el('div', { class: 'panel-hdr' });
    hdr.innerHTML = CK.iconSvg(I_KEY, 12) + ' GENERATED';
    var fill = el('span', { class: 'fill' });
    var tb = el('span', { class: 'tb' });
    var genBtn = el('button', { class: 'prim enc' }, 'Generate');
    tb.appendChild(genBtn);
    tb.appendChild(ui.miniBtn('Copy', function () { CK.copy(ta.value); }));
    tb.appendChild(ui.miniBtn('Download', function () { CK.download(ta.value, 'passwords.txt'); }));
    hdr.appendChild(fill); hdr.appendChild(tb);
    panel.appendChild(hdr);

    var meta = el('div', { style: 'display:flex; align-items:center; justify-content:space-between; font-size:11px; color:var(--muted);' });
    var strLabel = el('span', {}, 'Strength');
    var entLabel = el('span', {});
    meta.appendChild(strLabel); meta.appendChild(entLabel);
    var bar = el('div', { class: 'strength' }); var barFill = el('span'); bar.appendChild(barFill);
    var ta = el('textarea', { class: 'ta', readonly: 'readonly' });
    panel.appendChild(meta); panel.appendChild(bar); panel.appendChild(ta);
    io.appendChild(panel); root.appendChild(io);

    function activeSets() {
      var pool = '', chosen = [];
      [tUpper, tLower, tDigit, tSym].forEach(function (t) {
        if (t.cb.checked) {
          var s = SETS[t.cb.dataset.set];
          if (tAmbig.cb.checked) s = s.replace(AMBIG, '');
          if (s) { pool += s; chosen.push(s); }
        }
      });
      return { pool: pool, chosen: chosen };
    }
    function onePassword(len, sets) {
      var chars = [], i;
      // guarantee at least one from each chosen set (when it fits)
      for (i = 0; i < sets.chosen.length && i < len; i++) chars.push(sets.chosen[i][randInt(sets.chosen[i].length)]);
      for (i = chars.length; i < len; i++) chars.push(sets.pool[randInt(sets.pool.length)]);
      return shuffle(chars).join('');
    }
    function strength(len, poolSize) {
      var bits = poolSize > 1 ? Math.round(len * Math.log2(poolSize)) : 0;
      var pct = Math.min(100, Math.round(bits / 128 * 100));
      var label, color;
      if (bits < 40) { label = 'Weak'; color = 'var(--err)'; }
      else if (bits < 60) { label = 'Fair'; color = 'var(--warn)'; }
      else if (bits < 80) { label = 'Strong'; color = 'var(--acc)'; }
      else { label = 'Very strong'; color = 'var(--ok)'; }
      barFill.style.width = pct + '%'; barFill.style.background = color;
      strLabel.textContent = 'Strength: ' + label;
      entLabel.textContent = bits + ' bits entropy';
    }
    function generate() {
      var sets = activeSets();
      if (!sets.pool) { ta.value = ''; ctx.toast('Select at least one character set', 'warn'); strength(0, 0); return; }
      var len = +lenRange.value, count = Math.max(1, Math.min(50, +countInput.value || 1));
      var out = []; for (var i = 0; i < count; i++) out.push(onePassword(len, sets));
      ta.value = out.join('\n');
      strength(len, sets.pool.length);
    }

    lenRange.addEventListener('input', function () { lenVal.textContent = lenRange.value; generate(); });
    countInput.addEventListener('input', generate);
    [tUpper, tLower, tDigit, tSym, tAmbig].forEach(function (t) { t.cb.addEventListener('change', generate); });
    genBtn.addEventListener('click', generate);

    generate();
    return {
      reset: function () {
        lenRange.value = '16'; lenVal.textContent = '16'; countInput.value = '1';
        tUpper.cb.checked = tLower.cb.checked = tDigit.cb.checked = tSym.cb.checked = true; tAmbig.cb.checked = false;
        generate(); ctx.toast('Reset complete', 'success');
      },
      onKey: function (e) { if ((e.ctrlKey || e.metaKey) && String(e.key).toLowerCase() === 'g') { e.preventDefault(); generate(); } }
    };
  });
})();

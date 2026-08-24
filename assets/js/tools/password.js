/*
   password.js - Password Generator (Web Crypto RNG)
   Policy presets, modes (AlphaNum/PIN/Passphrase/Custom), exclude
   ambiguous/similar, embed-your-word with leet + anchor, quantity, strength.
*/
(function () {
  'use strict';
  var SETS = { lower: 'abcdefghijklmnopqrstuvwxyz', upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', digits: '0123456789', symbols: '!@#$%^&*()-_=+[]{};:,.<>?/' };
  var SIMILAR = /[il1LoO0]/g;
  var AMBIG_SYM = /[()\[\]{}<>\/\\|'"`;:,.]/g;
  var LEET = { a: '@', e: '3', i: '1', o: '0', s: '$', t: '7', A: '@', E: '3', I: '1', O: '0', S: '$', T: '7' };
  var WORDS = 'able acid aged also area army away baby back ball band bank base bath bear beat been beer bell belt best bird blue boat body bone book born both bowl bulk burn bush busy calm came camp card care cart case cash cell chip city clay coal coat code cold cook cool cope copy core corn cost crew crop dark data date dawn days dead deal dean dear debt deep deer disk done door dose down draw drew drop drug dual duke dust duty each earn ease east easy edge fair fall farm fast fate fear feed feel feet fell felt file fill film find fine fire fish five flag flat flow food foot ford form fort four free frog fuel full fund gain game gate gave gear gene gift girl give glad goal goat gold golf gone good gray grew grey grow gulf hair half hall hand hang hard harm hate have head heat held hell help herb hero high hill hint hire hold hole holy home hope host hour huge hunt idea inch iron item jack jane jazz join jump jury keen keep kept kick kill kind king knee knew know lace lack lady laid lake land lane last late lawn lazy lead leaf lean leap left lend lens less life lift like limb lime line link lion list live load loan lock long look loop lord lose loss lost love luck lung made mail main make male mall many mark mask mass mate math meal mean meat meet mega melt menu mere mesh mild mile milk mill mind mine mint miss mode mood moon more moss most move much must myth name navy near neat neck need news next nice node none noon norm nose note noun oath obey odds okay once only open oral oval oven over pace pack page paid pain pair palm park part pass past path peak pear peer pile pill pine pink pipe plan play plot plug plus poem poet poll polo pond pool poor pope port pose post pour pray prey pull pump pure push quiz race rack rage raid rail rain rank rare rate read real reap rear rely rent rest rice rich ride ring riot rise risk road rock role roll roof room root rope rose ruby rule rush rust safe sage said sail salt same sand save scan seal seat seed seek seen self sell send sent ship shoe shop shot show sick side sign silk sing sink site size skin slip slot slow snap snow soap sock soda soft soil sold sole solo some song soon sort soul soup sour spin spot star stay stem step stir stop such suit sung sure surf swap swim tail take tale talk tall tank tape task team tear tell tend tent term test text than that them then they thin this tide tidy tied ties tile till time tiny toll tone tool torn tour town trap tray tree trim trip true tube tune turn twin type unit upon urge used user vary vast very vice view vine visa void vote wage wait wake walk wall want ward ware warm warn wash wave ways weak wear week weed well went were west what when whom wide wife wild will wind wine wing wire wise wish with wolf wood wool word wore work yard yarn yeah year yoga zero zone zoom'.split(' ');

  function randInt(max) { var limit = Math.floor(0x100000000 / max) * max, a = new Uint32Array(1); do { crypto.getRandomValues(a); } while (a[0] >= limit); return a[0] % max; }
  function pick(arr) { return arr[randInt(arr.length)]; }
  function shuffle(a) { for (var i = a.length - 1; i > 0; i--) { var j = randInt(i + 1), t = a[i]; a[i] = a[j]; a[j] = t; } return a; }
  function leetify(s) { return s.split('').map(function (c) { return LEET[c] || c; }).join(''); }

  var PRESETS = { pci: { len: 12, sets: ['upper', 'lower', 'digits', 'symbols'] }, nist: { len: 16, sets: ['upper', 'lower', 'digits', 'symbols'] }, hipaa: { len: 12, sets: ['upper', 'lower', 'digits', 'symbols'] }, owasp: { len: 14, sets: ['upper', 'lower', 'digits', 'symbols'] } };

  var I_DICE = '<rect x="4" y="4" width="16" height="16" rx="3"/><circle cx="9" cy="9" r="1.2"/><circle cx="15" cy="15" r="1.2"/><circle cx="15" cy="9" r="1.2"/><circle cx="9" cy="15" r="1.2"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('password', function (root, ctx) {
    var ui = CK.ui, el = CK.el, mode = 'custom';

    root.appendChild(ui.head('Password Generator', 'secure'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_DICE);
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var presetPk = ui.picker([{ label: 'Policy preset', items: [{ id: 'pci', label: 'PCI-DSS' }, { id: 'nist', label: 'NIST' }, { id: 'hipaa', label: 'HIPAA' }, { id: 'owasp', label: 'OWASP' }] }], applyPreset);
    cfg.appendChild(presetPk.el);
    var modePk = ui.picker([{ label: 'Mode', items: [{ id: 'custom', label: 'Custom' }, { id: 'alnum', label: 'AlphaNum' }, { id: 'pin', label: 'PIN' }, { id: 'passphrase', label: 'Passphrase' }] }], function (id) { mode = id; modePk.setActive(id); applyMode(); generate(); });
    cfg.appendChild(modePk.el);

    var form = el('div', { class: 'cfg-form' });
    var lenRange = el('input', { type: 'range', min: '4', max: '64', value: '16' });
    var lenVal = el('span', { class: 'range-val' }, '16');
    var lenRow = el('div', { class: 'range-row', style: 'min-width:220px' }); lenRow.appendChild(lenRange); lenRow.appendChild(lenVal);
    var lenField = ui.field('Length', lenRow); form.appendChild(lenField);
    var qtyInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '100', value: '5' });
    form.appendChild(ui.field('Quantity', qtyInput));
    function tog(label, key, checked) { var t = ui.toggle(label, checked, generate); t.cb.dataset.set = key; return t; }
    var tUpper = tog('A-Z', 'upper', true), tLower = tog('a-z', 'lower', true), tDigit = tog('0-9', 'digits', true), tSym = tog('!@#', 'symbols', true);
    var tAmbig = ui.toggle('No ambiguous', false, generate), tSim = ui.toggle('No similar', false, generate);
    var setsWrap = el('div', { style: 'display:flex; flex-wrap:wrap; gap:12px; align-items:center;' });
    [tUpper, tLower, tDigit, tSym, tAmbig, tSim].forEach(function (t) { setsWrap.appendChild(t.wrap); });
    var setsField = ui.field('Character sets', setsWrap); form.appendChild(setsField);
    cfg.appendChild(form);

    var embedForm = el('div', { class: 'cfg-form' });
    var wordInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Embed a word (optional)' });
    var wf = ui.field('Embed word', wordInput); wf.style.flex = '1'; wf.style.minWidth = '200px'; embedForm.appendChild(wf);
    var leetTog = ui.toggle('Leet', false, generate); embedForm.appendChild(ui.field('Transform', leetTog.wrap));
    var anchorSel = ui.select([['start', 'At start'], ['end', 'At end'], ['middle', 'Middle'], ['random', 'Random']].map(function (a) { return { value: a[0], label: a[1] }; }), generate, 'random');
    embedForm.appendChild(ui.field('Anchor', anchorSel));
    wordInput.addEventListener('input', generate);
    cfg.appendChild(embedForm);
    root.appendChild(cfg);

    var io = ui.ioRow(true);
    var panel = el('div', { class: 'panel io-p' });
    var hdr = el('div', { class: 'panel-hdr' }); hdr.innerHTML = CK.iconSvg(I_DICE, 12) + ' GENERATED';
    var fill = el('span', { class: 'fill' }); var tb = el('span', { class: 'tb' });
    var genBtn = el('button', { class: 'prim enc' }, 'Generate');
    tb.appendChild(genBtn); tb.appendChild(ui.miniBtn('Copy', function () { CK.copy(ta.value); })); tb.appendChild(ui.miniBtn('Download', function () { CK.download(ta.value, 'passwords.txt'); }));
    hdr.appendChild(fill); hdr.appendChild(tb); panel.appendChild(hdr);
    var meta = el('div', { style: 'display:flex; justify-content:space-between; font-size:11px; color:var(--muted);' });
    var strLabel = el('span', {}, 'Strength'), entLabel = el('span', {}); meta.appendChild(strLabel); meta.appendChild(entLabel);
    var bar = el('div', { class: 'strength' }); var barFill = el('span'); bar.appendChild(barFill);
    var ta = el('textarea', { class: 'ta', readonly: 'readonly' });
    panel.appendChild(meta); panel.appendChild(bar); panel.appendChild(ta);
    io.appendChild(panel); root.appendChild(io);

    function applyPreset(id) { presetPk.setActive(id); var p = PRESETS[id]; mode = 'custom'; modePk.setActive('custom'); lenRange.value = p.len; lenVal.textContent = p.len; tUpper.cb.checked = p.sets.indexOf('upper') >= 0; tLower.cb.checked = p.sets.indexOf('lower') >= 0; tDigit.cb.checked = p.sets.indexOf('digits') >= 0; tSym.cb.checked = p.sets.indexOf('symbols') >= 0; applyMode(); generate(); }
    function applyMode() {
      var pass = mode === 'passphrase', pin = mode === 'pin';
      setsField.style.display = (pass || pin) ? 'none' : '';
      embedForm.style.display = pass ? 'none' : '';
      lenField.querySelector('label').textContent = pass ? 'Words' : 'Length';
      if (pass) { lenRange.min = 3; lenRange.max = 10; if (+lenRange.value > 10 || +lenRange.value < 3) { lenRange.value = 5; lenVal.textContent = 5; } }
      else { lenRange.min = pin ? 3 : 4; lenRange.max = pin ? 12 : 64; }
      if (mode === 'alnum') { tUpper.cb.checked = tLower.cb.checked = tDigit.cb.checked = true; tSym.cb.checked = false; }
    }
    function pool() {
      var p = '';
      if (mode === 'pin') return SETS.digits;
      [tUpper, tLower, tDigit, tSym].forEach(function (t) { if (t.cb.checked) { var s = SETS[t.cb.dataset.set]; if (t.cb.dataset.set === 'symbols' && tAmbig.cb.checked) s = s.replace(AMBIG_SYM, ''); p += s; } });
      if (tSim.cb.checked) p = p.replace(SIMILAR, '');
      return p;
    }
    function chosenSets() { var arr = []; [tUpper, tLower, tDigit, tSym].forEach(function (t) { if (t.cb.checked) { var s = SETS[t.cb.dataset.set]; if (t.cb.dataset.set === 'symbols' && tAmbig.cb.checked) s = s.replace(AMBIG_SYM, ''); if (tSim.cb.checked) s = s.replace(SIMILAR, ''); if (s) arr.push(s); } }); return arr; }

    function onePassphrase(n) { var w = []; for (var i = 0; i < n; i++) { var word = pick(WORDS); w.push(word.charAt(0).toUpperCase() + word.slice(1)); } return w.join('-') + randInt(100); }
    function embed(pw) {
      var word = wordInput.value.trim(); if (!word) return pw;
      if (leetTog.cb.checked) word = leetify(word);
      var a = anchorSel.value, base = pw.slice(0, Math.max(0, pw.length - word.length));
      if (a === 'start') return word + base;
      if (a === 'end') return base + word;
      var idx = a === 'middle' ? (base.length / 2 | 0) : randInt(base.length + 1);
      return base.slice(0, idx) + word + base.slice(idx);
    }
    function onePassword(len) {
      var p = pool(); if (!p) return '';
      var sets = mode === 'pin' ? [SETS.digits] : chosenSets();
      var chars = [], i;
      for (i = 0; i < sets.length && i < len; i++) chars.push(sets[i][randInt(sets[i].length)]);
      for (i = chars.length; i < len; i++) chars.push(p[randInt(p.length)]);
      return embed(shuffle(chars).join(''));
    }
    function strength(entropyBits) {
      var pct = Math.min(100, Math.round(entropyBits / 128 * 100)), label, color;
      if (entropyBits < 40) { label = 'Weak'; color = 'var(--err)'; } else if (entropyBits < 60) { label = 'Fair'; color = 'var(--warn)'; } else if (entropyBits < 80) { label = 'Strong'; color = 'var(--acc)'; } else { label = 'Very strong'; color = 'var(--ok)'; }
      barFill.style.width = pct + '%'; barFill.style.background = color; strLabel.textContent = 'Strength: ' + label; entLabel.textContent = Math.round(entropyBits) + ' bits entropy';
    }
    function generate() {
      lenVal.textContent = lenRange.value;
      var qty = Math.max(1, Math.min(100, +qtyInput.value || 1)), out = [], i, ent;
      if (mode === 'passphrase') { var n = +lenRange.value; for (i = 0; i < qty; i++) out.push(onePassphrase(n)); ent = n * Math.log2(WORDS.length) + Math.log2(100); }
      else { var p = pool(); if (!p) { ta.value = ''; ctx.toast('Select at least one character set', 'warn'); strength(0); return; } var len = +lenRange.value; for (i = 0; i < qty; i++) out.push(onePassword(len)); ent = len * Math.log2(p.length); }
      ta.value = out.join('\n'); strength(ent);
    }

    lenRange.addEventListener('input', generate);
    qtyInput.addEventListener('input', generate);
    genBtn.addEventListener('click', generate);
    applyMode(); generate();

    return {
      reset: doReset,
      onKey: function (e) { if ((e.ctrlKey || e.metaKey) && String(e.key).toLowerCase() === 'g') { e.preventDefault(); generate(); } }
    };
    function doReset() { mode = 'custom'; modePk.setActive('custom'); presetPk.setActive(null); lenRange.min = 4; lenRange.max = 64; lenRange.value = '16'; lenVal.textContent = '16'; qtyInput.value = '5'; tUpper.cb.checked = tLower.cb.checked = tDigit.cb.checked = tSym.cb.checked = true; tAmbig.cb.checked = tSim.cb.checked = false; wordInput.value = ''; leetTog.cb.checked = false; anchorSel.value = 'random'; applyMode(); generate(); ctx.toast('Reset complete', 'success'); }
  });
})();

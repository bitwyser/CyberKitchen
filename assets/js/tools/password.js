/*
   password.js - Password Generator (Web Crypto RNG)
   Policy presets, modes (AlphaNum/PIN/Passphrase/Custom), character-set and
   option switches, custom symbols, guarantee-each-type, no-consecutive-repeat,
   embed-your-word with leet + anchor, quantity, live strength meter.
*/
(function () {
  'use strict';
  var SETS = { lower: 'abcdefghijklmnopqrstuvwxyz', upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', digits: '0123456789', symbols: '!@#$%^&*()-_=+[]{};:,.<>?/' };
  var DEFAULT_SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';
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
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';
  function b64uEnc(s) { var b = new TextEncoder().encode(s), x = ''; b.forEach(function (c) { x += String.fromCharCode(c); }); return btoa(x).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; var bin = atob(s), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  CK.registerTool('password', function (root, ctx) {
    var ui = CK.ui, el = CK.el, mode = 'custom';

    root.appendChild(ui.head('Password Generator', 'secure'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_DICE);
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var presetPk = ui.picker([{ label: 'Policy preset', items: [{ id: 'pci', label: 'PCI-DSS' }, { id: 'nist', label: 'NIST' }, { id: 'hipaa', label: 'HIPAA' }, { id: 'owasp', label: 'OWASP' }] }], applyPreset);
    var modePk = ui.picker([{ label: 'Mode', items: [{ id: 'custom', label: 'Custom' }, { id: 'alnum', label: 'AlphaNum' }, { id: 'pin', label: 'PIN' }, { id: 'passphrase', label: 'Passphrase' }] }], function (id) { mode = id; modePk.setActive(id); applyMode(); generate(); });
    var topRow = el('div', { class: 'pw-top' });
    topRow.appendChild(presetPk.el); topRow.appendChild(modePk.el);
    cfg.appendChild(topRow);
    var row2 = el('div', { class: 'pw-row' });
    cfg.appendChild(row2);

    // A labelled toggle switch: label on the left, switch on the right
    function switchRow(label, checked, key) {
      var cb = el('input', { type: 'checkbox' }); cb.checked = !!checked;
      var sw = el('label', { class: 'switch' }); sw.appendChild(cb); sw.appendChild(el('span', { class: 'track' }));
      var row = el('div', { class: 'pw-opt' });
      row.appendChild(el('span', { class: 'pw-opt-label' }, label)); row.appendChild(sw);
      cb.addEventListener('change', generate);
      if (key) cb.dataset.set = key;
      return { row: row, cb: cb };
    }

    var grid = el('div', { class: 'pw-grid' });
    var c1 = el('div', { class: 'col' }), c2 = el('div', { class: 'col' }), c3 = el('div', { class: 'col' }), c4 = el('div', { class: 'col' });

    // Column 1: Character sets (switches)
    var tUpper = switchRow('Uppercase A-Z', true, 'upper'), tLower = switchRow('Lowercase a-z', true, 'lower'),
      tDigit = switchRow('Numbers 0-9', true, 'digits'), tSym = switchRow('Symbols', true, 'symbols');
    var setsBox = el('div', { class: 'pw-opts' });
    [tUpper, tLower, tDigit, tSym].forEach(function (t) { setsBox.appendChild(t.row); });
    var setsField = ui.field('Character sets', setsBox); c1.appendChild(setsField);

    // Column 2: Options (switches)
    var tAmbig = switchRow('Exclude ambiguous characters', false), tSim = switchRow('Exclude similar characters', false),
      tGuar = switchRow('Guarantee one of each type', true), tNoRep = switchRow('No consecutive repeats', false);
    var optBox = el('div', { class: 'pw-opts' });
    [tAmbig, tSim, tGuar, tNoRep].forEach(function (t) { optBox.appendChild(t.row); });
    var optField = ui.field('Options', optBox); c2.appendChild(optField);

    // Row under the pickers: Quantity first, then Length / Words (both slider + number)
    var qtyRange = el('input', { type: 'range', class: 'slim', min: '1', max: '100', value: '5' });
    var qtyInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '100', value: '5' });
    var qtyRow = el('div', { class: 'length-row' }); qtyRow.appendChild(qtyRange); qtyRow.appendChild(qtyInput);
    row2.appendChild(ui.field('Quantity', qtyRow));
    var lenRange = el('input', { type: 'range', class: 'slim', min: '4', max: '128', value: '16' });
    var lenNum = el('input', { class: 'inp sm', type: 'number', min: '4', max: '128', value: '16' });
    var lenRow = el('div', { class: 'length-row' }); lenRow.appendChild(lenRange); lenRow.appendChild(lenNum);
    var lenField = ui.field('Length', lenRow); row2.appendChild(lenField);

    // Column 3: Custom symbols + Embed word
    var symInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', value: DEFAULT_SYMBOLS, placeholder: 'Symbols to draw from' });
    symInput.addEventListener('input', generate);
    var symField = ui.field('Custom symbols', symInput); c3.appendChild(symField);
    var wordInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'e.g. tiger, 2024' });
    wordInput.addEventListener('input', generate);
    var embField = ui.field('Embed word (optional)', wordInput); c3.appendChild(embField);

    // Column 4: Transform + Anchor
    var leetTog = switchRow('Leet transform', false);
    var leetBox = el('div', { class: 'pw-opts' }); leetBox.appendChild(leetTog.row);
    var leetField = ui.field('Transform', leetBox); c4.appendChild(leetField);
    var anchorSel = ui.select([['start', 'At start'], ['end', 'At end'], ['middle', 'Middle'], ['random', 'Random']].map(function (a) { return { value: a[0], label: a[1] }; }), generate, 'random');
    var anchorField = ui.field('Anchor position', anchorSel); c4.appendChild(anchorField);

    grid.appendChild(c1); grid.appendChild(c2); grid.appendChild(c3); grid.appendChild(c4);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow(true);
    var outP = ui.textPanel({ title: 'GENERATED', icon: I_DICE, readonly: true, primaries: [{ label: 'Generate', cls: 'enc', onClick: generate }], actions: ['copy', 'download'], downloadName: 'passwords.txt' });
    var ta = outP.ta;
    var strBadge = el('span', { class: 'pw-strength' }); outP.panel.appendChild(strBadge);
    var ccEl = outP.panel.querySelector('.char-count');
    io.appendChild(outP.panel); root.appendChild(io);

    function setBounds(mn, mx) { lenRange.min = lenNum.min = mn; lenRange.max = lenNum.max = mx; }
    function setLen(v) { lenRange.value = v; lenNum.value = v; }
    function setQty(v) { qtyRange.value = v; qtyInput.value = v; }
    function symbolsSet() { var s = symInput.value; return (s && s.length) ? s : SETS.symbols; }

    function applyPreset(id) {
      presetPk.setActive(id); var p = PRESETS[id]; mode = 'custom'; modePk.setActive('custom');
      setBounds(4, 128); setLen(p.len);
      tUpper.cb.checked = p.sets.indexOf('upper') >= 0; tLower.cb.checked = p.sets.indexOf('lower') >= 0;
      tDigit.cb.checked = p.sets.indexOf('digits') >= 0; tSym.cb.checked = p.sets.indexOf('symbols') >= 0;
      applyMode(); generate();
    }
    function applyMode() {
      var pass = mode === 'passphrase', pin = mode === 'pin', hideChar = pass || pin;
      setsField.style.display = hideChar ? 'none' : '';
      symField.style.display = hideChar ? 'none' : '';
      optField.style.display = hideChar ? 'none' : '';
      embField.style.display = hideChar ? 'none' : '';
      leetField.style.display = hideChar ? 'none' : '';
      anchorField.style.display = hideChar ? 'none' : '';
      lenField.querySelector('label').textContent = pass ? 'Words' : 'Length';
      if (pass) { setBounds(3, 10); if (+lenRange.value > 10 || +lenRange.value < 3) setLen(5); }
      else setBounds(pin ? 3 : 4, pin ? 12 : 128);
      if (mode === 'alnum') { tUpper.cb.checked = tLower.cb.checked = tDigit.cb.checked = true; tSym.cb.checked = false; }
    }
    function pool() {
      var p = '';
      if (mode === 'pin') return SETS.digits;
      [tUpper, tLower, tDigit, tSym].forEach(function (t) {
        if (t.cb.checked) {
          var key = t.cb.dataset.set, s = key === 'symbols' ? symbolsSet() : SETS[key];
          if (key === 'symbols' && tAmbig.cb.checked) s = s.replace(AMBIG_SYM, '');
          p += s;
        }
      });
      if (tSim.cb.checked) p = p.replace(SIMILAR, '');
      return p;
    }
    function chosenSets() {
      var arr = [];
      [tUpper, tLower, tDigit, tSym].forEach(function (t) {
        if (t.cb.checked) {
          var key = t.cb.dataset.set, s = key === 'symbols' ? symbolsSet() : SETS[key];
          if (key === 'symbols' && tAmbig.cb.checked) s = s.replace(AMBIG_SYM, '');
          if (tSim.cb.checked) s = s.replace(SIMILAR, '');
          if (s) arr.push(s);
        }
      });
      return arr;
    }
    function noRepeat(s, p) {
      if (p.length < 2) return s;
      var arr = s.split('');
      for (var i = 1; i < arr.length; i++) { var tries = 0; while (arr[i] === arr[i - 1] && tries < 30) { arr[i] = p[randInt(p.length)]; tries++; } }
      return arr.join('');
    }

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
      var chars = [], i;
      if (tGuar.cb.checked) {
        var sets = mode === 'pin' ? [SETS.digits] : chosenSets();
        for (i = 0; i < sets.length && i < len; i++) chars.push(sets[i][randInt(sets[i].length)]);
      }
      for (i = chars.length; i < len; i++) chars.push(p[randInt(p.length)]);
      var body = shuffle(chars).join('');
      if (tNoRep.cb.checked) body = noRepeat(body, p);
      return embed(body);
    }
    function strength(entropyBits) {
      var label, cls;
      if (entropyBits < 40) { label = 'Weak'; cls = 'err'; } else if (entropyBits < 60) { label = 'Fair'; cls = 'warn'; } else if (entropyBits < 80) { label = 'Strong'; cls = 'acc'; } else { label = 'Very strong'; cls = 'ok'; }
      strBadge.style.display = entropyBits > 0 ? '' : 'none';
      strBadge.textContent = label + ' · ' + Math.round(entropyBits) + ' bits';
      strBadge.className = 'pw-strength ' + cls;
      strBadge.style.right = (23 + (ccEl ? ccEl.offsetWidth : 0) + 8) + 'px';
    }
    function generate() {
      var qty = Math.max(1, Math.min(100, +qtyInput.value || 1)), out = [], i, ent;
      if (mode === 'passphrase') { var n = +lenRange.value; for (i = 0; i < qty; i++) out.push(onePassphrase(n)); ent = n * Math.log2(WORDS.length) + Math.log2(100); }
      else { var p = pool(); if (!p) { ta.value = ''; ctx.toast('Select at least one character set', 'warn'); strength(0); return; } var len = +lenRange.value; for (i = 0; i < qty; i++) out.push(onePassword(len)); ent = len * Math.log2(p.length); }
      ta.value = out.join('\n'); strength(ent);
    }

    lenRange.addEventListener('input', function () { lenNum.value = lenRange.value; generate(); });
    lenNum.addEventListener('input', function () { lenRange.value = lenNum.value; generate(); });
    lenNum.addEventListener('change', function () { lenNum.value = lenRange.value; });
    qtyRange.addEventListener('input', function () { qtyInput.value = qtyRange.value; generate(); });
    qtyInput.addEventListener('input', function () { qtyRange.value = qtyInput.value; generate(); });
    qtyInput.addEventListener('change', function () { qtyInput.value = qtyRange.value; });

    var sm = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (sm) {
      try {
        var st = JSON.parse(b64uDec(sm[1]));
        if (st.m) { mode = st.m; modePk.setActive(mode); }
        if (st.l) setLen(st.l);
        if (st.q) setQty(st.q);
        if ('u' in st) { tUpper.cb.checked = st.u; tLower.cb.checked = st.lo; tDigit.cb.checked = st.d; tSym.cb.checked = st.y; }
        if ('amb' in st) { tAmbig.cb.checked = st.amb; tSim.cb.checked = st.sim; }
        if ('guar' in st) tGuar.cb.checked = st.guar;
        if ('nr' in st) tNoRep.cb.checked = st.nr;
        if (st.sym != null) symInput.value = st.sym;
        if (st.w) wordInput.value = st.w; if ('leet' in st) leetTog.cb.checked = st.leet; if (st.anc) anchorSel.value = st.anc;
      } catch (e) { }
    }
    applyMode(); generate();

    return {
      reset: doReset,
      onKey: function (e) { if ((e.ctrlKey || e.metaKey) && String(e.key).toLowerCase() === 'g') { e.preventDefault(); generate(); } }
    };
    function doShare() {
      CK.copy(location.href.split('#')[0] + '#tool=password&s=' + b64uEnc(JSON.stringify({
        m: mode, l: +lenRange.value, q: +qtyInput.value,
        u: tUpper.cb.checked, lo: tLower.cb.checked, d: tDigit.cb.checked, y: tSym.cb.checked,
        amb: tAmbig.cb.checked, sim: tSim.cb.checked, guar: tGuar.cb.checked, nr: tNoRep.cb.checked, sym: symInput.value,
        w: wordInput.value, leet: leetTog.cb.checked, anc: anchorSel.value
      })));
    }
    function doReset() {
      mode = 'custom'; modePk.setActive('custom'); presetPk.setActive(null);
      setBounds(4, 128); setLen(16); setQty(5);
      tUpper.cb.checked = tLower.cb.checked = tDigit.cb.checked = tSym.cb.checked = true;
      tAmbig.cb.checked = tSim.cb.checked = tNoRep.cb.checked = false; tGuar.cb.checked = true;
      symInput.value = DEFAULT_SYMBOLS;
      wordInput.value = ''; leetTog.cb.checked = false; anchorSel.value = 'random';
      applyMode(); generate(); ctx.toast('Reset complete', 'success');
    }
  });
})();

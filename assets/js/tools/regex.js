/*
   regex.js - Regex Tester
   Live testing with match list, capture groups (numbered and named), flags,
   a highlighted rendering of the subject, and a library of common patterns.
   Uses the native RegExp engine. Pure JS, no dependencies.
*/
(function () {
  'use strict';

  var FLAGS = [['g', 'global'], ['i', 'ignore case'], ['m', 'multiline'], ['s', 'dotall'], ['u', 'unicode'], ['y', 'sticky']];
  var COMMON = [
    ['', 'Common patterns...'],
    ['[\\w.+-]+@[\\w-]+\\.[\\w.-]+', 'Email address'],
    ['https?://[\\w.-]+(?:/[\\w./?%&=-]*)?', 'URL (http/https)'],
    ['(?:\\d{1,3}\\.){3}\\d{1,3}', 'IPv4 address'],
    ['#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})\\b', 'Hex color'],
    ['\\d{4}-\\d{2}-\\d{2}', 'Date (YYYY-MM-DD)'],
    ['[+]?[0-9][0-9 ()-]{7,}[0-9]', 'Phone number'],
    ['\\b[A-Za-z0-9._%+-]+\\b', 'Word / token'],
    ['"(?:[^"\\\\]|\\\\.)*"', 'Double-quoted string'],
    ['<([a-z]+)(?:[^<]*?)>.*?</\\1>', 'HTML tag pair']
  ];

  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  var I_REGEX = '<path d="M17 3v6M14.5 4.5l5 3M14.5 7.5l5-3M5 20a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM7 14V4"/>';
  var I_OUT = '<path d="M4 7h16M4 12h16M4 17h10"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('regex', function (root, ctx) {
    var ui = CK.ui, el = CK.el;
    function o(a) { return { value: a[0], label: a[1] }; }

    root.appendChild(ui.head('Regex Tester', 'live'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_REGEX);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col' });
    var colR = el('div', { class: 'col' });

    var patInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'pattern, e.g. (\\w+)@(\\w+)' });
    patInput.addEventListener('input', run);
    colL.appendChild(ui.field('Pattern', patInput));

    // Flags as multi-select toggle buttons
    var flagState = { g: true, i: false, m: false, s: false, u: false, y: false };
    var flagBtns = {}, flagRow = el('div', { style: 'display:flex; gap:5px; align-items:center; flex-wrap:wrap;' });
    FLAGS.forEach(function (f) {
      var b = el('button', { class: 'eb', title: f[1] }); b.textContent = f[0];
      b.addEventListener('click', function () { flagState[f[0]] = !flagState[f[0]]; markFlags(); run(); });
      flagBtns[f[0]] = b; flagRow.appendChild(b);
    });
    colL.appendChild(ui.field('Flags', flagRow));

    var commonSel = ui.select(COMMON.map(function (c) { return { value: c[0], label: c[1] }; }), function (v) { if (v) { patInput.value = v; run(); } }, '');
    colR.appendChild(ui.field('Insert pattern', commonSel));
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'TEST STRING', icon: I_REGEX, placeholder: 'Text to test the pattern against...', primaries: [{ label: 'Test', cls: 'enc', onClick: run }], actions: ['copy', 'paste', 'clear'], onInput: run });
    var outP = ui.textPanel({ title: 'MATCHES', icon: I_OUT, placeholder: 'Matches and capture groups appear here...', readonly: true, actions: ['copy'] });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function markFlags() { FLAGS.forEach(function (f) { flagBtns[f[0]].classList.toggle('active', flagState[f[0]]); }); }
    function flagStr() { return FLAGS.map(function (f) { return f[0]; }).filter(function (k) { return flagState[k]; }).join(''); }

    function run() {
      var pat = patInput.value;
      if (!pat) { outP.ta.value = ''; ui.setSel(strip, 'Regex Tester', 'RegExp', 'Enter a pattern to test.'); return; }
      var flags = flagStr(), re;
      try { re = new RegExp(pat, flags); } catch (e) { outP.ta.value = ''; ui.setSel(strip, 'Invalid pattern', 'error', e.message); CK.flashVerify(false, inP.ta); return; }
      inP.ta.classList.remove('verify-match', 'verify-fail');
      var text = inP.ta.value, matches = [], m, guard = 0;
      var reAll = new RegExp(pat, flags.indexOf('g') >= 0 ? flags : flags + 'g');
      while ((m = reAll.exec(text)) !== null) {
        matches.push(m);
        if (m.index === reAll.lastIndex) reAll.lastIndex++;
        if (++guard > 100000) break;
      }
      ui.setSel(strip, '/' + pat + '/' + flags, matches.length + (matches.length === 1 ? ' match' : ' matches'), matches.length ? 'Pattern is valid and matched.' : 'Pattern is valid, no matches.');
      if (!matches.length) { outP.ta.value = 'No matches.'; return; }
      var lines = [matches.length + (matches.length === 1 ? ' match' : ' matches') + ':\n'];
      matches.forEach(function (mm, i) {
        lines.push('Match ' + (i + 1) + ' at index ' + mm.index + ': ' + JSON.stringify(mm[0]));
        for (var g = 1; g < mm.length; g++) if (mm[g] !== undefined) lines.push('  Group ' + g + ': ' + JSON.stringify(mm[g]));
        if (mm.groups) Object.keys(mm.groups).forEach(function (name) { lines.push('  Group "' + name + '": ' + JSON.stringify(mm.groups[name])); });
      });
      // Highlighted rendering with matches wrapped in guillemets
      var hi = '', pos = 0;
      matches.forEach(function (mm) { hi += text.slice(pos, mm.index) + '«' + mm[0] + '»'; pos = mm.index + mm[0].length; });
      hi += text.slice(pos);
      lines.push('\nHighlighted (matches in « »):\n' + hi);
      outP.ta.value = lines.join('\n');
    }
    function doShare() { CK.copy(location.href.split('#')[0] + '#tool=regex&s=' + b64uEnc(JSON.stringify({ p: patInput.value, f: flagStr(), in: inP.ta.value }))); }
    function doReset() { patInput.value = ''; inP.ta.value = ''; outP.ta.value = ''; commonSel.value = ''; flagState = { g: true, i: false, m: false, s: false, u: false, y: false }; markFlags(); inP.ta.classList.remove('verify-match', 'verify-fail'); ctx.toast('Reset complete', 'success'); }

    var m0 = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m0) { try { var st = JSON.parse(b64uDec(m0[1])); patInput.value = st.p || ''; inP.ta.value = st.in || ''; if (st.f != null) FLAGS.forEach(function (f) { flagState[f[0]] = st.f.indexOf(f[0]) >= 0; }); } catch (e) { } }
    markFlags(); run();
  });
})();

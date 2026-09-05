/*
   diff.js - Text Diff
   Compare two texts by line or word, shown inline (unified) or side-by-side,
   with an additions / deletions summary. LCS-based. Pure JS, no dependencies.
*/
(function () {
  'use strict';

  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  // LCS diff of two token arrays -> [{t:-1|0|1, v}]
  function diffTokens(a, b) {
    var n = a.length, m = b.length;
    if (n * m > 6000000) return null; // too large for the quadratic table
    var dp = new Array(n + 1);
    for (var i = 0; i <= n; i++) dp[i] = new Uint32Array(m + 1);
    for (i = n - 1; i >= 0; i--) for (var j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    var ops = []; i = 0; j = 0;
    while (i < n && j < m) { if (a[i] === b[j]) { ops.push({ t: 0, v: a[i] }); i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) { ops.push({ t: -1, v: a[i] }); i++; } else { ops.push({ t: 1, v: b[j] }); j++; } }
    while (i < n) ops.push({ t: -1, v: a[i++] });
    while (j < m) ops.push({ t: 1, v: b[j++] });
    return ops;
  }
  function padEnd(s, w) { s = String(s); if (s.length >= w) return s.slice(0, w); while (s.length < w) s += ' '; return s; }

  var I_DIFF = '<path d="M9 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h4M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M12 3v18"/>';
  var I_OUT = '<path d="M4 7h16M4 12h16M4 17h10"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('diff', function (root, ctx) {
    var ui = CK.ui, el = CK.el;
    function o(a) { return { value: a[0], label: a[1] }; }

    root.appendChild(ui.head('Text Diff', 'compare'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_DIFF);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col2' });
    var colR = el('div', { class: 'col' });
    var granSel = ui.select([['line', 'Line'], ['word', 'Word']].map(o), run, 'line');
    var viewSel = ui.select([['inline', 'Inline (unified)'], ['side', 'Side-by-side']].map(o), run, 'inline');
    colL.appendChild(ui.field('Granularity', granSel)); colL.appendChild(ui.field('View', viewSel));
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var aP = ui.textPanel({ title: 'ORIGINAL', icon: I_DIFF, placeholder: 'Original text...', primaries: [{ label: 'Compare', cls: 'enc', onClick: run }], actions: ['copy', 'paste', 'clear'], onInput: run });
    var bP = ui.textPanel({ title: 'CHANGED', icon: I_DIFF, placeholder: 'Changed text...', actions: ['copy', 'paste', 'clear'], onInput: run });
    io.appendChild(aP.panel); io.appendChild(bP.panel);
    root.appendChild(io);

    var io2 = ui.ioRow(true);
    var outP = ui.textPanel({ title: 'DIFF', icon: I_OUT, placeholder: 'Differences appear here...', readonly: true, actions: ['copy', 'download'], downloadName: 'diff.txt' });
    io2.appendChild(outP.panel);
    root.appendChild(io2);

    function tokens(s) { return granSel.value === 'word' ? s.split(/(\s+)/) : s.split('\n'); }

    function run() {
      var a = aP.ta.value, b = bP.ta.value;
      if (!a && !b) { outP.ta.value = ''; ui.setSel(strip, 'Text Diff', 'LCS', 'Enter text in both panels to compare.'); return; }
      var ops = diffTokens(tokens(a), tokens(b));
      if (!ops) { outP.ta.value = 'Inputs are too large to diff.'; ui.setSel(strip, 'Text Diff', 'too large', 'Reduce the input size.'); return; }
      var adds = 0, dels = 0;
      ops.forEach(function (op) { if (op.t === 1) adds++; else if (op.t === -1) dels++; });
      ui.setSel(strip, 'Text Diff', '+' + adds + ' / -' + dels, adds + ' additions, ' + dels + ' deletions (' + granSel.value + ' level)');

      var out;
      if (granSel.value === 'word') {
        out = ops.map(function (op) { return op.t === 0 ? op.v : op.t === -1 ? '[-' + op.v + '-]' : '{+' + op.v + '+}'; }).join('');
      } else if (viewSel.value === 'side') {
        var rows = [], left = [], right = [];
        function flush() { var n = Math.max(left.length, right.length); for (var i = 0; i < n; i++) rows.push(padEnd(left[i] || '', 44) + ' | ' + (right[i] || '')); left = []; right = []; }
        ops.forEach(function (op) {
          if (op.t === 0) { flush(); rows.push(padEnd('  ' + op.v, 44) + ' |   ' + op.v); }
          else if (op.t === -1) left.push('- ' + op.v);
          else right.push('+ ' + op.v);
        });
        flush();
        out = rows.join('\n');
      } else {
        out = ops.map(function (op) { return (op.t === 0 ? '  ' : op.t === -1 ? '- ' : '+ ') + op.v; }).join('\n');
      }
      outP.ta.value = out;
    }
    function doShare() { CK.copy(location.href.split('#')[0] + '#tool=diff&s=' + b64uEnc(JSON.stringify({ a: aP.ta.value, b: bP.ta.value, g: granSel.value, v: viewSel.value }))); }
    function doReset() { aP.ta.value = ''; bP.ta.value = ''; outP.ta.value = ''; granSel.value = 'line'; viewSel.value = 'inline'; ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); aP.ta.value = st.a || ''; bP.ta.value = st.b || ''; granSel.value = st.g || 'line'; viewSel.value = st.v || 'inline'; } catch (e) { } }
    run();
  });
})();

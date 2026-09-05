/*
   ipconv.js - IP Converter (IPv4)
   Convert an IPv4 address between dotted-decimal, 32-bit integer, hexadecimal
   and binary. Auto-detects the input form and shows every representation.
   Pure math, no dependencies.
*/
(function () {
  'use strict';

  function ipStr(n) { n = n >>> 0; return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); }
  function parseDotted(s) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim());
    if (!m) return null;
    var o = [+m[1], +m[2], +m[3], +m[4]];
    for (var i = 0; i < 4; i++) if (o[i] > 255) return null;
    return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
  }
  // Detect the input form; returns { fmt, n } or null
  function toInt(s, fmt) {
    s = s.trim();
    if (!s) return null;
    var n;
    if (fmt === 'auto') {
      if (s.indexOf('.') >= 0 && /^[0-9.]+$/.test(s)) fmt = 'dotted';
      else if (/^0x[0-9a-f]+$/i.test(s)) fmt = 'hex';
      else if (/^[01]{1,32}$/.test(s)) fmt = 'binary';
      else if (/^\d+$/.test(s)) fmt = 'integer';
      else return null;
    }
    if (fmt === 'dotted') { n = parseDotted(s); }
    else if (fmt === 'hex') { if (!/^(0x)?[0-9a-f]+$/i.test(s)) return null; n = parseInt(s.replace(/^0x/i, ''), 16); }
    else if (fmt === 'binary') { if (!/^[01]+$/.test(s)) return null; n = parseInt(s, 2); }
    else { if (!/^\d+$/.test(s)) return null; n = Number(s); }
    if (n == null || isNaN(n) || n < 0 || n > 4294967295) return null;
    return { fmt: fmt, n: n >>> 0 };
  }
  function binOctets(n) { n = n >>> 0; return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].map(function (x) { return x.toString(2).padStart(8, '0'); }).join('.'); }

  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  var I_GLOBE = '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/>';
  var I_OUT = '<path d="M4 7h16M4 12h16M4 17h10"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('ipconv', function (root, ctx) {
    var ui = CK.ui, el = CK.el;
    function o(a) { return { value: a[0], label: a[1] }; }

    root.appendChild(ui.head('IP Converter', 'IPv4'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_GLOBE);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col' });
    var colR = el('div', { class: 'col' });
    var fmtSel = ui.select([['auto', 'Auto-detect'], ['dotted', 'Dotted decimal'], ['integer', 'Integer'], ['hex', 'Hexadecimal'], ['binary', 'Binary']].map(o), run, 'auto');
    colR.appendChild(ui.field('Input format', fmtSel));
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: I_GLOBE, placeholder: '192.168.1.10  ·  3232235786  ·  0xC0A8010A  ·  binary', primaries: [{ label: 'Convert', cls: 'enc', onClick: run }], actions: ['copy', 'paste', 'clear'], onInput: run });
    var outP = ui.textPanel({ title: 'REPRESENTATIONS', icon: I_OUT, placeholder: 'All representations appear here...', readonly: true, actions: ['copy', 'download'], downloadName: 'ip.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function pad(k) { return (k + ':').padEnd(18, ' '); }
    function run() {
      var r = toInt(inP.ta.value, fmtSel.value);
      if (!r) { outP.ta.value = ''; ui.setSel(strip, 'IP Converter', 'IPv4', 'Enter an IPv4 address, integer, hexadecimal or binary value.'); return; }
      var n = r.n;
      ui.setSel(strip, ipStr(n), fmtSel.value === 'auto' ? 'detected ' + r.fmt : r.fmt, '32-bit IPv4 address, ' + n.toLocaleString() + ' as integer');
      outP.ta.value = [
        pad('Dotted decimal') + ipStr(n),
        pad('Integer') + n,
        pad('Hexadecimal') + '0x' + n.toString(16).toUpperCase().padStart(8, '0'),
        pad('Binary') + binOctets(n),
        pad('Octal') + '0o' + n.toString(8),
        pad('Per-octet') + [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(' . ')
      ].join('\n');
    }
    function doShare() { CK.copy(location.href.split('#')[0] + '#tool=ipconv&s=' + b64uEnc(JSON.stringify({ in: inP.ta.value, f: fmtSel.value }))); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; fmtSel.value = 'auto'; run(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); fmtSel.value = st.f || 'auto'; inP.ta.value = st.in || ''; } catch (e) { } }
    run();
  });
})();

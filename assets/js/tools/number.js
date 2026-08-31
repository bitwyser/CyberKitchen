/*
   number.js - Number Converter
   Parse a value in an input base, output it in any target representation:
   bases (bin/oct/dec/hex/base32/36/58/62/custom), signed (two's/one's
   complement, sign-magnitude, excess-K), Gray, BCD, IEEE-754, sci/eng, hex
   formats. Input panel + output panel; Convert / Swap / Detect / Share / Reset.
*/
(function () {
  'use strict';
  var STD = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  var B32 = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
  var B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  var B62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  var BASES = [['bin', 'Binary'], ['oct', 'Octal'], ['dec', 'Decimal'], ['hex', 'Hex'], ['b32', 'Base32'], ['b36', 'Base36'], ['b58', 'Base58'], ['b62', 'Base62'], ['cust', 'Custom']];
  var OUT_GROUPS = [
    { label: 'Bases', items: BASES.map(function (b) { return { id: b[0], label: b[1] }; }) },
    { label: 'Signed', items: [['twos', "Two's complement"], ['ones', "One's complement"], ['smag', 'Sign-magnitude'], ['excess', 'Excess-K'], ['gray', 'Gray code']].map(function (a) { return { id: a[0], label: a[1] }; }) },
    { label: 'Codes', items: [{ id: 'bcd', label: 'BCD' }] },
    { label: 'Floating point', items: [['ieee32', 'IEEE-754 32'], ['ieee64', 'IEEE-754 64'], ['sci', 'Scientific'], ['eng', 'Engineering']].map(function (a) { return { id: a[0], label: a[1] }; }) }
  ];
  // Input accepts every representation, including the floating-point views (IEEE-754 bits, scientific / engineering)
  var IN_GROUPS = OUT_GROUPS;
  function isBase(id) { for (var i = 0; i < BASES.length; i++) if (BASES[i][0] === id) return true; return false; }
  // Only the fixed-width signed representations depend on a bit width
  function usesWidth(id) { return id === 'twos' || id === 'ones' || id === 'smag' || id === 'excess'; }
  function labelOf(id) { var i; for (i = 0; i < BASES.length; i++) if (BASES[i][0] === id) return BASES[i][1]; for (i = 0; i < OUT_GROUPS.length; i++) for (var j = 0; j < OUT_GROUPS[i].items.length; j++) if (OUT_GROUPS[i].items[j].id === id) return OUT_GROUPS[i].items[j].label; return id; }

  function alphaOf(id, custBase) {
    if (id === 'bin') return '01'; if (id === 'oct') return STD.slice(0, 8); if (id === 'dec') return STD.slice(0, 10);
    if (id === 'hex') return STD.slice(0, 16); if (id === 'b32') return B32; if (id === 'b36') return STD;
    if (id === 'b58') return B58; if (id === 'b62') return B62; if (id === 'cust') return STD.slice(0, custBase);
    return STD.slice(0, 10);
  }
  function caseSensitive(id) { return id === 'b58' || id === 'b62'; }
  function parseAlpha(str, alphabet, cs) {
    str = str.trim(); if (!str) return null; var neg = false;
    if (str[0] === '-') { neg = true; str = str.slice(1); }
    str = str.replace(/^0x/i, '').replace(/^0b/i, '').replace(/^0o/i, '');
    if (!cs) str = str.toUpperCase();
    var base = BigInt(alphabet.length), n = 0n;
    for (var i = 0; i < str.length; i++) { var v = alphabet.indexOf(str[i]); if (v < 0) throw new Error('Invalid digit "' + str[i] + '"'); n = n * base + BigInt(v); }
    return neg ? -n : n;
  }
  function parseBinStr(raw) { var s = raw.replace(/[^01]/g, ''); if (!s) return 0n; var n = 0n; for (var i = 0; i < s.length; i++) n = (n << 1n) | (s[i] === '1' ? 1n : 0n); return n; }
  function parseInput(raw, id, width, custBase) {
    if (isBase(id)) return parseAlpha(raw, alphaOf(id, custBase), caseSensitive(id));
    var W = BigInt(width), mask = (1n << W) - 1n, half = 1n << (W - 1n);
    switch (id) {
      case 'twos': { var b = parseBinStr(raw) & mask; return b >= half ? b - (1n << W) : b; }
      case 'ones': { var c = parseBinStr(raw) & mask; return (c & half) !== 0n ? -(mask - c) : c; }
      case 'smag': { var d = parseBinStr(raw) & mask; var mg = d & (half - 1n); return (d & half) !== 0n ? -mg : mg; }
      case 'excess': { var e = parseBinStr(raw) & mask; return e - half; }
      case 'gray': { var g = parseBinStr(raw), m = g >> 1n; while (m > 0n) { g ^= m; m >>= 1n; } return g; }
      case 'bcd': { var neg = /^\s*-/.test(raw); var bits = raw.replace(/[^01]/g, ''); if (bits.length % 4) throw new Error('BCD needs whole 4-bit groups'); var ds = ''; for (var i = 0; i + 4 <= bits.length; i += 4) { var dg = parseInt(bits.substr(i, 4), 2); if (dg > 9) throw new Error('Invalid BCD nibble ' + bits.substr(i, 4)); ds += dg; } var v = BigInt(ds || '0'); return neg ? -v : v; }
      // Floating point inputs return a JS Number (may be fractional)
      case 'ieee32': { var h32 = raw.replace(/[^0-9a-fA-F]/g, ''); if (!h32) return 0; var dv32 = new DataView(new ArrayBuffer(4)); dv32.setUint32(0, parseInt(h32.padStart(8, '0').slice(-8), 16) >>> 0); return dv32.getFloat32(0); }
      case 'ieee64': { var h64 = raw.replace(/[^0-9a-fA-F]/g, '').padStart(16, '0').slice(-16); var dv64 = new DataView(new ArrayBuffer(8)); dv64.setUint32(0, parseInt(h64.slice(0, 8), 16) >>> 0); dv64.setUint32(4, parseInt(h64.slice(8), 16) >>> 0); return dv64.getFloat64(0); }
      case 'sci': case 'eng': { var f = parseFloat(raw.replace(/\s+/g, '')); if (isNaN(f)) throw new Error('Not a valid number'); return f; }
    }
    throw new Error('Cannot parse this input type');
  }
  function toAlpha(n, alphabet) { var base = BigInt(alphabet.length); if (n === 0n) return alphabet[0]; var neg = n < 0n, x = neg ? -n : n, s = ''; while (x > 0n) { s = alphabet[Number(x % base)] + s; x = x / base; } return (neg ? '-' : '') + s; }
  function ieee(bits, val) { var dv = new DataView(new ArrayBuffer(8)); if (bits === 32) { dv.setFloat32(0, val); return dv.getUint32(0).toString(16).padStart(8, '0'); } dv.setFloat64(0, val); return dv.getUint32(0).toString(16).padStart(8, '0') + dv.getUint32(4).toString(16).padStart(8, '0'); }
  function eng(val) { if (!isFinite(val)) return String(val); if (val === 0) return '0e+0'; var e = Math.floor(Math.log10(Math.abs(val))), en = Math.floor(e / 3) * 3, m = val / Math.pow(10, en); return (+m.toPrecision(7)) + 'e' + (en >= 0 ? '+' : '') + en; }
  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }
  // Best-effort input-type guess. Prefixes and spacing are reliable; a bare digit
  // string is reported as the smallest base whose alphabet fits it. Signed integer
  // conventions (two's/one's/sign-magnitude/excess/Gray) look identical to binary,
  // so they cannot be told apart and are reported as Binary.
  function detectType(raw) {
    var s = (raw || '').trim(); if (!s) return null;
    if (s[0] === '-') s = s.slice(1).trim();
    if (/^0x/i.test(s)) return 'hex';
    if (/^0b/i.test(s)) return 'bin';
    if (/^0o/i.test(s)) return 'oct';
    if (/\./.test(s) || /^[+-]?\d*\.?\d+e[+-]?\d+$/i.test(s)) return 'sci';
    if (/\s/.test(s)) {
      var toks = s.split(/\s+/);
      if (toks.every(function (t) { return /^[01]{4}$/.test(t); })) return 'bin';
      if (toks.every(function (t) { return /^[0-9a-fA-F]{2}$/.test(t); })) return 'hex';
      s = s.replace(/\s+/g, '');
    }
    if (/^[01]+$/.test(s)) return 'bin';
    if (/^[0-7]+$/.test(s)) return 'oct';
    if (/^[0-9]+$/.test(s)) return 'dec';
    if (/^[0-9a-fA-F]+$/.test(s)) return 'hex';
    var U = s.toUpperCase();
    if (/^[0-9A-V]+$/.test(U)) return 'b32';
    if (/^[0-9A-Z]+$/.test(U)) return 'b36';
    if (s.split('').every(function (ch) { return B58.indexOf(ch) >= 0; })) return 'b58';
    if (s.split('').every(function (ch) { return B62.indexOf(ch) >= 0; })) return 'b62';
    return null;
  }

  var I_HASH = '<path d="M6 4v16M6 4h4a3 3 0 0 1 0 6H6M14 4h4v6h-4zM14 14h4v6h-4z"/>';
  var I_OUT = '<path d="M7 7 3 12l4 5M17 7l4 5-4 5M14 4l-4 16"/>';
  var I_CHECK = '<path d="M20 6 9 17l-5-5"/>';
  var I_SWAP = '<path d="M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4"/>';
  var I_DETECT = '<path d="m12 3 1.9 4.6L18 9l-4.1 1.4L12 15l-1.9-4.6L6 9l4.1-1.4zM19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9z"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('number', function (root, ctx) {
    var ui = CK.ui, el = CK.el, from = 'dec', outId = 'hex', inWidth = 32, outWidth = 32, inCustBase = 3, outCustBase = 3;
    function o(a) { return { value: a[0], label: a[1] }; }

    root.appendChild(ui.head('Number Converter', BASES.length + ' bases'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_HASH);
    strip.acts.appendChild(ui.iconBtn(I_DETECT, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(I_CHECK, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(I_SWAP, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    // Input base picker | Output representation picker
    var grid = el('div', { class: 'cfg-grid' }); grid.style.alignItems = 'start';
    var colL = el('div', { class: 'col' });
    var colR = el('div', { class: 'col' });
    var inPk = ui.picker(IN_GROUPS, function (id) { from = id; syncOpts(); convert(); });
    inPk.el.classList.add('stacked'); colL.appendChild(inPk.el);
    var outPk = ui.picker(OUT_GROUPS, function (id) { outId = id; syncOpts(); convert(); });
    outPk.el.classList.add('stacked'); colR.appendChild(outPk.el);
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);

    var form = el('div', { class: 'cfg-form' });
    function mkWidth(cb) { return ui.select([['8', '8-bit'], ['16', '16-bit'], ['32', '32-bit'], ['64', '64-bit']].map(o), cb, '32'); }
    var widthSelIn = mkWidth(function (v) { inWidth = +v; convert(); });
    var widthFieldIn = ui.field('Input bit width', widthSelIn); widthFieldIn.style.display = 'none';
    form.appendChild(widthFieldIn);
    var custInputIn = el('input', { class: 'inp sm', type: 'number', min: '2', max: '36', value: '3' });
    var custFieldIn = ui.field('Custom input base', custInputIn); custFieldIn.style.display = 'none';
    custInputIn.addEventListener('input', function () { inCustBase = Math.max(2, Math.min(36, +custInputIn.value || 2)); convert(); });
    form.appendChild(custFieldIn);
    var widthSelOut = mkWidth(function (v) { outWidth = +v; convert(); });
    var widthFieldOut = ui.field('Output bit width', widthSelOut); widthFieldOut.style.display = 'none';
    form.appendChild(widthFieldOut);
    var custInputOut = el('input', { class: 'inp sm', type: 'number', min: '2', max: '36', value: '3' });
    var custFieldOut = ui.field('Custom output base', custInputOut); custFieldOut.style.display = 'none';
    custInputOut.addEventListener('input', function () { outCustBase = Math.max(2, Math.min(36, +custInputOut.value || 2)); convert(); });
    form.appendChild(custFieldOut);
    cfg.appendChild(form);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: I_HASH, placeholder: 'Enter a value...', primaries: [{ label: 'Convert', cls: 'enc', onClick: convert }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'input.txt', onInput: convert });
    var outP = ui.textPanel({ title: 'OUTPUT', icon: I_OUT, placeholder: 'Result appears here...', actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'number.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function syncOpts() {
      custFieldIn.style.display = from === 'cust' ? '' : 'none';
      custFieldOut.style.display = outId === 'cust' ? '' : 'none';
      widthFieldIn.style.display = usesWidth(from) ? '' : 'none';
      widthFieldOut.style.display = usesWidth(outId) ? '' : 'none';
    }
    function decStr(f) { return Object.is(f, -0) ? '0' : (Math.abs(f) !== 0 && (Math.abs(f) < 1e-6 || Math.abs(f) >= 1e21)) ? f.toExponential() : String(f); }
    function computeOutput(val) {
      var isBig = typeof val === 'bigint';
      var fv = isBig ? Number(val.toString()) : val;
      // Floating-point outputs always apply, integer or not
      switch (outId) {
        case 'ieee32': return ieee(32, fv).toUpperCase();
        case 'ieee64': return ieee(64, fv).toUpperCase();
        case 'sci': return isFinite(fv) ? fv.toExponential() : String(fv);
        case 'eng': return eng(fv);
      }
      // Integer representations: a fractional value only has a Decimal form
      if (!isBig) {
        if (!isFinite(val)) return String(val);
        if (!Number.isInteger(val)) return outId === 'dec' ? decStr(val) : '(non-integer, use Decimal or Scientific)';
      }
      var n = isBig ? val : BigInt(val);
      var mag = n < 0n ? -n : n, W = BigInt(outWidth), mask = (1n << W) - 1n, half = 1n << (W - 1n);
      switch (outId) {
        case 'bin': return n.toString(2);
        case 'oct': return n.toString(8);
        case 'dec': return n.toString(10);
        case 'hex': return (n < 0n ? '-' : '') + mag.toString(16).toUpperCase();
        case 'b32': return toAlpha(n, B32);
        case 'b36': return toAlpha(n, STD);
        case 'b58': return n < 0n ? '(n/a for negative)' : toAlpha(n, B58);
        case 'b62': return n < 0n ? '(n/a for negative)' : toAlpha(n, B62);
        case 'cust': return toAlpha(n, STD.slice(0, outCustBase));
        case 'twos': return (n & mask).toString(2).padStart(outWidth, '0');
        case 'ones': return (n >= 0n ? (n & mask) : (mask - mag)).toString(2).padStart(outWidth, '0');
        case 'smag': return (((n < 0n ? 1n : 0n) << (W - 1n)) | (mag & (half - 1n))).toString(2).padStart(outWidth, '0');
        case 'excess': return ((n + half) & mask).toString(2).padStart(outWidth, '0') + '  (K=' + half.toString() + ')';
        case 'gray': return (mag ^ (mag >> 1n)).toString(2);
        case 'bcd': var bcd = '', ds = mag.toString(10); for (var i = 0; i < ds.length; i++) bcd += (+ds[i]).toString(2).padStart(4, '0') + ' '; return (n < 0n ? '- ' : '') + bcd.trim();
      }
      return '';
    }
    function clearVerify() { outP.ta.classList.remove('verify-match', 'verify-fail'); inP.ta.classList.remove('verify-match', 'verify-fail'); }
    function convert() {
      clearVerify();
      inPk.setActive(from); outPk.setActive(outId);
      var raw = inP.ta.value;
      if (!raw.trim()) { outP.ta.value = ''; ui.setSel(strip, 'Number', labelOf(from), 'Enter a value to convert'); return; }
      try {
        var val = parseInput(raw, from, inWidth, inCustBase);
        if (val === null || val === undefined) { outP.ta.value = ''; return; }
        outP.ta.value = computeOutput(val);
        var isBig = typeof val === 'bigint', dv = isBig ? val.toString(10) : decStr(val);
        ui.setSel(strip, labelOf(from) + ' → ' + labelOf(outId), dv, (isBig ? 'Decimal ' + dv : 'Value ' + dv));
      } catch (err) { outP.ta.value = ''; ctx.toast(err.message, 'error'); }
    }

    function doVerify() {
      try {
        var left = inP.ta.value.trim(), right = outP.ta.value.trim();
        if (!left || !right) throw new Error('Both panels need content');
        var a = parseInput(left, from, inWidth, inCustBase);
        var b = parseInput(right, outId, outWidth, outCustBase);
        var match = (typeof a === 'bigint' && typeof b === 'bigint') ? (a === b) : (Math.abs(Number(a.toString()) - Number(b.toString())) < 1e-9);
        clearVerify(); CK.flashVerify(match, inP.ta, outP.ta);
        ctx.toast(match ? 'Match: both panels are the same value' : 'No match', match ? 'success' : 'error');
      } catch (err) { ctx.toast(err.message, 'error'); }
    }
    function doSwap() {
      var t = from; from = outId; outId = t;
      var w = inWidth; inWidth = outWidth; outWidth = w; widthSelIn.value = '' + inWidth; widthSelOut.value = '' + outWidth;
      var cb = inCustBase; inCustBase = outCustBase; outCustBase = cb; custInputIn.value = inCustBase; custInputOut.value = outCustBase;
      inP.ta.value = outP.ta.value; outP.ta.value = ''; syncOpts(); convert();
      ctx.toast('Swapped', 'success');
    }
    function doDetect() {
      var s = inP.ta.value.trim(); if (!s) { ctx.toast('Enter a value first', 'warn'); return; }
      var id = detectType(s);
      if (id) { from = id; syncOpts(); convert(); ctx.toast('Detected input type: ' + labelOf(from), 'success'); }
      else ctx.toast('Could not detect the input type', 'warn');
    }
    function doShare() { CK.copy(location.href.split('#')[0] + '#tool=number&s=' + b64uEnc(JSON.stringify({ i: from, o: outId, iw: inWidth, ow: outWidth, icb: inCustBase, ocb: outCustBase, v: inP.ta.value }))); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; from = 'dec'; outId = 'hex'; inWidth = 32; outWidth = 32; widthSelIn.value = '32'; widthSelOut.value = '32'; inCustBase = 3; outCustBase = 3; custInputIn.value = '3'; custInputOut.value = '3'; syncOpts(); convert(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); if (st.i) from = st.i; if (st.o) outId = st.o; if (st.iw) { inWidth = st.iw; widthSelIn.value = '' + inWidth; } if (st.ow) { outWidth = st.ow; widthSelOut.value = '' + outWidth; } if (st.icb) { inCustBase = st.icb; custInputIn.value = inCustBase; } if (st.ocb) { outCustBase = st.ocb; custInputOut.value = outCustBase; } inP.ta.value = st.v || ''; } catch (e) { } }
    syncOpts(); convert();
  });
})();

/*
   number.js - Number Converter
   Bases (bin/oct/dec/hex/base32/36/58/62/custom), signed representations
   (two's/one's complement, sign-magnitude, excess-K), Gray code, BCD,
   IEEE-754 32/64, scientific/engineering notation, bit widths, hex formats.
*/
(function () {
  'use strict';
  var STD = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  var B32 = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
  var B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  var B62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

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
    if (!cs) str = str.toUpperCase();
    var base = BigInt(alphabet.length), n = 0n;
    for (var i = 0; i < str.length; i++) { var v = alphabet.indexOf(str[i]); if (v < 0) throw new Error('Invalid digit "' + str[i] + '"'); n = n * base + BigInt(v); }
    return neg ? -n : n;
  }
  function toAlpha(n, alphabet) { var base = BigInt(alphabet.length); if (n === 0n) return alphabet[0]; var neg = n < 0n, x = neg ? -n : n, s = ''; while (x > 0n) { s = alphabet[Number(x % base)] + s; x = x / base; } return (neg ? '-' : '') + s; }
  function grp(s, n, sep) { var r = ''; for (var i = 0; i < s.length; i++) { if (i && (s.length - i) % n === 0) r += sep; r += s[i]; } return r; }

  function ieee(bits, val) { var dv = new DataView(new ArrayBuffer(8)); if (bits === 32) { dv.setFloat32(0, val); return dv.getUint32(0).toString(16).padStart(8, '0'); } dv.setFloat64(0, val); return dv.getUint32(0).toString(16).padStart(8, '0') + dv.getUint32(4).toString(16).padStart(8, '0'); }
  function eng(val) { if (!isFinite(val)) return String(val); if (val === 0) return '0e+0'; var e = Math.floor(Math.log10(Math.abs(val))), en = Math.floor(e / 3) * 3, m = val / Math.pow(10, en); return (+m.toPrecision(7)) + 'e' + (en >= 0 ? '+' : '') + en; }

  var I_HASH = '<path d="M6 4v16M6 4h4a3 3 0 0 1 0 6H6M14 4h4v6h-4zM14 14h4v6h-4z"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('number', function (root, ctx) {
    var ui = CK.ui, el = CK.el, from = 'dec', width = 32, custBase = 3;

    root.appendChild(ui.head('Number Converter', 'radix'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_HASH);
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var form = el('div', { class: 'cfg-form' });
    var input = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Enter a value...' });
    var vf = ui.field('Value', input); vf.style.flex = '1'; vf.style.minWidth = '220px'; form.appendChild(vf);
    var baseSel = ui.select([['bin', 'Binary'], ['oct', 'Octal'], ['dec', 'Decimal'], ['hex', 'Hexadecimal'], ['b32', 'Base32'], ['b36', 'Base36'], ['b58', 'Base58'], ['b62', 'Base62'], ['cust', 'Custom base']].map(o), function (v) { from = v; custField.style.display = v === 'cust' ? '' : 'none'; convert(); }, 'dec');
    form.appendChild(ui.field('Input base', baseSel));
    var custInput = el('input', { class: 'inp sm', type: 'number', min: '2', max: '36', value: '3' });
    var custField = ui.field('Custom base', custInput); custField.style.display = 'none'; form.appendChild(custField);
    custInput.addEventListener('input', function () { custBase = Math.max(2, Math.min(36, +custInput.value || 2)); convert(); });
    var widthSel = ui.select([['8', '8-bit'], ['16', '16-bit'], ['32', '32-bit'], ['64', '64-bit']].map(o), function (v) { width = +v; convert(); }, '32');
    form.appendChild(ui.field('Bit width', widthSel));
    cfg.appendChild(form);
    root.appendChild(cfg);
    function o(a) { return { value: a[0], label: a[1] }; }

    var io = ui.ioRow(true);
    var panel = el('div', { class: 'panel io-p' });
    var hdr = el('div', { class: 'panel-hdr' }); hdr.innerHTML = CK.iconSvg(I_HASH, 12) + ' REPRESENTATIONS';
    panel.appendChild(hdr);
    var body = el('div', { style: 'overflow:auto; flex:1;' }); panel.appendChild(body);
    io.appendChild(panel); root.appendChild(io);

    var rows = {};
    function section(t) { body.appendChild(el('div', { class: 'pk-label', style: 'text-align:left; padding:8px 0 2px;' }, t)); }
    function addRow(key) { var r = el('div', { class: 'row-out' }); var k = el('span', { class: 'k' }, key); var v = el('span', { class: 'v' }, '-'); var cp = ui.miniBtn('Copy', function () { CK.copy(v.textContent); }); r.appendChild(k); r.appendChild(v); r.appendChild(cp); body.appendChild(r); rows[key] = v; }
    section('Bases'); ['Binary', 'Octal', 'Decimal', 'Hex', 'Base32', 'Base36', 'Base58', 'Base62'].forEach(addRow);
    section('Signed (bit width)'); ["Two's complement", "One's complement", 'Sign-magnitude', 'Excess-K', 'Gray code'].forEach(addRow);
    section('Codes'); ['BCD'].forEach(addRow);
    section('Floating point'); ['IEEE-754 32', 'IEEE-754 64', 'Scientific', 'Engineering'].forEach(addRow);
    section('Formatted'); ['Hex 0x', 'Hex spaced', 'Binary grouped'].forEach(addRow);
    section('Info'); ['Bit length', 'Bytes'].forEach(addRow);

    function setAll(v) { Object.keys(rows).forEach(function (k) { rows[k].textContent = v; }); }
    function convert() {
      var raw = input.value; if (!raw.trim()) { setAll('-'); ui.setSel(strip, 'Number', baseSel.value, 'Enter a value to convert'); return; }
      try {
        var n = parseAlpha(raw, alphaOf(from, custBase), caseSensitive(from));
        if (n === null) { setAll('-'); return; }
        var mag = n < 0n ? -n : n;
        rows['Binary'].textContent = n.toString(2);
        rows['Octal'].textContent = n.toString(8);
        rows['Decimal'].textContent = n.toString(10);
        rows['Hex'].textContent = (n < 0n ? '-' : '') + mag.toString(16).toUpperCase();
        rows['Base32'].textContent = toAlpha(n, B32);
        rows['Base36'].textContent = toAlpha(n, STD);
        rows['Base58'].textContent = n < 0n ? '(n/a for negative)' : toAlpha(n, B58);
        rows['Base62'].textContent = n < 0n ? '(n/a for negative)' : toAlpha(n, B62);

        var W = BigInt(width), mask = (1n << W) - 1n, half = 1n << (W - 1n);
        var fits = n >= -half && n < (1n << W);
        var over = fits ? '' : '  (overflow at ' + width + '-bit)';
        var tc = n & mask;
        rows["Two's complement"].textContent = tc.toString(2).padStart(width, '0') + over;
        var oc = n >= 0n ? (n & mask) : (mask - mag);
        rows["One's complement"].textContent = oc.toString(2).padStart(width, '0') + over;
        var sm = ((n < 0n ? 1n : 0n) << (W - 1n)) | (mag & (half - 1n));
        rows['Sign-magnitude'].textContent = sm.toString(2).padStart(width, '0') + over;
        var ex = (n + half) & mask;
        rows['Excess-K'].textContent = ex.toString(2).padStart(width, '0') + '  (K=' + half.toString() + ')';
        var g = mag ^ (mag >> 1n);
        rows['Gray code'].textContent = g.toString(2);

        var bcd = ''; var ds = mag.toString(10); for (var i = 0; i < ds.length; i++) bcd += (+ds[i]).toString(2).padStart(4, '0') + ' ';
        rows['BCD'].textContent = (n < 0n ? '- ' : '') + bcd.trim();

        var fv = Number(n.toString(10));
        rows['IEEE-754 32'].textContent = ieee(32, fv).toUpperCase();
        rows['IEEE-754 64'].textContent = ieee(64, fv).toUpperCase();
        rows['Scientific'].textContent = fv.toExponential();
        rows['Engineering'].textContent = eng(fv);

        var hx = mag.toString(16).toUpperCase(); if (hx.length % 2) hx = '0' + hx;
        rows['Hex 0x'].textContent = (n < 0n ? '-' : '') + '0x' + hx;
        rows['Hex spaced'].textContent = (n < 0n ? '-' : '') + grp(hx, 2, ' ');
        rows['Binary grouped'].textContent = grp(mag.toString(2), 4, ' ');

        var bits = mag === 0n ? 1 : mag.toString(2).length;
        rows['Bit length'].textContent = bits + ' bit' + (bits === 1 ? '' : 's');
        rows['Bytes'].textContent = Math.ceil(bits / 8) + ' byte' + (Math.ceil(bits / 8) === 1 ? '' : 's');

        ui.setSel(strip, n.toString(10), baseSel.options ? baseSel.value : from, 'Parsed from ' + baseSel.value + ' at ' + width + '-bit');
      } catch (err) { setAll('-'); rows['Decimal'].textContent = err.message; }
    }

    input.addEventListener('input', convert);
    convert();
    return { reset: doReset };
    function doReset() { input.value = ''; from = 'dec'; baseSel.value = 'dec'; width = 32; widthSel.value = '32'; custField.style.display = 'none'; convert(); ctx.toast('Reset complete', 'success'); }
  });
})();

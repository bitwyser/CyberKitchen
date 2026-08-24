/*
   number.js - Number Converter tool
   Convert an integer between binary, octal, decimal and hex (BigInt, any size).
*/
(function () {
  'use strict';

  var BASES = [
    { id: 'bin', label: 'Binary', base: 2 },
    { id: 'oct', label: 'Octal', base: 8 },
    { id: 'dec', label: 'Decimal', base: 10 },
    { id: 'hex', label: 'Hex', base: 16 }
  ];
  function baseOf(id) { for (var i = 0; i < BASES.length; i++) if (BASES[i].id === id) return BASES[i]; return null; }

  function digitVal(ch) {
    var c = ch.charCodeAt(0);
    if (c >= 48 && c <= 57) return c - 48;
    if (c >= 97 && c <= 122) return c - 97 + 10;
    if (c >= 65 && c <= 90) return c - 65 + 10;
    return -1;
  }
  function parseInBase(str, base) {
    str = str.trim(); if (!str) return null;
    var neg = false;
    if (str[0] === '-') { neg = true; str = str.slice(1); }
    else if (str[0] === '+') str = str.slice(1);
    // tolerate 0x / 0b / 0o prefixes matching the base
    str = str.replace(/^0x/i, '').replace(/^0b/i, '').replace(/^0o/i, '');
    if (!str) return null;
    var big = BigInt(base), n = 0n;
    for (var i = 0; i < str.length; i++) {
      var v = digitVal(str[i]);
      if (v < 0 || v >= base) throw new Error('Invalid digit "' + str[i] + '" for ' + base);
      n = n * big + BigInt(v);
    }
    return neg ? -n : n;
  }

  var I_HASH = '<path d="M6 4v16M6 4h4a3 3 0 0 1 0 6H6M14 4h4v6h-4zM14 14h4v6h-4z"/>';

  CK.registerTool('number', function (root, ctx) {
    var ui = CK.ui, el = CK.el, from = 'dec';

    root.appendChild(ui.head('Number Converter', 'radix'));

    var cfg = ui.configPanel();
    var pk = ui.picker([{ label: 'Input base', items: BASES.map(function (b) { return { id: b.id, label: b.label }; }) }], function (id) { from = id; input.placeholder = 'Enter ' + baseOf(id).label.toLowerCase() + ' value...'; convert(); });
    cfg.appendChild(pk.el);

    var form = el('div', { class: 'cfg-form' });
    var input = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off' });
    input.placeholder = 'Enter decimal value...';
    form.appendChild(ui.field('Value', input));
    cfg.appendChild(form);
    root.appendChild(cfg);

    var io = ui.ioRow(true);
    var panel = el('div', { class: 'panel io-p' });
    var hdr = el('div', { class: 'panel-hdr' });
    hdr.innerHTML = CK.iconSvg(I_HASH, 12) + ' REPRESENTATIONS';
    panel.appendChild(hdr);
    var body = el('div', { style: 'overflow:auto; flex:1;' });
    panel.appendChild(body);
    io.appendChild(panel);
    root.appendChild(io);

    var rows = {};
    ['Binary', 'Octal', 'Decimal', 'Hex', 'Bit length', 'Bytes'].forEach(function (k) {
      var r = el('div', { class: 'row-out' });
      var kk = el('span', { class: 'k' }, k);
      var vv = el('span', { class: 'v' }, '-');
      var cp = ui.miniBtn('Copy', function () { CK.copy(vv.textContent); });
      r.appendChild(kk); r.appendChild(vv); r.appendChild(cp);
      body.appendChild(r); rows[k] = vv;
    });

    function setAll(dash) {
      Object.keys(rows).forEach(function (k) { rows[k].textContent = dash; });
    }
    function convert() {
      var raw = input.value;
      if (!raw.trim()) { setAll('-'); return; }
      try {
        var n = parseInBase(raw, baseOf(from).base);
        if (n === null) { setAll('-'); return; }
        var mag = n < 0n ? -n : n;
        rows['Binary'].textContent = n.toString(2);
        rows['Octal'].textContent = n.toString(8);
        rows['Decimal'].textContent = n.toString(10);
        rows['Hex'].textContent = (n < 0n ? '-' : '') + mag.toString(16).toUpperCase();
        var bits = mag === 0n ? 1 : mag.toString(2).length;
        rows['Bit length'].textContent = bits + ' bit' + (bits === 1 ? '' : 's');
        rows['Bytes'].textContent = Math.ceil(bits / 8) + ' byte' + (Math.ceil(bits / 8) === 1 ? '' : 's');
      } catch (err) {
        setAll('-'); rows['Decimal'].textContent = err.message;
      }
    }

    input.addEventListener('input', convert);
    pk.setActive(from);
    convert();

    return { reset: function () { input.value = ''; from = 'dec'; pk.setActive('dec'); input.placeholder = 'Enter decimal value...'; convert(); ctx.toast('Reset complete', 'success'); } };
  });
})();

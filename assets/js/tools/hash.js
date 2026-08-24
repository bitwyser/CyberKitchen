/*
   hash.js - Hash Generator tool
   SHA-1/256/384/512 via Web Crypto; MD5, SHA-3, Keccak, CRC32 via HashLib.
   Computes every algorithm live for the input. Pure client-side.
*/
(function () {
  'use strict';

  var ENC = new TextEncoder();
  function toHex(buf) { var b = new Uint8Array(buf), s = ''; for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; }
  function webHash(algo, bytes) { return crypto.subtle.digest(algo, bytes).then(toHex); }

  var ALGOS = [
    { id: 'md5', label: 'MD5', group: 'Legacy', fn: function (b) { return Promise.resolve(HashLib.md5(b)); } },
    { id: 'sha1', label: 'SHA-1', group: 'Legacy', fn: function (b) { return webHash('SHA-1', b); } },
    { id: 'crc32', label: 'CRC32', group: 'Legacy', fn: function (b) { return Promise.resolve(HashLib.crc32(b)); } },
    { id: 'sha256', label: 'SHA-256', group: 'SHA-2', fn: function (b) { return webHash('SHA-256', b); } },
    { id: 'sha384', label: 'SHA-384', group: 'SHA-2', fn: function (b) { return webHash('SHA-384', b); } },
    { id: 'sha512', label: 'SHA-512', group: 'SHA-2', fn: function (b) { return webHash('SHA-512', b); } },
    { id: 'sha3-256', label: 'SHA3-256', group: 'SHA-3', fn: function (b) { return Promise.resolve(HashLib.sha3(256, b)); } },
    { id: 'sha3-512', label: 'SHA3-512', group: 'SHA-3', fn: function (b) { return Promise.resolve(HashLib.sha3(512, b)); } },
    { id: 'keccak-256', label: 'Keccak-256', group: 'SHA-3', fn: function (b) { return Promise.resolve(HashLib.keccak(256, b)); } }
  ];

  var I_HASH = '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>';
  var I_FILE = '<path d="M14 3v5h5M6 3h9l5 5v13H6z"/>';

  CK.registerTool('hash', function (root, ctx) {
    var ui = CK.ui, el = CK.el, upper = false;

    root.appendChild(ui.head('Hash Generator', ALGOS.length + ' algorithms'));

    var cfg = ui.configPanel();
    var form = el('div', { class: 'cfg-form' });
    var upWrap = el('label', { class: 'toggle-row' });
    var upCb = el('input', { type: 'checkbox' });
    upWrap.appendChild(upCb); upWrap.appendChild(document.createTextNode('Uppercase hex'));
    form.appendChild(ui.field('Output', upWrap));
    cfg.appendChild(form);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: I_FILE, placeholder: 'Type or paste text to hash...', actions: ['copy', 'paste', 'clear'], onInput: compute });
    io.appendChild(inP.panel);

    var panel = el('div', { class: 'panel io-p' });
    var hdr = el('div', { class: 'panel-hdr' });
    hdr.innerHTML = CK.iconSvg(I_HASH, 12) + ' DIGESTS';
    panel.appendChild(hdr);
    var body = el('div', { style: 'overflow:auto; flex:1;' });
    panel.appendChild(body);
    io.appendChild(panel);
    root.appendChild(io);

    var rows = {};
    var lastGroup = null;
    ALGOS.forEach(function (a) {
      if (a.group !== lastGroup) { body.appendChild(el('div', { class: 'pk-label', style: 'text-align:left; padding:8px 0 2px;' }, a.group)); lastGroup = a.group; }
      var r = el('div', { class: 'row-out' });
      var k = el('span', { class: 'k' }, a.label);
      var v = el('span', { class: 'v' }, '-');
      var cp = ui.miniBtn('Copy', function () { CK.copy(v.textContent); });
      r.appendChild(k); r.appendChild(v); r.appendChild(cp);
      body.appendChild(r); rows[a.id] = v;
    });

    function compute() {
      var text = inP.ta.value;
      if (!text) { ALGOS.forEach(function (a) { rows[a.id].textContent = '-'; }); return; }
      var bytes = ENC.encode(text);
      ALGOS.forEach(function (a) {
        a.fn(bytes).then(function (hx) { rows[a.id].textContent = upper ? hx.toUpperCase() : hx; })
          .catch(function () { rows[a.id].textContent = 'error'; });
      });
    }
    upCb.addEventListener('change', function () { upper = upCb.checked; compute(); });

    compute();
    return { reset: function () { inP.ta.value = ''; upCb.checked = false; upper = false; compute(); ctx.toast('Reset complete', 'success'); } };
  });
})();

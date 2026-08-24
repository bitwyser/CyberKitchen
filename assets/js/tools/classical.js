/*
   classical.js - Classical Ciphers tool
   Historical substitution / transposition ciphers, pure JS.
*/
(function () {
  'use strict';

  function shiftLetters(text, fn) {
    return text.replace(/[a-z]/gi, function (c) {
      var base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(((fn(c.charCodeAt(0) - base) % 26) + 26) % 26 + base);
    });
  }
  function caesar(text, s) { return shiftLetters(text, function (x) { return x + s; }); }
  function atbash(text) { return shiftLetters(text, function (x) { return 25 - x; }); }
  function rot47(text) { return text.replace(/[!-~]/g, function (c) { return String.fromCharCode(33 + (c.charCodeAt(0) - 33 + 47) % 94); }); }

  function cleanKey(k) { return (k || '').toUpperCase().replace(/[^A-Z]/g, ''); }

  function vigenere(text, key, dec) {
    key = cleanKey(key); if (!key) throw new Error('Keyword required');
    var ki = 0;
    return text.replace(/[a-z]/gi, function (c) {
      var base = c <= 'Z' ? 65 : 97, k = key.charCodeAt(ki % key.length) - 65, p = c.charCodeAt(0) - base; ki++;
      return String.fromCharCode((dec ? (p - k + 26) : (p + k)) % 26 + base);
    });
  }
  function beaufort(text, key) {
    key = cleanKey(key); if (!key) throw new Error('Keyword required');
    var ki = 0;
    return text.replace(/[a-z]/gi, function (c) {
      var base = c <= 'Z' ? 65 : 97, k = key.charCodeAt(ki % key.length) - 65, p = c.charCodeAt(0) - base; ki++;
      return String.fromCharCode((k - p + 26) % 26 + base);
    });
  }
  function gronsfeld(text, key, dec) {
    var d = (key || '').replace(/[^0-9]/g, ''); if (!d) throw new Error('Numeric key required');
    var ki = 0;
    return text.replace(/[a-z]/gi, function (c) {
      var base = c <= 'Z' ? 65 : 97, k = +d[ki % d.length], p = c.charCodeAt(0) - base; ki++;
      return String.fromCharCode((dec ? (p - k + 260) : (p + k)) % 26 + base);
    });
  }
  function autokey(text, key, dec) {
    key = cleanKey(key); if (!key) throw new Error('Keyword required');
    var ks = key.split(''), ki = 0;
    return text.replace(/[a-z]/gi, function (c) {
      var base = c <= 'Z' ? 65 : 97, k = ks[ki].charCodeAt(0) - 65;
      if (!dec) { var p = c.charCodeAt(0) - base; ks.push(String.fromCharCode(p + 65)); ki++; return String.fromCharCode((p + k) % 26 + base); }
      var ct = c.charCodeAt(0) - base, pp = (ct - k + 26) % 26; ks.push(String.fromCharCode(pp + 65)); ki++; return String.fromCharCode(pp + base);
    });
  }
  function modInv(a) { a = ((a % 26) + 26) % 26; for (var x = 1; x < 26; x++) if ((a * x) % 26 === 1) return x; return -1; }
  function affine(text, key, dec) {
    var m = /(-?\d+)\s*,\s*(-?\d+)/.exec(key || ''); if (!m) throw new Error('Key must be "a, b"');
    var a = +m[1], b = +m[2], ai = modInv(a); if (ai < 0) throw new Error('a must be coprime with 26');
    return shiftLetters(text, function (x) { return dec ? ai * (x - b) : a * x + b; });
  }
  function a1z26enc(text) { return text.toUpperCase().split('').map(function (c) { return c >= 'A' && c <= 'Z' ? (c.charCodeAt(0) - 64) : (c === ' ' ? '/' : ''); }).filter(function (x) { return x !== ''; }).join(' '); }
  function a1z26dec(text) { return text.split(/\s+/).map(function (t) { if (t === '/') return ' '; var n = +t; return n >= 1 && n <= 26 ? String.fromCharCode(n + 64) : ''; }).join(''); }

  function baconEnc(text) { return text.toUpperCase().replace(/[^A-Z]/g, '').split('').map(function (c) { return (c.charCodeAt(0) - 65).toString(2).padStart(5, '0').replace(/0/g, 'a').replace(/1/g, 'b'); }).join(' '); }
  function baconDec(text) { var b = text.toLowerCase().replace(/[^ab]/g, ''), r = ''; for (var i = 0; i + 5 <= b.length; i += 5) r += String.fromCharCode(parseInt(b.substr(i, 5).replace(/a/g, '0').replace(/b/g, '1'), 2) + 65); return r; }

  function subAlpha(key) {
    key = cleanKey(key); var seen = {}, a = '', i;
    for (i = 0; i < key.length; i++) if (!seen[key[i]]) { seen[key[i]] = 1; a += key[i]; }
    for (i = 65; i <= 90; i++) { var ch = String.fromCharCode(i); if (!seen[ch]) a += ch; }
    return a;
  }
  function substitution(text, key, dec) {
    var a = subAlpha(key); if (a.length !== 26) throw new Error('Invalid key alphabet');
    return text.replace(/[a-z]/gi, function (c) {
      var up = c <= 'Z', i = (up ? c.charCodeAt(0) - 65 : c.charCodeAt(0) - 97);
      var out = dec ? String.fromCharCode(a.indexOf(String.fromCharCode(i + 65)) + 65) : a[i];
      return up ? out : out.toLowerCase();
    });
  }

  var POL = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
  function polEnc(text) { text = text.toUpperCase().replace(/J/g, 'I'); var r = []; for (var i = 0; i < text.length; i++) { var idx = POL.indexOf(text[i]); if (idx < 0) continue; r.push('' + (Math.floor(idx / 5) + 1) + (idx % 5 + 1)); } return r.join(' '); }
  function polDec(text) { var d = text.replace(/[^1-5]/g, ''), r = ''; for (var i = 0; i + 2 <= d.length; i += 2) { var idx = (+d[i] - 1) * 5 + (+d[i + 1] - 1); if (idx >= 0 && idx < 25) r += POL[idx]; } return r; }

  function railEnc(text, rails) {
    rails = Math.max(2, rails | 0); var rows = []; for (var i = 0; i < rails; i++) rows.push('');
    var r = 0, dir = 1;
    for (i = 0; i < text.length; i++) { rows[r] += text[i]; r += dir; if (r === 0 || r === rails - 1) dir = -dir; }
    return rows.join('');
  }
  function railDec(text, rails) {
    rails = Math.max(2, rails | 0); var len = text.length, pat = [], r = 0, dir = 1, i;
    for (i = 0; i < len; i++) { pat.push(r); r += dir; if (r === 0 || r === rails - 1) dir = -dir; }
    var counts = []; for (i = 0; i < rails; i++) counts.push(0);
    for (i = 0; i < len; i++) counts[pat[i]]++;
    var pos = [], acc = 0; for (r = 0; r < rails; r++) { pos.push(acc); acc += counts[r]; }
    var out = []; for (i = 0; i < len; i++) out[i] = text[pos[pat[i]]++];
    return out.join('');
  }

  var LIST = [
    { id: 'caesar', label: 'Caesar', group: 'Shift', badge: 'Shift', desc: 'Caesar shift cipher', num: 'Shift', numDef: 3, enc: function (t, p) { return caesar(t, p.num); }, dec: function (t, p) { return caesar(t, -p.num); } },
    { id: 'rot13', label: 'ROT13', group: 'Shift', badge: 'Shift', desc: 'Rotate letters by 13', enc: function (t) { return caesar(t, 13); }, dec: function (t) { return caesar(t, 13); } },
    { id: 'atbash', label: 'Atbash', group: 'Shift', badge: 'Mirror', desc: 'Atbash mirror cipher', enc: function (t) { return atbash(t); }, dec: function (t) { return atbash(t); } },
    { id: 'rot47', label: 'ROT47', group: 'Shift', badge: 'ASCII', desc: 'Rotate printable ASCII by 47', enc: function (t) { return rot47(t); }, dec: function (t) { return rot47(t); } },
    { id: 'affine', label: 'Affine', group: 'Shift', badge: 'Math', desc: 'Affine cipher (a*x + b)', key: 'a, b', keyPh: '5, 8', enc: function (t, p) { return affine(t, p.key, false); }, dec: function (t, p) { return affine(t, p.key, true); } },
    { id: 'a1z26', label: 'A1Z26', group: 'Shift', badge: 'Numeric', desc: 'Letters to numbers (A=1)', enc: function (t) { return a1z26enc(t); }, dec: function (t) { return a1z26dec(t); } },

    { id: 'vigenere', label: 'Vigenere', group: 'Polyalphabetic', badge: 'Key', desc: 'Vigenere cipher', key: 'Keyword', keyPh: 'LEMON', enc: function (t, p) { return vigenere(t, p.key, false); }, dec: function (t, p) { return vigenere(t, p.key, true); } },
    { id: 'beaufort', label: 'Beaufort', group: 'Polyalphabetic', badge: 'Key', desc: 'Beaufort cipher (reciprocal)', key: 'Keyword', keyPh: 'LEMON', enc: function (t, p) { return beaufort(t, p.key); }, dec: function (t, p) { return beaufort(t, p.key); } },
    { id: 'gronsfeld', label: 'Gronsfeld', group: 'Polyalphabetic', badge: 'Digits', desc: 'Gronsfeld (numeric Vigenere)', key: 'Numeric key', keyPh: '31415', enc: function (t, p) { return gronsfeld(t, p.key, false); }, dec: function (t, p) { return gronsfeld(t, p.key, true); } },
    { id: 'autokey', label: 'Autokey', group: 'Polyalphabetic', badge: 'Key', desc: 'Autokey cipher', key: 'Keyword', keyPh: 'LEMON', enc: function (t, p) { return autokey(t, p.key, false); }, dec: function (t, p) { return autokey(t, p.key, true); } },

    { id: 'substitution', label: 'Substitution', group: 'Substitution', badge: 'Key', desc: 'Monoalphabetic substitution', key: 'Keyword / 26 letters', keyPh: 'CIPHER', enc: function (t, p) { return substitution(t, p.key, false); }, dec: function (t, p) { return substitution(t, p.key, true); } },
    { id: 'bacon', label: 'Bacon', group: 'Substitution', badge: 'Binary', desc: "Bacon's cipher (a/b)", enc: function (t) { return baconEnc(t); }, dec: function (t) { return baconDec(t); } },
    { id: 'polybius', label: 'Polybius', group: 'Substitution', badge: 'Grid', desc: 'Polybius square (5x5, I=J)', enc: function (t) { return polEnc(t); }, dec: function (t) { return polDec(t); } },

    { id: 'railfence', label: 'Rail Fence', group: 'Transposition', badge: 'Zigzag', desc: 'Rail fence transposition', num: 'Rails', numDef: 3, enc: function (t, p) { return railEnc(t, p.num); }, dec: function (t, p) { return railDec(t, p.num); } }
  ];
  function get(id) { for (var i = 0; i < LIST.length; i++) if (LIST[i].id === id) return LIST[i]; return null; }
  var GROUPS = ['Shift', 'Polyalphabetic', 'Substitution', 'Transposition'];

  var I_SCROLL = '<path d="M4 7V5h16v2M9 20h6M12 5v15"/>';
  var I_LOCK = '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';
  var I_SWAP = '<path d="M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4"/>';

  CK.registerTool('classical', function (root, ctx) {
    var ui = CK.ui, el = CK.el, current = 'caesar';

    root.appendChild(ui.head('Classical Ciphers', LIST.length + ' ciphers'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_SCROLL);
    strip.acts.appendChild(ui.iconBtn(I_SWAP, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var form = el('div', { class: 'cfg-form' });
    var keyInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off' });
    var numInput = el('input', { class: 'inp sm', type: 'number', value: '3' });
    var keyField = ui.field('Key', keyInput);
    var numField = ui.field('Shift', numInput);
    form.appendChild(keyField); form.appendChild(numField);
    cfg.appendChild(form);

    var groups = GROUPS.map(function (g) { return { label: g, items: LIST.filter(function (c) { return c.group === g; }).map(function (c) { return { id: c.id, label: c.label, title: c.desc }; }) }; });
    var pk = ui.picker(groups, select);
    cfg.appendChild(pk.el);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'PLAINTEXT', icon: I_SCROLL, placeholder: 'Text to encrypt...', primary: { label: 'Encrypt', cls: 'enc', onClick: doEncrypt }, actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'plaintext.txt' });
    var outP = ui.textPanel({ title: 'CIPHERTEXT', icon: I_LOCK, placeholder: 'Ciphertext, or paste to decrypt...', primary: { label: 'Decrypt', cls: 'dec', onClick: doDecrypt }, actions: ['copy', 'clear', 'download'], downloadName: 'ciphertext.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function params() { return { key: keyInput.value, num: parseInt(numInput.value, 10) || 0 }; }
    function select(id) {
      var c = get(id); if (!c) return; current = id; pk.setActive(id);
      ui.setSel(strip, c.label, c.badge, c.desc);
      keyField.style.display = c.key ? '' : 'none';
      if (c.key) { keyField.querySelector('label').textContent = c.key; keyInput.placeholder = c.keyPh || ''; }
      numField.style.display = c.num ? '' : 'none';
      if (c.num) { numField.querySelector('label').textContent = c.num; if (c.numDef != null && !numInput.dataset.touched) numInput.value = c.numDef; }
    }
    numInput.addEventListener('input', function () { numInput.dataset.touched = '1'; });
    function doEncrypt() { try { var c = get(current); if (!inP.ta.value) throw new Error('Plaintext is empty'); outP.ta.value = c.enc(inP.ta.value, params()); ctx.toast(c.label + ' encrypted', 'success'); } catch (e) { ctx.toast(e.message, 'error'); } }
    function doDecrypt() { try { var c = get(current); if (!outP.ta.value) throw new Error('Ciphertext is empty'); inP.ta.value = c.dec(outP.ta.value, params()); ctx.toast(c.label + ' decrypted', 'success'); } catch (e) { ctx.toast(e.message, 'error'); } }
    function doSwap() { var a = inP.ta.value; inP.ta.value = outP.ta.value; outP.ta.value = a; ctx.toast('Panels swapped', 'success'); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; keyInput.value = ''; numInput.value = '3'; delete numInput.dataset.touched; select('caesar'); ctx.toast('Reset complete', 'success'); }

    select(current);
    return {
      reset: doReset,
      onKey: function (e) { if (!(e.ctrlKey || e.metaKey)) return; var k = String(e.key).toLowerCase(); if (k === 'e') { e.preventDefault(); doEncrypt(); } else if (k === 'd') { e.preventDefault(); doDecrypt(); } }
    };
  });
})();

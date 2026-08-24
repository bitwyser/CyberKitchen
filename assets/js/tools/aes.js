/*
   aes.js - AES encryption tool (Web Crypto)
   Passphrase-based: PBKDF2(SHA-256, 100k) derives the key; random salt + IV.
   Output bundle = base64( salt(16) | iv | ciphertext ). Modes: GCM, CBC.
*/
(function () {
  'use strict';

  var ENC = new TextEncoder(), DEC = new TextDecoder();
  var ITER = 100000;
  function b64(bytes) { var s = ''; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
  function unb64(str) { var bin = atob(str.trim().replace(/\s/g, '')); var a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  function concat() { var total = 0, i; for (i = 0; i < arguments.length; i++) total += arguments[i].length; var out = new Uint8Array(total), off = 0; for (i = 0; i < arguments.length; i++) { out.set(arguments[i], off); off += arguments[i].length; } return out; }

  function deriveKey(pass, salt, mode, bits) {
    return crypto.subtle.importKey('raw', ENC.encode(pass), 'PBKDF2', false, ['deriveKey']).then(function (base) {
      return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: ITER, hash: 'SHA-256' }, base, { name: mode, length: bits }, false, ['encrypt', 'decrypt']);
    });
  }

  var I_KEY = '<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3M17 6l3 0 0 3M14 9l2 2"/>';
  var I_LOCK = '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';
  var I_SWAP = '<path d="M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4"/>';

  CK.registerTool('aes', function (root, ctx) {
    var ui = CK.ui, el = CK.el, mode = 'AES-GCM', bits = 256;

    root.appendChild(ui.head('AES Encrypt / Decrypt', 'Web Crypto'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_KEY);
    strip.acts.appendChild(ui.iconBtn(I_SWAP, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var modePk = ui.picker([{ label: 'Mode', items: [{ id: 'AES-GCM', label: 'GCM' }, { id: 'AES-CBC', label: 'CBC' }] }], function (id) { mode = id; modePk.setActive(id); updateSel(); });
    var sizePk = ui.picker([{ label: 'Key size', items: [{ id: '128', label: '128' }, { id: '192', label: '192' }, { id: '256', label: '256' }] }], function (id) { bits = +id; sizePk.setActive(id); updateSel(); });
    cfg.appendChild(modePk.el); cfg.appendChild(sizePk.el);

    var form = el('div', { class: 'cfg-form' });
    var passInput = el('input', { class: 'inp', type: 'password', autocomplete: 'off', placeholder: 'Passphrase' });
    form.appendChild(ui.field('Passphrase', passInput));
    cfg.appendChild(form);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'PLAINTEXT', icon: I_KEY, placeholder: 'Text to encrypt...', primary: { label: 'Encrypt', cls: 'enc', onClick: doEncrypt }, actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'plaintext.txt' });
    var outP = ui.textPanel({ title: 'CIPHERTEXT (base64)', icon: I_LOCK, placeholder: 'Ciphertext bundle, or paste to decrypt...', primary: { label: 'Decrypt', cls: 'dec', onClick: doDecrypt }, actions: ['copy', 'clear', 'download'], downloadName: 'ciphertext.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function updateSel() { modePk.setActive(mode); sizePk.setActive('' + bits); ui.setSel(strip, 'AES-' + bits + '-' + mode.split('-')[1], 'PBKDF2', 'Passphrase-derived key, random salt and IV'); }

    function doEncrypt() {
      var pass = passInput.value, text = inP.ta.value;
      if (!pass) { ctx.toast('Passphrase required', 'warn'); return; }
      if (!text) { ctx.toast('Plaintext is empty', 'warn'); return; }
      var salt = crypto.getRandomValues(new Uint8Array(16));
      var iv = crypto.getRandomValues(new Uint8Array(mode === 'AES-GCM' ? 12 : 16));
      deriveKey(pass, salt, mode, bits).then(function (key) {
        return crypto.subtle.encrypt({ name: mode, iv: iv }, key, ENC.encode(text));
      }).then(function (ct) {
        outP.ta.value = b64(concat(salt, iv, new Uint8Array(ct)));
        ctx.toast('Encrypted (' + mode + ')', 'success');
      }).catch(function (e) { ctx.toast('Encryption failed: ' + e.message, 'error'); });
    }
    function doDecrypt() {
      var pass = passInput.value, data = outP.ta.value;
      if (!pass) { ctx.toast('Passphrase required', 'warn'); return; }
      if (!data) { ctx.toast('Ciphertext is empty', 'warn'); return; }
      var bytes; try { bytes = unb64(data); } catch (e) { ctx.toast('Invalid base64 ciphertext', 'error'); return; }
      var ivLen = mode === 'AES-GCM' ? 12 : 16;
      if (bytes.length <= 16 + ivLen) { ctx.toast('Ciphertext too short', 'error'); return; }
      var salt = bytes.slice(0, 16), iv = bytes.slice(16, 16 + ivLen), ct = bytes.slice(16 + ivLen);
      deriveKey(pass, salt, mode, bits).then(function (key) {
        return crypto.subtle.decrypt({ name: mode, iv: iv }, key, ct);
      }).then(function (pt) {
        inP.ta.value = DEC.decode(pt);
        ctx.toast('Decrypted', 'success');
      }).catch(function () { ctx.toast('Decryption failed: wrong passphrase, mode, or key size', 'error'); });
    }
    function doSwap() { var a = inP.ta.value; inP.ta.value = outP.ta.value; outP.ta.value = a; ctx.toast('Panels swapped', 'success'); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; passInput.value = ''; mode = 'AES-GCM'; bits = 256; updateSel(); ctx.toast('Reset complete', 'success'); }

    updateSel();
    return {
      reset: doReset,
      onKey: function (e) { if (!(e.ctrlKey || e.metaKey)) return; var k = String(e.key).toLowerCase(); if (k === 'e') { e.preventDefault(); doEncrypt(); } else if (k === 'd') { e.preventDefault(); doDecrypt(); } }
    };
  });
})();

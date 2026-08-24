/*
   rsa.js - RSA encryption tool (Web Crypto, RSA-OAEP + SHA-256)
   Generate a keypair (PEM), encrypt with the public key, decrypt with private.
   OAEP has a per-key size limit; long messages are rejected with guidance.
*/
(function () {
  'use strict';

  var ENC = new TextEncoder(), DEC = new TextDecoder();
  function b64(bytes) { var s = ''; bytes = new Uint8Array(bytes); for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
  function unb64(str) { var bin = atob(str.trim().replace(/\s/g, '')); var a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  function pem(label, buf) { return '-----BEGIN ' + label + '-----\n' + b64(buf).replace(/(.{64})/g, '$1\n').trim() + '\n-----END ' + label + '-----'; }
  function unpem(str) { var b = str.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''); return unb64(b).buffer; }
  var ALG = { name: 'RSA-OAEP', hash: 'SHA-256' };

  var I_SHIELD = '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/>';
  var I_LOCK = '<path d="M6 10V7a6 6 0 0 1 12 0v3M5 10h14v10H5z"/>';
  var I_GEN = '<path d="M12 2v4M12 18v4M2 12h4M18 12h4M5 5l2.5 2.5M19 5l-2.5 2.5M5 19l2.5-2.5M19 19l-2.5-2.5"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('rsa', function (root, ctx) {
    var ui = CK.ui, el = CK.el, bits = 2048;

    root.appendChild(ui.head('RSA Encrypt / Decrypt', 'Web Crypto'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_SHIELD);
    strip.acts.appendChild(ui.iconBtn(I_GEN, 'Generate', doGenerate));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var sizePk = ui.picker([{ label: 'Key size', items: [{ id: '2048', label: '2048' }, { id: '4096', label: '4096' }] }], function (id) { bits = +id; sizePk.setActive(id); updateSel(); });
    cfg.appendChild(sizePk.el);

    // Key fields (public / private)
    var keyRow = el('div', { class: 'cfg-form' });
    function keyBox(labelText, dl) {
      var box = el('div', { class: 'field', style: 'flex:1; min-width:240px;' });
      var lab = el('label'); lab.textContent = labelText;
      var head = el('div', { style: 'display:flex; align-items:center; gap:6px;' });
      head.appendChild(lab); var fill = el('span', { style: 'flex:1' }); head.appendChild(fill);
      var ta = el('textarea', { class: 'ta', style: 'flex:none; height:76px; font-size:11px;', spellcheck: 'false', placeholder: labelText + ' (PEM)' });
      head.appendChild(ui.miniBtn('Copy', function () { CK.copy(ta.value); }));
      box.appendChild(head); box.appendChild(ta);
      return { box: box, ta: ta };
    }
    var pub = keyBox('Public key');
    var priv = keyBox('Private key');
    keyRow.appendChild(pub.box); keyRow.appendChild(priv.box);
    cfg.appendChild(keyRow);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'PLAINTEXT', icon: I_SHIELD, placeholder: 'Text to encrypt (public key)...', primary: { label: 'Encrypt', cls: 'enc', onClick: doEncrypt }, actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'plaintext.txt' });
    var outP = ui.textPanel({ title: 'CIPHERTEXT (base64)', icon: I_LOCK, placeholder: 'Ciphertext, or paste to decrypt (private key)...', primary: { label: 'Decrypt', cls: 'dec', onClick: doDecrypt }, actions: ['copy', 'clear', 'download'], downloadName: 'ciphertext.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function updateSel() { sizePk.setActive('' + bits); ui.setSel(strip, 'RSA-' + bits, 'OAEP', 'RSA-OAEP with SHA-256; generate a keypair to begin'); }

    function doGenerate() {
      ctx.toast('Generating ' + bits + '-bit keypair...', 'success');
      crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt'])
        .then(function (kp) {
          return Promise.all([crypto.subtle.exportKey('spki', kp.publicKey), crypto.subtle.exportKey('pkcs8', kp.privateKey)]);
        }).then(function (keys) {
          pub.ta.value = pem('PUBLIC KEY', keys[0]);
          priv.ta.value = pem('PRIVATE KEY', keys[1]);
          ctx.toast('Keypair generated', 'success');
        }).catch(function (e) { ctx.toast('Key generation failed: ' + e.message, 'error'); });
    }
    function doEncrypt() {
      if (!inP.ta.value) { ctx.toast('Plaintext is empty', 'warn'); return; }
      if (!pub.ta.value) { ctx.toast('Public key required (generate or paste one)', 'warn'); return; }
      crypto.subtle.importKey('spki', unpem(pub.ta.value), ALG, false, ['encrypt']).then(function (key) {
        return crypto.subtle.encrypt(ALG, key, ENC.encode(inP.ta.value));
      }).then(function (ct) { outP.ta.value = b64(ct); ctx.toast('Encrypted', 'success'); })
        .catch(function (e) {
          var max = bits / 8 - 66;
          if (/too long|data too large|OperationError/i.test(e.name + e.message)) ctx.toast('Message too long for RSA-OAEP (max ~' + max + ' bytes at ' + bits + '-bit). Use AES for large data.', 'error');
          else ctx.toast('Encryption failed: check the public key', 'error');
        });
    }
    function doDecrypt() {
      if (!outP.ta.value) { ctx.toast('Ciphertext is empty', 'warn'); return; }
      if (!priv.ta.value) { ctx.toast('Private key required', 'warn'); return; }
      var bytes; try { bytes = unb64(outP.ta.value); } catch (e) { ctx.toast('Invalid base64 ciphertext', 'error'); return; }
      crypto.subtle.importKey('pkcs8', unpem(priv.ta.value), ALG, false, ['decrypt']).then(function (key) {
        return crypto.subtle.decrypt(ALG, key, bytes);
      }).then(function (pt) { inP.ta.value = DEC.decode(pt); ctx.toast('Decrypted', 'success'); })
        .catch(function () { ctx.toast('Decryption failed: wrong key or ciphertext', 'error'); });
    }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; pub.ta.value = ''; priv.ta.value = ''; bits = 2048; updateSel(); ctx.toast('Reset complete', 'success'); }

    updateSel();
    return {
      reset: doReset,
      onKey: function (e) { if (!(e.ctrlKey || e.metaKey)) return; var k = String(e.key).toLowerCase(); if (k === 'e') { e.preventDefault(); doEncrypt(); } else if (k === 'd') { e.preventDefault(); doDecrypt(); } }
    };
  });
})();

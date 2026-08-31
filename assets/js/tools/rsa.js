/*
   rsa.js - RSA Encrypt / Decrypt (Web Crypto, RSA-OAEP)
   Key sizes 1024/2048/4096, OAEP hash SHA-256/384/512/SHA-1, Base64/Hex
   ciphertext, UTF-8/Base64/Hex plaintext, PEM keypair generation.
   Verify (via decryption), Auto-detect (format + key-size guess), Swap, Share.
*/
(function () {
  'use strict';
  var ENC = new TextEncoder(), DEC = new TextDecoder();
  function b64(bytes) { var s = ''; bytes = new Uint8Array(bytes); for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
  function unb64(str) { var bin = atob(str.trim().replace(/\s/g, '')); var a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  function toHex(bytes) { bytes = new Uint8Array(bytes); var s = ''; for (var i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0'); return s; }
  function hexToBytes(h) { h = h.replace(/[^0-9a-fA-F]/g, ''); var a = new Uint8Array(h.length / 2); for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
  function pem(label, buf) { return '-----BEGIN ' + label + '-----\n' + b64(buf).replace(/(.{64})/g, '$1\n').trim() + '\n-----END ' + label + '-----'; }
  function unpem(str) { return unb64(str.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')).buffer; }
  function b64uEnc(str) { var b = ENC.encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return DEC.decode(a); }

  function detectFmt(s) {
    var c = s.trim(), clean = c.replace(/\s/g, '');
    if (/^[0-9a-fA-F\s]+$/.test(c) && clean.length % 2 === 0 && clean.length >= 2) return 'hex';
    if (/^[A-Za-z0-9+/=\s]+$/.test(c) && clean.length % 4 === 0 && clean.length >= 4) { try { atob(clean); return 'base64'; } catch (e) { } }
    return 'utf8';
  }
  function fmtByteLen(s, fmt) {
    if (fmt === 'hex') return s.replace(/[^0-9a-fA-F]/g, '').length / 2;
    if (fmt === 'base64') { try { return atob(s.trim().replace(/\s/g, '')).length; } catch (e) { return null; } }
    return ENC.encode(s).length;
  }
  function fmtLabelOf(fmt) { return fmt === 'hex' ? 'Hexadecimal' : fmt === 'base64' ? 'Base64' : 'UTF-8'; }

  var I_SHIELD = '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/>';
  var I_LOCK = '<path d="M6 10V7a6 6 0 0 1 12 0v3M5 10h14v10H5z"/>';
  var I_SHUF = '<path d="M18 4l3 3-3 3M21 7H8a4 4 0 0 0-4 4M6 20l-3-3 3-3M3 17h12a4 4 0 0 0 4-4"/>';
  var I_CHECK = '<path d="M20 6 9 17l-5-5"/>';
  var I_DETECT = '<path d="m12 3 1.9 4.6L18 9l-4.1 1.4L12 15l-1.9-4.6L6 9l4.1-1.4zM19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9z"/>';
  var I_SWAP = '<path d="M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('rsa', function (root, ctx) {
    var ui = CK.ui, el = CK.el, bits = 2048, hash = 'SHA-256';
    function o(a) { return { value: a[0], label: a[1] }; }

    root.appendChild(ui.head('RSA Encrypt / Decrypt', 'Web Crypto'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_SHIELD);
    strip.acts.appendChild(ui.iconBtn(I_DETECT, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(I_CHECK, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(I_SWAP, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    // Main grid: left column is a 2x2 sub-grid (Public key / Key size over Private key / Hash);
    // right column is the formats.
    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col2 kv-mp' });
    var colR = el('div', { class: 'col' });
    var sizeSel = ui.select([['1024', 'RSA-1024'], ['2048', 'RSA-2048'], ['4096', 'RSA-4096']].map(o), function (v) { bits = +v; updateSel(); }, '2048');
    var hashSel = ui.select([['SHA-256', 'OAEP + SHA-256'], ['SHA-384', 'OAEP + SHA-384'], ['SHA-512', 'OAEP + SHA-512'], ['SHA-1', 'OAEP + SHA-1']].map(o), function (v) { hash = v; updateSel(); }, 'SHA-256');
    var ptFmt = ui.select([['utf8', 'UTF-8'], ['base64', 'Base64'], ['hex', 'Hexadecimal']].map(o), null, 'utf8');
    var ctFmt = ui.select([['base64', 'Base64'], ['hex', 'Hexadecimal']].map(o), null, 'base64');
    function keyBox(labelText) {
      var ta = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: labelText + ' (PEM)' });
      ta.style.flex = '1'; ta.style.fontSize = '11px';
      var wrap = el('div', { style: 'display:flex; gap:5px; align-items:center;' });
      wrap.appendChild(ta);
      wrap.appendChild(ui.iconBtn(I_SHUF, 'Generate keypair', function () { doGenerate(); }));
      return { box: ui.field(labelText, wrap), ta: ta };
    }
    var pub = keyBox('Public key'), priv = keyBox('Private key');
    // Left sub-grid, row-flow order: Public key, Key size (row 1), Private key, Hash (row 2)
    colL.appendChild(pub.box); colL.appendChild(ui.field('Key size', sizeSel));
    colL.appendChild(priv.box); colL.appendChild(ui.field('Hash', hashSel));
    // Right column: Input format, Output format
    colR.appendChild(ui.field('Input format', ptFmt));
    colR.appendChild(ui.field('Output format', ctFmt));
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: I_SHIELD, placeholder: 'Plaintext to encrypt (public key), or ciphertext to decrypt (private key)...', primaries: [{ label: 'Encrypt', cls: 'enc', onClick: doEncrypt }, { label: 'Decrypt', cls: 'dec', onClick: doDecrypt }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'input.txt' });
    var outP = ui.textPanel({ title: 'OUTPUT', icon: I_LOCK, placeholder: 'Result appears here...', actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'output.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearVerify() { outP.ta.classList.remove('verify-match', 'verify-fail'); inP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearVerify);
    outP.ta.addEventListener('input', clearVerify);

    function alg() { return { name: 'RSA-OAEP', hash: hash }; }
    function updateSel() { ui.setSel(strip, 'RSA-' + bits, hash, 'RSA-OAEP with ' + hash); }
    function ptBytes() { var v = inP.ta.value; if (ptFmt.value === 'hex') return hexToBytes(v); if (ptFmt.value === 'base64') return unb64(v); return ENC.encode(v); }
    function fromPt(buf) { if (ptFmt.value === 'hex') return toHex(buf); if (ptFmt.value === 'base64') return b64(buf); return DEC.decode(buf); }
    function ctBytes(src) { return ctFmt.value === 'hex' ? hexToBytes(src) : unb64(src); }

    function doGenerate() {
      ctx.toast('Generating ' + bits + '-bit keypair...', 'success');
      crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: hash }, true, ['encrypt', 'decrypt'])
        .then(function (kp) { return Promise.all([crypto.subtle.exportKey('spki', kp.publicKey), crypto.subtle.exportKey('pkcs8', kp.privateKey)]); })
        .then(function (k) { pub.ta.value = pem('PUBLIC KEY', k[0]); priv.ta.value = pem('PRIVATE KEY', k[1]); ctx.toast('Keypair generated', 'success'); })
        .catch(function (e) { ctx.toast('Key generation failed: ' + e.message, 'error'); });
    }
    function doEncrypt() {
      if (!inP.ta.value) { ctx.toast('Input is empty', 'warn'); return; }
      if (!pub.ta.value) { ctx.toast('Public key required', 'warn'); return; }
      return crypto.subtle.importKey('spki', unpem(pub.ta.value), alg(), false, ['encrypt'])
        .then(function (key) { return crypto.subtle.encrypt(alg(), key, ptBytes()); })
        .then(function (ct) { outP.ta.value = ctFmt.value === 'hex' ? toHex(ct) : b64(ct); clearVerify(); ctx.toast('Encrypted', 'success'); })
        .catch(function (e) {
          var hl = { 'SHA-1': 20, 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64 }[hash], max = bits / 8 - 2 * hl - 2;
          if (/too long|too large|Operation/i.test(e.name + e.message)) ctx.toast('Message too long for RSA-OAEP (max ' + max + ' bytes at ' + bits + '-bit / ' + hash + ')', 'error');
          else ctx.toast('Encryption failed: check the public key and hash', 'error');
        });
    }
    function doDecrypt() {
      if (!inP.ta.value) { ctx.toast('Input is empty', 'warn'); return; }
      if (!priv.ta.value) { ctx.toast('Private key required', 'warn'); return; }
      var bytes; try { bytes = ctBytes(inP.ta.value); } catch (e) { ctx.toast('Invalid ciphertext', 'error'); return; }
      return crypto.subtle.importKey('pkcs8', unpem(priv.ta.value), alg(), false, ['decrypt'])
        .then(function (key) { return crypto.subtle.decrypt(alg(), key, bytes); })
        .then(function (pt) { outP.ta.value = fromPt(pt); clearVerify(); ctx.toast('Decrypted', 'success'); })
        .catch(function () { ctx.toast('Decryption failed: wrong key, hash, or ciphertext', 'error'); });
    }
    function doVerify() {
      clearVerify();
      if (!priv.ta.value) { ctx.toast('Private key required to verify', 'warn'); return; }
      var a = inP.ta.value, b = outP.ta.value;
      if (!a || !b) { ctx.toast('Both panels need content', 'warn'); return; }
      crypto.subtle.importKey('pkcs8', unpem(priv.ta.value), alg(), false, ['decrypt']).then(function (key) {
        function tryDec(src) { var bytes; try { bytes = ctBytes(src); } catch (e) { return Promise.resolve(null); } return crypto.subtle.decrypt(alg(), key, bytes).then(function (pt) { return fromPt(pt); }).catch(function () { return null; }); }
        return Promise.all([tryDec(a), tryDec(b)]).then(function (r) {
          var match = (r[0] !== null && r[0] === b) || (r[1] !== null && r[1] === a);
          CK.flashVerify(match, inP.ta, outP.ta);
          ctx.toast(match ? 'Match: input and output are a valid RSA pair' : 'No match', match ? 'success' : 'error');
        });
      }).catch(function () { ctx.toast('Invalid private key', 'error'); });
    }
    function doDetect() {
      var s = inP.ta.value.trim();
      if (!s) { ctx.toast('Enter data in the input first', 'warn'); return; }
      var fmt = detectFmt(s); ptFmt.value = fmt; if (fmt !== 'utf8') ctFmt.value = fmt;
      var len = fmtByteLen(s, fmt), guessed = '';
      if (fmt !== 'utf8' && len) {
        var sz = len === 128 ? '1024' : len === 256 ? '2048' : len === 512 ? '4096' : null;
        if (sz) { bits = +sz; sizeSel.value = sz; guessed = ', guessed RSA-' + sz + ' (best-effort)'; }
      }
      updateSel();
      ctx.toast('RSA · detected ' + fmtLabelOf(fmt) + ' input' + guessed, 'success');
    }
    function doSwap() { inP.ta.value = outP.ta.value; outP.ta.value = ''; clearVerify(); ctx.toast('Output moved to input', 'success'); }
    function doShare() { var st = { sz: bits, h: hash, cf: ctFmt.value, pf: ptFmt.value, pub: pub.ta.value, priv: priv.ta.value, in: inP.ta.value, out: outP.ta.value }; CK.copy(location.href.split('#')[0] + '#tool=rsa&s=' + b64uEnc(JSON.stringify(st))); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; pub.ta.value = ''; priv.ta.value = ''; bits = 2048; hash = 'SHA-256'; sizeSel.value = '2048'; hashSel.value = 'SHA-256'; ctFmt.value = 'base64'; ptFmt.value = 'utf8'; clearVerify(); updateSel(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); bits = st.sz || 2048; hash = st.h || 'SHA-256'; sizeSel.value = '' + bits; hashSel.value = hash; ctFmt.value = st.cf || 'base64'; ptFmt.value = st.pf || 'utf8'; pub.ta.value = st.pub || ''; priv.ta.value = st.priv || ''; inP.ta.value = st.in || ''; outP.ta.value = st.out || ''; } catch (e) { } }
    updateSel();
  });
})();

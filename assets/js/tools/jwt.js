/*
   jwt.js - JSON Web Token tool (RFC 7519)
   Decode header + payload, sign, and verify. HS256/384/512 use Web Crypto HMAC
   with a UTF-8/Base64/Hex secret; RS256 uses Web Crypto RSASSA-PKCS1-v1_5 with
   PEM public / private keys. Fully offline.
*/
(function () {
  'use strict';
  var ENC = new TextEncoder(), DEC = new TextDecoder();
  function hexToBytes(h) { h = h.replace(/[^0-9a-fA-F]/g, ''); var a = new Uint8Array(h.length / 2); for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
  function b64ToBytes(s) { s = s.trim().replace(/\s/g, ''); var bin = atob(s), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  function b64uBytes(buf) { var b = new Uint8Array(buf), s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uStr(str) { return b64uBytes(ENC.encode(str)); }
  function unb64u(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  function unb64uText(str) { return DEC.decode(unb64u(str)); }
  function unpem(str) { return b64ToBytes(str.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')).buffer; }

  function rndBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }
  function bytesToFmt(b, fmt) { var i, s = ''; if (fmt === 'hex') { for (i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; } if (fmt === 'base64') { for (i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); } for (i = 0; i < b.length; i++) s += String.fromCharCode(33 + (b[i] % 94)); return s; }

  function b64uEnc(str) { var b = ENC.encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return DEC.decode(a); }

  var HASH = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512', RS256: 'SHA-256' };

  function secretBytes(v, fmt) { if (fmt === 'hex') return hexToBytes(v); if (fmt === 'base64') return b64ToBytes(v); return ENC.encode(v); }

  // signingInput -> Promise<base64url signature>
  function sign(algo, signingInput, keyState) {
    var data = ENC.encode(signingInput);
    if (algo === 'RS256') {
      if (!keyState.priv) return Promise.reject(new Error('Private key required for RS256'));
      return crypto.subtle.importKey('pkcs8', unpem(keyState.priv), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign'])
        .then(function (k) { return crypto.subtle.sign('RSASSA-PKCS1-v1_5', k, data); }).then(b64uBytes);
    }
    if (!keyState.secret) return Promise.reject(new Error('Secret required for ' + algo));
    return crypto.subtle.importKey('raw', secretBytes(keyState.secret, keyState.secretFmt), { name: 'HMAC', hash: { name: HASH[algo] } }, false, ['sign'])
      .then(function (k) { return crypto.subtle.sign('HMAC', k, data); }).then(b64uBytes);
  }
  // returns Promise<boolean>
  function verify(algo, signingInput, sigB64u, keyState) {
    var data = ENC.encode(signingInput), sig = unb64u(sigB64u);
    if (algo === 'RS256') {
      if (!keyState.pub) return Promise.reject(new Error('Public key required for RS256'));
      return crypto.subtle.importKey('spki', unpem(keyState.pub), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
        .then(function (k) { return crypto.subtle.verify('RSASSA-PKCS1-v1_5', k, sig, data); });
    }
    if (!keyState.secret) return Promise.reject(new Error('Secret required for ' + algo));
    return crypto.subtle.importKey('raw', secretBytes(keyState.secret, keyState.secretFmt), { name: 'HMAC', hash: { name: HASH[algo] } }, false, ['verify'])
      .then(function (k) { return crypto.subtle.verify('HMAC', k, sig, data); });
  }

  var I_TOKEN = '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/><path d="M9 12l2 2 4-4"/>';
  var I_CODE = '<path d="M7 7 3 12l4 5M17 7l4 5-4 5M14 4l-4 16"/>';
  var I_JSON = '<path d="M8 4H6a2 2 0 0 0-2 2v4l-2 2 2 2v4a2 2 0 0 0 2 2h2M16 4h2a2 2 0 0 1 2 2v4l2 2-2 2v4a2 2 0 0 1-2 2h-2"/>';
  var I_CHECK = '<path d="M20 6 9 17l-5-5"/>';
  var I_SHUF = '<path d="M18 4l3 3-3 3M21 7H8a4 4 0 0 0-4 4M6 20l-3-3 3-3M3 17h12a4 4 0 0 0 4-4"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  function pem(label, buf) { var b = new Uint8Array(buf), s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return '-----BEGIN ' + label + '-----\n' + btoa(s).replace(/(.{64})/g, '$1\n').trim() + '\n-----END ' + label + '-----'; }

  CK.registerTool('jwt', function (root, ctx) {
    var ui = CK.ui, el = CK.el, algo = 'HS256';
    function o(a) { return { value: a[0], label: a[1] }; }

    root.appendChild(ui.head('JSON Web Token', 'sign + verify'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_TOKEN);
    strip.acts.appendChild(ui.iconBtn(I_CHECK, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col' });
    var colR = el('div', { class: 'col' });

    var algoSel = ui.select([['HS256', 'HS256 (HMAC SHA-256)'], ['HS384', 'HS384 (HMAC SHA-384)'], ['HS512', 'HS512 (HMAC SHA-512)'], ['RS256', 'RS256 (RSA SHA-256)']].map(o), function (v) { algo = v; applyAlgo(); updateSel(); }, 'HS256');
    colR.appendChild(ui.field('Algorithm', algoSel));

    // HMAC secret (HS*)
    var secretInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'HMAC secret' });
    var secretFmt = ui.select([['utf8', 'UTF-8'], ['base64', 'Base64'], ['hex', 'Hexadecimal']].map(o), null, 'utf8');
    var secretGen = ui.iconBtn(I_SHUF, 'Random secret', function () { secretInput.value = bytesToFmt(rndBytes(32), secretFmt.value); });
    var secretWrap = el('div', { style: 'display:flex; gap:5px; align-items:center; overflow:hidden;' });
    secretInput.style.flex = '1'; secretInput.style.minWidth = '0'; secretFmt.style.width = 'auto';
    secretWrap.appendChild(secretInput); secretWrap.appendChild(secretFmt); secretWrap.appendChild(secretGen);
    var secretField = ui.field('Secret', secretWrap);
    colL.appendChild(secretField);

    // RSA keys (RS256)
    function keyBox(labelText) {
      var input = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: labelText + ' (PEM)' });
      input.style.flex = '1'; input.style.fontSize = '11px'; input.style.minWidth = '0';
      var wrap = el('div', { style: 'display:flex; gap:5px; align-items:center; overflow:hidden;' });
      wrap.appendChild(input);
      return { field: ui.field(labelText, wrap), input: input, wrap: wrap };
    }
    var pub = keyBox('Public key'), priv = keyBox('Private key');
    var genBtn = ui.iconBtn(I_SHUF, 'Generate RSA keypair', doGenerate);
    priv.wrap.appendChild(genBtn);
    pub.field.style.display = 'none'; priv.field.style.display = 'none';
    colL.appendChild(pub.field); colL.appendChild(priv.field);

    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'TOKEN / CLAIMS', icon: I_TOKEN, placeholder: 'Paste a JWT to decode or verify, or paste a claims JSON to sign...', primaries: [{ label: 'Sign', cls: 'enc', onClick: doSign }, { label: 'Decode', cls: 'dec', onClick: doDecode }], actions: ['copy', 'paste', 'clear'], onInput: clearVerify });
    var outP = ui.textPanel({ title: 'RESULT', icon: I_JSON, placeholder: 'Decoded header and payload, or the signed token...', actions: ['copy', 'download'], downloadName: 'jwt.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearVerify() { inP.ta.classList.remove('verify-match', 'verify-fail'); outP.ta.classList.remove('verify-match', 'verify-fail'); }
    outP.ta.addEventListener('input', clearVerify);

    function keyState() { return { secret: secretInput.value, secretFmt: secretFmt.value, pub: pub.ta ? pub.ta.value : pub.input.value, priv: priv.input.value }; }
    // The keyBox exposes `.input`; alias `.ta` for RSA generation reuse
    pub.ta = pub.input; priv.ta = priv.input;

    function applyAlgo() {
      var rsa = algo === 'RS256';
      secretField.style.display = rsa ? 'none' : '';
      pub.field.style.display = rsa ? '' : 'none';
      priv.field.style.display = rsa ? '' : 'none';
    }
    function updateSel() { ui.setSel(strip, 'JWT · ' + algo, algo.slice(0, 2), algo === 'RS256' ? 'RSASSA-PKCS1-v1_5 with SHA-256' : 'HMAC with ' + HASH[algo].replace('SHA-', 'SHA-')); }

    function doDecode() {
      var t = inP.ta.value.trim();
      var p = t.split('.');
      if (p.length < 2) { ctx.toast('Not a valid JWT (expected header.payload.signature)', 'error'); return; }
      function part(x) { try { return JSON.stringify(JSON.parse(unb64uText(x)), null, 2); } catch (e) { try { return unb64uText(x); } catch (e2) { return '(unreadable)'; } } }
      var header;
      try { header = JSON.parse(unb64uText(p[0])); } catch (e) { header = null; }
      if (header && header.alg && HASH[header.alg]) { algo = header.alg; algoSel.value = algo; applyAlgo(); updateSel(); }
      var out = 'Header:\n' + part(p[0]) + '\n\nPayload:\n' + part(p[1]);
      if (p[2]) out += '\n\nSignature (Base64 URL):\n' + p[2];
      // Human-readable timestamps, if present
      try {
        var pay = JSON.parse(unb64uText(p[1])), notes = [];
        ['iat', 'nbf', 'exp'].forEach(function (k) { if (typeof pay[k] === 'number') notes.push(k + ': ' + new Date(pay[k] * 1000).toISOString() + (k === 'exp' && pay[k] * 1000 < Date.now() ? ' (expired)' : '')); });
        if (notes.length) out += '\n\nTimestamps:\n' + notes.join('\n');
      } catch (e) { }
      outP.ta.value = out; clearVerify(); ctx.toast('Decoded', 'success');
    }
    function doSign() {
      var claims = inP.ta.value.trim();
      if (!claims) { ctx.toast('Enter a claims JSON to sign', 'warn'); return; }
      var payloadObj;
      try { payloadObj = JSON.parse(claims); } catch (e) { ctx.toast('Claims must be valid JSON', 'error'); return; }
      var header = { alg: algo, typ: 'JWT' };
      var signingInput = b64uStr(JSON.stringify(header)) + '.' + b64uStr(JSON.stringify(payloadObj));
      return sign(algo, signingInput, keyState()).then(function (sig) {
        outP.ta.value = signingInput + '.' + sig; clearVerify(); ctx.toast('Signed with ' + algo, 'success');
      }).catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    function doVerify() {
      clearVerify();
      var t = inP.ta.value.trim(), p = t.split('.');
      if (p.length !== 3 || !p[2]) { ctx.toast('Put a full JWT (with signature) in the input', 'warn'); return; }
      var header;
      try { header = JSON.parse(unb64uText(p[0])); } catch (e) { ctx.toast('Cannot read the token header', 'error'); return; }
      var a = (header && HASH[header.alg]) ? header.alg : algo;
      verify(a, p[0] + '.' + p[1], p[2], keyState()).then(function (ok) {
        CK.flashVerify(ok, inP.ta);
        ctx.toast(ok ? 'Signature valid (' + a + ')' : 'Signature does not match', ok ? 'success' : 'error');
      }).catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    function doGenerate() {
      ctx.toast('Generating 2048-bit RSA keypair...', 'success');
      crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify'])
        .then(function (kp) { return Promise.all([crypto.subtle.exportKey('spki', kp.publicKey), crypto.subtle.exportKey('pkcs8', kp.privateKey)]); })
        .then(function (k) { pub.input.value = pem('PUBLIC KEY', k[0]); priv.input.value = pem('PRIVATE KEY', k[1]); ctx.toast('Keypair generated', 'success'); })
        .catch(function (e) { ctx.toast('Key generation failed: ' + e.message, 'error'); });
    }
    function doShare() { CK.copy(location.href.split('#')[0] + '#tool=jwt&s=' + b64uEnc(JSON.stringify({ a: algo, sf: secretFmt.value, sec: secretInput.value, in: inP.ta.value }))); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; secretInput.value = ''; secretFmt.value = 'utf8'; pub.input.value = ''; priv.input.value = ''; algo = 'HS256'; algoSel.value = 'HS256'; applyAlgo(); updateSel(); clearVerify(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); algo = st.a || 'HS256'; algoSel.value = algo; secretFmt.value = st.sf || 'utf8'; secretInput.value = st.sec || ''; inP.ta.value = st.in || ''; } catch (e) { } }
    applyAlgo(); updateSel();
  });
})();

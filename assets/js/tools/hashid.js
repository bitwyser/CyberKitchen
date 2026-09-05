/*
   hashid.js - Hash Identifier
   Paste a hash and get the most likely algorithm(s) by prefix, length and
   character set. Pure logic, no dependencies. Identification is best-effort:
   many algorithms share a digest length, so results are ranked, not certain.
*/
(function () {
  'use strict';

  // Prefix / format signatures, checked first (most reliable)
  var PREFIX = [
    { re: /^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$/, names: ['bcrypt'] },
    { re: /^\$argon2(id|i|d)\$/, names: ['Argon2'] },
    { re: /^\$6\$/, names: ['sha512crypt (Unix)'] },
    { re: /^\$5\$/, names: ['sha256crypt (Unix)'] },
    { re: /^\$1\$/, names: ['md5crypt (Unix)'] },
    { re: /^\$y\$/, names: ['yescrypt'] },
    { re: /^\$7\$/, names: ['scrypt'] },
    { re: /^\$pbkdf2-sha(256|512|1)\$/, names: ['PBKDF2'] },
    { re: /^\{SSHA\}/, names: ['Salted SHA-1 (LDAP)'] },
    { re: /^\{SHA\}/, names: ['SHA-1 (LDAP, Base64)'] },
    { re: /^\{SSHA256\}/, names: ['Salted SHA-256 (LDAP)'] },
    { re: /^\{SSHA512\}/, names: ['Salted SHA-512 (LDAP)'] },
    { re: /^\{MD5\}/, names: ['MD5 (LDAP, Base64)'] },
    { re: /^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$/, names: ['JWT (JSON Web Token)'] },
    { re: /^[0-9a-fA-F]{32}:[0-9a-fA-F]{1,}$/, names: ['MD5 with salt (hash:salt)'] },
    { re: /^[0-9a-fA-F]{40}:[0-9a-fA-F]{1,}$/, names: ['SHA-1 with salt (hash:salt)'] },
    { re: /^[0-9a-fA-F]{32}:[^:]{1,}$/, names: ['MD5 with salt (hash:salt)'] },
    { re: /^\*[0-9A-F]{40}$/, names: ['MySQL 4.1+ (SHA-1 based)'] }
  ];

  // Hex-length -> ranked candidate algorithms (chars, not bytes)
  var BY_HEX = {
    8: ['CRC-32', 'Adler-32', 'CRC-32B', 'FNV-32'],
    16: ['MySQL 3.x (old password)', 'CRC-64', 'DES (Unix, partial)'],
    32: ['MD5', 'NTLM', 'MD4', 'MD2', 'RIPEMD-128', 'Haval-128', 'Tiger-128', 'double MD5'],
    40: ['SHA-1', 'RIPEMD-160', 'Haval-160', 'Tiger-160', 'HAS-160', 'MySQL 4.1+ (SHA-1)'],
    48: ['Tiger-192', 'Haval-192', 'SHA-1 (truncated)'],
    56: ['SHA-224', 'SHA3-224', 'Haval-224', 'Keccak-224'],
    64: ['SHA-256', 'SHA3-256', 'BLAKE2s-256', 'RIPEMD-256', 'Keccak-256', 'GOST R 34.11', 'Snefru-256'],
    96: ['SHA-384', 'SHA3-384', 'Keccak-384'],
    128: ['SHA-512', 'SHA3-512', 'BLAKE2b-512', 'Whirlpool', 'Keccak-512', 'RIPEMD-320 (near)']
  };

  function identify(raw) {
    var s = (raw || '').trim();
    if (!s) return null;
    var hits = [], seen = {};
    function add(list) { list.forEach(function (n) { if (!seen[n]) { seen[n] = 1; hits.push(n); } }); }

    for (var i = 0; i < PREFIX.length; i++) if (PREFIX[i].re.test(s)) add(PREFIX[i].names);

    // Length + charset analysis for bare digests
    var isHex = /^[0-9a-fA-F]+$/.test(s);
    var isB64 = /^[A-Za-z0-9+/]+=*$/.test(s);
    var isB64u = /^[A-Za-z0-9\-_]+=*$/.test(s);
    var lines = ['Input length: ' + s.length + ' characters'];

    if (isHex) {
      lines.push('Character set: hexadecimal (' + (s.length / 2) + ' bytes)');
      if (BY_HEX[s.length]) add(BY_HEX[s.length]);
    } else if (isB64 || isB64u) {
      var bytes = Math.floor(s.replace(/=+$/, '').length * 3 / 4);
      lines.push('Character set: Base64' + (isB64u && !isB64 ? ' URL-safe' : '') + ' (about ' + bytes + ' bytes decoded)');
      var guess = { 16: ['MD5 (Base64)'], 20: ['SHA-1 (Base64)'], 28: ['SHA-224 (Base64)'], 32: ['SHA-256 (Base64)'], 48: ['SHA-384 (Base64)'], 64: ['SHA-512 (Base64)'] }[bytes];
      if (guess) add(guess);
    } else {
      lines.push('Character set: mixed / non-hex');
    }
    return { hits: hits, lines: lines };
  }

  var I_SEARCH = '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>';
  var I_HASH = '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  CK.registerTool('hashid', function (root, ctx) {
    var ui = CK.ui;

    root.appendChild(ui.head('Hash Identifier', 'best-effort'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_SEARCH);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);
    ui.setSel(strip, 'Hash Identifier', 'heuristic', 'Guesses the algorithm from prefix, length and character set. Multiple algorithms often share a length, so treat matches as candidates.');
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'HASH', icon: I_HASH, placeholder: 'Paste a hash, for example 5f4dcc3b5aa765d61d8327deb882cf99', primaries: [{ label: 'Identify', cls: 'enc', onClick: run }], actions: ['copy', 'paste', 'clear'], onInput: run });
    var outP = ui.textPanel({ title: 'LIKELY ALGORITHMS', icon: I_SEARCH, placeholder: 'Candidate algorithms appear here...', readonly: true, actions: ['copy'] });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function run() {
      var r = identify(inP.ta.value);
      if (!r) { outP.ta.value = ''; return; }
      var out = r.lines.join('\n') + '\n\n';
      if (r.hits.length) {
        out += 'Likely matches (' + r.hits.length + '), most probable first:\n';
        out += r.hits.map(function (n, i) { return '  ' + (i + 1) + '. ' + n; }).join('\n');
      } else {
        out += 'No confident match. Check for a prefix (like $2b$ or $6$), or confirm the hash was not truncated.';
      }
      outP.ta.value = out;
    }
    function doShare() { CK.copy(location.href.split('#')[0] + '#tool=hashid&s=' + b64uEnc(JSON.stringify({ in: inP.ta.value }))); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); inP.ta.value = st.in || ''; } catch (e) { } }
    run();
  });
})();

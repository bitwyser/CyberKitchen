/*
   encode.js - Encoder / Decoder tool
   Bidirectional text encodings, all pure JS (UTF-8 aware). No dependencies.
*/
(function () {
  'use strict';

  var ENC = new TextEncoder(), DECU = new TextDecoder();
  function s2b(s) { return ENC.encode(s); }
  function b2s(b) { return DECU.decode(b instanceof Uint8Array ? b : new Uint8Array(b)); }
  function bytesToHex(b) {
    b = b instanceof Uint8Array ? b : new Uint8Array(b);
    var r = ''; for (var i = 0; i < b.length; i++) r += b[i].toString(16).padStart(2, '0'); return r;
  }
  function hexToBytes(h) {
    h = h.replace(/[^0-9a-fA-F]/g, '');
    if (h.length % 2) throw new Error('Hex length must be even');
    var b = new Uint8Array(h.length / 2);
    for (var i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
    return b;
  }

  /* Base64 (UTF-8 safe) */
  function b64enc(s) { var b = s2b(s), bin = ''; for (var i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]); return btoa(bin); }
  function b64dec(s) { s = s.replace(/\s/g, ''); var bin = atob(s), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return b2s(a); }

  /* Base32 RFC 4648 */
  var B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function base32enc(s) {
    var b = s2b(s), r = '', buf = 0, bits = 0;
    for (var i = 0; i < b.length; i++) { buf = (buf << 8) | b[i]; bits += 8; while (bits >= 5) { r += B32[(buf >>> (bits - 5)) & 31]; bits -= 5; } }
    if (bits) r += B32[(buf << (5 - bits)) & 31];
    while (r.length % 8) r += '=';
    return r;
  }
  function base32dec(s) {
    s = s.toUpperCase().replace(/=+$/, ''); var out = [], buf = 0, bits = 0;
    for (var i = 0; i < s.length; i++) { var v = B32.indexOf(s[i]); if (v < 0) continue; buf = (buf << 5) | v; bits += 5; if (bits >= 8) { out.push((buf >>> (bits - 8)) & 255); bits -= 8; } }
    return b2s(new Uint8Array(out));
  }

  /* Base58 (Bitcoin) */
  var B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function base58enc(s) {
    var bytes = s2b(s), digits = [0], i, j;
    for (i = 0; i < bytes.length; i++) { var carry = bytes[i]; for (j = 0; j < digits.length; j++) { carry += digits[j] << 8; digits[j] = carry % 58; carry = (carry / 58) | 0; } while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; } }
    var r = ''; for (i = 0; i < bytes.length && bytes[i] === 0; i++) r += B58[0];
    for (i = digits.length - 1; i >= 0; i--) r += B58[digits[i]];
    return r;
  }
  function base58dec(s) {
    s = s.trim(); var bytes = [0], i, j;
    for (i = 0; i < s.length; i++) { var v = B58.indexOf(s[i]); if (v < 0) throw new Error('Invalid Base58 char: ' + s[i]); var carry = v; for (j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 255; carry >>= 8; } while (carry) { bytes.push(carry & 255); carry >>= 8; } }
    for (i = 0; i < s.length && s[i] === B58[0]; i++) bytes.push(0);
    return b2s(new Uint8Array(bytes.reverse()));
  }

  /* Base62 */
  var B62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  function base62enc(s) {
    var h = bytesToHex(s2b(s)); if (!h) return ''; var n = BigInt('0x' + h);
    if (n === 0n) return '0'; var r = ''; while (n > 0n) { r = B62[Number(n % 62n)] + r; n = n / 62n; } return r;
  }
  function base62dec(s) {
    s = s.trim(); if (!s) return ''; var n = 0n;
    for (var i = 0; i < s.length; i++) { var v = B62.indexOf(s[i]); if (v < 0) throw new Error('Invalid Base62 char'); n = n * 62n + BigInt(v); }
    var h = n.toString(16); if (h.length % 2) h = '0' + h; return b2s(hexToBytes(h));
  }

  /* ASCII85 / Base85 */
  function a85enc(s) {
    var b = s2b(s), r = '<~', i, j;
    for (i = 0; i < b.length; i += 4) {
      var need = Math.min(4, b.length - i), v = 0;
      for (j = 0; j < 4; j++) v = (v * 256 + (j < need ? b[i + j] : 0)) >>> 0;
      if (v === 0 && need === 4) { r += 'z'; }
      else { var c = []; for (j = 4; j >= 0; j--) { c[j] = v % 85 + 33; v = Math.floor(v / 85); } r += String.fromCharCode.apply(null, c.slice(0, need + 1)); }
    }
    return r + '~>';
  }
  function a85dec(s) {
    s = s.replace(/^<~/, '').replace(/~>$/, '').replace(/\s/g, ''); var out = [], i;
    for (i = 0; i < s.length;) {
      if (s[i] === 'z') { out.push(0, 0, 0, 0); i++; continue; }
      var chunk = ''; for (var k = 0; k < 5 && i < s.length; k++, i++) chunk += s[i];
      var pad = 5 - chunk.length; while (chunk.length < 5) chunk += 'u';
      var v = 0; for (var j = 0; j < 5; j++) v = v * 85 + (chunk.charCodeAt(j) - 33);
      var bytes = [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];
      for (var m = 0; m < 4 - pad; m++) out.push(bytes[m]);
    }
    return b2s(new Uint8Array(out));
  }

  /* UUEncode */
  function uuenc(s) {
    var b = s2b(s), lines = ['begin 644 encoded'], i = 0;
    while (i < b.length) {
      var chunk = b.slice(i, i + 45); i += 45; var len = chunk.length, line = String.fromCharCode(len + 32);
      for (var j = 0; j < len; j += 3) {
        var b0 = chunk[j] || 0, b1 = chunk[j + 1] || 0, b2 = chunk[j + 2] || 0;
        line += String.fromCharCode(((b0 >> 2) & 63) + 32, (((b0 << 4) | (b1 >> 4)) & 63) + 32, (((b1 << 2) | (b2 >> 6)) & 63) + 32, (b2 & 63) + 32);
      }
      lines.push(line);
    }
    lines.push('`', 'end'); return lines.join('\n');
  }
  function uudec(s) {
    var out = [], lines = s.split('\n');
    lines.forEach(function (line) {
      if (!line || /^begin/.test(line) || /^end/.test(line) || line === '`') return;
      var len = (line.charCodeAt(0) - 32) & 63, i = 1, j = 0;
      while (j < len) {
        var a = (line.charCodeAt(i++) - 32) & 63, b = (line.charCodeAt(i++) - 32) & 63, c = (line.charCodeAt(i++) - 32) & 63, d = (line.charCodeAt(i++) - 32) & 63;
        if (j++ < len) out.push((a << 2) | (b >> 4));
        if (j++ < len) out.push(((b & 15) << 4) | (c >> 2));
        if (j++ < len) out.push(((c & 3) << 6) | d);
      }
    });
    return b2s(new Uint8Array(out));
  }

  /* Radix (per UTF-8 byte) */
  function radixEnc(base, pad) { return function (s) { return Array.from(s2b(s)).map(function (x) { return x.toString(base).padStart(pad, '0'); }).join(' '); }; }
  function radixDec(base) { return function (s) { return b2s(new Uint8Array(s.trim().split(/\s+/).filter(Boolean).map(function (t) { return parseInt(t, base); }))); }; }

  /* Web encodings */
  function htmlEnc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;'); }
  function htmlDec(s) { var d = document.createElement('textarea'); d.innerHTML = s; return d.value; }
  function htmlNumEnc(s) { var r = ''; for (var i = 0; i < s.length;) { var c = s.codePointAt(i); r += '&#' + c + ';'; i += c > 0xFFFF ? 2 : 1; } return r; }
  function xmlEnc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;'); }
  function xmlDec(s) { return s.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#x([0-9a-fA-F]+);/g, function (_, h) { return String.fromCodePoint(parseInt(h, 16)); }).replace(/&#(\d+);/g, function (_, n) { return String.fromCodePoint(+n); }); }
  function uniEnc(s) { var r = ''; for (var i = 0; i < s.length; i++) r += '\\u' + s.charCodeAt(i).toString(16).toUpperCase().padStart(4, '0'); return r; }
  function uniDec(s) { return s.replace(/\\u([0-9a-fA-F]{4})/g, function (_, h) { return String.fromCharCode(parseInt(h, 16)); }); }
  function cssEnc(s) { var r = ''; for (var i = 0; i < s.length; i++) { var c = s.codePointAt(i); if (c > 127 || c < 32) { r += '\\' + c.toString(16).toUpperCase().padStart(6, '0') + ' '; if (c > 0xFFFF) i++; } else r += s[i]; } return r; }
  function cssDec(s) { return s.replace(/\\([0-9a-fA-F]{1,6})\s?/g, function (_, h) { return String.fromCodePoint(parseInt(h, 16)); }); }
  function jsEnc(s) { return JSON.stringify(s).slice(1, -1); }
  function jsDec(s) { try { return JSON.parse('"' + s.replace(/"/g, '\\"') + '"'); } catch (e) { return s; } }
  function jwtDec(s) {
    var p = s.trim().split('.'); if (p.length < 2) throw new Error('Not a valid JWT');
    function dp(x) { x = x.replace(/-/g, '+').replace(/_/g, '/'); while (x.length % 4) x += '='; try { return JSON.stringify(JSON.parse(atob(x)), null, 2); } catch (e) { return atob(x); } }
    return 'Header:\n' + dp(p[0]) + '\n\nPayload:\n' + dp(p[1]) + (p[2] ? '\n\nSignature:\n' + p[2] : '');
  }
  function jwtEnc(s) {
    var h = function (o) { return btoa(JSON.stringify(o)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'); };
    var hdr = h({ alg: 'none', typ: 'JWT' });
    try { return hdr + '.' + h(JSON.parse(s)) + '.'; }
    catch (e) { return hdr + '.' + b64enc(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_') + '.'; }
  }

  /* Text ciphers */
  var MORSE = { A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---', K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.', '@': '.--.-.' };
  var MORSE_R = (function () { var m = {}; Object.keys(MORSE).forEach(function (k) { m[MORSE[k]] = k; }); return m; })();
  function morseEnc(s) { return s.toUpperCase().split('').map(function (c) { return c === ' ' ? '/' : (MORSE[c] || ''); }).filter(function (x) { return x !== ''; }).join(' '); }
  function morseDec(s) { return s.trim().split(/\s+/).map(function (t) { return t === '/' ? ' ' : (MORSE_R[t] || ''); }).join(''); }

  var NATO = { A: 'Alfa', B: 'Bravo', C: 'Charlie', D: 'Delta', E: 'Echo', F: 'Foxtrot', G: 'Golf', H: 'Hotel', I: 'India', J: 'Juliett', K: 'Kilo', L: 'Lima', M: 'Mike', N: 'November', O: 'Oscar', P: 'Papa', Q: 'Quebec', R: 'Romeo', S: 'Sierra', T: 'Tango', U: 'Uniform', V: 'Victor', W: 'Whiskey', X: 'Xray', Y: 'Yankee', Z: 'Zulu', '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three', '4': 'Four', '5': 'Five', '6': 'Six', '7': 'Seven', '8': 'Eight', '9': 'Nine' };
  var NATO_R = (function () { var m = {}; Object.keys(NATO).forEach(function (k) { m[NATO[k].toLowerCase()] = k; }); return m; })();
  function natoEnc(s) { return s.toUpperCase().split('').map(function (c) { return NATO[c] || (c === ' ' ? '' : c); }).filter(Boolean).join(' '); }
  function natoDec(s) { return s.trim().split(/\s+/).map(function (w) { return NATO_R[w.toLowerCase()] || w; }).join(''); }

  function rot13(s) { return s.replace(/[a-z]/gi, function (c) { var base = c <= 'Z' ? 65 : 97; return String.fromCharCode((c.charCodeAt(0) - base + 13) % 26 + base); }); }
  function rot47(s) { return s.replace(/[!-~]/g, function (c) { return String.fromCharCode(33 + (c.charCodeAt(0) - 33 + 47) % 94); }); }
  function atbash(s) { return s.replace(/[a-z]/gi, function (c) { return c <= 'Z' ? String.fromCharCode(90 - (c.charCodeAt(0) - 65)) : String.fromCharCode(122 - (c.charCodeAt(0) - 97)); }); }

  function qpEnc(s) { var b = s2b(s), r = ''; for (var i = 0; i < b.length; i++) { var c = b[i]; if (c === 61) r += '=3D'; else if ((c >= 33 && c <= 126) || c === 32 || c === 9) r += String.fromCharCode(c); else r += '=' + c.toString(16).toUpperCase().padStart(2, '0'); } return r; }
  function qpDec(s) { s = s.replace(/=\r?\n/g, ''); var out = []; for (var i = 0; i < s.length; i++) { if (s[i] === '=') { out.push(parseInt(s.substr(i + 1, 2), 16)); i += 2; } else out.push(s.charCodeAt(i)); } return b2s(new Uint8Array(out)); }

  /* Encoding registry */
  var LIST = [
    { id: 'base64', label: 'Base64', group: 'Bases', badge: 'RFC4648', desc: 'Standard RFC 4648 Base64', enc: b64enc, dec: b64dec },
    { id: 'base64url', label: 'Base64URL', group: 'Bases', badge: 'RFC4648', desc: 'URL-safe Base64 (no + / =)', enc: function (s) { return b64enc(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }, dec: function (s) { s = s.trim().replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return b64dec(s); } },
    { id: 'base32', label: 'Base32', group: 'Bases', badge: 'RFC4648', desc: 'Base32 (A-Z 2-7)', enc: base32enc, dec: base32dec },
    { id: 'base58', label: 'Base58', group: 'Bases', badge: 'BTC', desc: 'Base58 (Bitcoin alphabet)', enc: base58enc, dec: base58dec },
    { id: 'base62', label: 'Base62', group: 'Bases', badge: 'Base62', desc: 'Base62 alphanumeric', enc: base62enc, dec: base62dec },
    { id: 'ascii85', label: 'ASCII85', group: 'Bases', badge: 'Base85', desc: 'ASCII85 / Base85 (<~ ~>)', enc: a85enc, dec: a85dec },
    { id: 'hex', label: 'Hex', group: 'Bases', badge: 'Base16', desc: 'Hexadecimal', enc: function (s) { return bytesToHex(s2b(s)); }, dec: function (s) { return b2s(hexToBytes(s)); } },
    { id: 'uuencode', label: 'UUEncode', group: 'Bases', badge: 'UU', desc: 'Unix-to-Unix encoding', enc: uuenc, dec: uudec },

    { id: 'binary', label: 'Binary', group: 'Radix', badge: 'Base2', desc: '8-bit binary per byte', enc: radixEnc(2, 8), dec: radixDec(2) },
    { id: 'octal', label: 'Octal', group: 'Radix', badge: 'Base8', desc: 'Octal per byte', enc: radixEnc(8, 3), dec: radixDec(8) },
    { id: 'decimal', label: 'Decimal', group: 'Radix', badge: 'Base10', desc: 'Decimal byte values', enc: radixEnc(10, 0), dec: radixDec(10) },

    { id: 'url', label: 'URL', group: 'Web', badge: 'RFC3986', desc: 'URL percent-encoding', enc: function (s) { return encodeURIComponent(s); }, dec: function (s) { return decodeURIComponent(s); } },
    { id: 'urlall', label: 'URL Full', group: 'Web', badge: 'RFC3986', desc: 'Encode all reserved chars', enc: function (s) { return encodeURIComponent(s).replace(/[!'()*]/g, function (c) { return '%' + c.charCodeAt(0).toString(16).toUpperCase(); }); }, dec: function (s) { return decodeURIComponent(s); } },
    { id: 'html', label: 'HTML', group: 'Web', badge: 'HTML5', desc: 'HTML entity encoding', enc: htmlEnc, dec: htmlDec },
    { id: 'htmlnum', label: 'HTML Num', group: 'Web', badge: 'HTML5', desc: 'Numeric HTML entities', enc: htmlNumEnc, dec: htmlDec },
    { id: 'xml', label: 'XML', group: 'Web', badge: 'XML1.0', desc: 'XML / SGML entities', enc: xmlEnc, dec: xmlDec },
    { id: 'unicode', label: 'Unicode', group: 'Web', badge: 'ES6', desc: 'JavaScript \\uXXXX escapes', enc: uniEnc, dec: uniDec },
    { id: 'jsesc', label: 'JS Escape', group: 'Web', badge: 'ES6', desc: 'JavaScript string escape', enc: jsEnc, dec: jsDec },
    { id: 'cssesc', label: 'CSS Escape', group: 'Web', badge: 'CSS3', desc: 'CSS unicode escape', enc: cssEnc, dec: cssDec },
    { id: 'jwt', label: 'JWT', group: 'Web', badge: 'RFC7519', desc: 'JWT (decode header + payload)', enc: jwtEnc, dec: jwtDec },

    { id: 'morse', label: 'Morse', group: 'Text', badge: 'ITU', desc: 'International Morse code', enc: morseEnc, dec: morseDec },
    { id: 'nato', label: 'NATO', group: 'Text', badge: 'ICAO', desc: 'NATO phonetic alphabet', enc: natoEnc, dec: natoDec },
    { id: 'rot13', label: 'ROT13', group: 'Text', badge: 'Cipher', desc: 'ROT13 letter rotation', enc: rot13, dec: rot13 },
    { id: 'rot47', label: 'ROT47', group: 'Text', badge: 'Cipher', desc: 'ROT47 ASCII rotation', enc: rot47, dec: rot47 },
    { id: 'atbash', label: 'Atbash', group: 'Text', badge: 'Cipher', desc: 'Atbash mirror cipher', enc: atbash, dec: atbash },
    { id: 'qp', label: 'Quoted-P.', group: 'Text', badge: 'MIME', desc: 'Quoted-printable (MIME)', enc: qpEnc, dec: qpDec }
  ];
  function getEnc(id) { for (var i = 0; i < LIST.length; i++) if (LIST[i].id === id) return LIST[i]; return null; }
  var GROUP_ORDER = ['Bases', 'Radix', 'Web', 'Text'];

  /* Auto-detect */
  function detect(s) {
    var c = s.trim();
    if (!c) return null;
    if (/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$/.test(c)) return 'jwt';
    if (/^begin /.test(c) && /\bend\b/.test(c)) return 'uuencode';
    if (/^<~/.test(c) && /~>$/.test(c)) return 'ascii85';
    if (/^[.\-/\s]+$/.test(c) && /[.\-]/.test(c)) return 'morse';
    if (/^[01\s]+$/.test(c) && c.replace(/\s/g, '').length % 8 === 0) return 'binary';
    if (/%[0-9a-fA-F]{2}/.test(c)) return 'url';
    if (/&[a-z]+;|&#\d+;|&#x[0-9a-f]+;/i.test(c)) return 'html';
    if (/\\u[0-9a-fA-F]{4}/.test(c)) return 'unicode';
    if (/^[0-9a-fA-F\s]+$/.test(c) && c.replace(/\s/g, '').length % 2 === 0 && c.replace(/\s/g, '').length >= 2) return 'hex';
    if (/^[A-Za-z0-9\-_]+$/.test(c) && (c.indexOf('-') >= 0 || c.indexOf('_') >= 0) && c.length >= 4) return 'base64url';
    if (/^[A-Za-z0-9+/]+=*$/.test(c) && c.length % 4 === 0 && c.length >= 4) { try { atob(c); return 'base64'; } catch (e) { } }
    if (/^[A-Z2-7]+=*$/i.test(c) && c.length % 8 === 0) return 'base32';
    if (/^[1-9A-HJ-NP-Za-km-z]+$/.test(c) && c.length >= 6) return 'base58';
    return null;
  }

  /* Share-URL state (base64url of JSON) */
  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  var I_FILE = '<path d="M14 3v5h5M6 3h9l5 5v13H6z"/>';
  var I_CODE = '<path d="M7 7 3 12l4 5M17 7l4 5-4 5M14 4l-4 16"/>';
  var I_CHECK = '<path d="M20 6 9 17l-5-5"/>';
  var I_SWAP = '<path d="M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4"/>';
  var I_DETECT = '<path d="m12 3 1.9 4.6L18 9l-4.1 1.4L12 15l-1.9-4.6L6 9l4.1-1.4zM19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9z"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('encode', function (root, ctx) {
    var ui = CK.ui, current = 'base64';

    root.appendChild(ui.head('Encoder / Decoder', LIST.length + ' types'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_CODE);
    strip.acts.appendChild(ui.iconBtn(I_CHECK, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(I_DETECT, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(I_SWAP, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var groups = GROUP_ORDER.map(function (g) {
      return { label: g, items: LIST.filter(function (e) { return e.group === g; }).map(function (e) { return { id: e.id, label: e.label, title: e.desc }; }) };
    });
    var pk = ui.picker(groups, select);
    pk.el.classList.add('stacked');
    var pkGrid = CK.el('div', { class: 'cfg-grid', style: 'grid-template-columns:1fr;' });
    pkGrid.appendChild(pk.el);
    cfg.appendChild(pkGrid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: I_FILE, placeholder: 'Text to encode, or encoded data to decode...', primaries: [{ label: 'Encode', cls: 'enc', onClick: doEncode }, { label: 'Decode', cls: 'dec', onClick: doDecode }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'input.txt', onInput: clearVerify });
    var outP = ui.textPanel({ title: 'OUTPUT', icon: I_CODE, placeholder: 'Result appears here...', actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'output.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearVerify() { outP.ta.classList.remove('verify-match', 'verify-fail'); }
    function select(id) { var e = getEnc(id); if (!e) return; current = id; pk.setActive(id); ui.setSel(strip, e.label, e.badge, e.desc); clearVerify(); }
    function doEncode() { try { var e = getEnc(current); if (!inP.ta.value) throw new Error('Input is empty'); outP.ta.value = e.enc(inP.ta.value); clearVerify(); ctx.toast(e.label + ' encoded', 'success'); } catch (err) { ctx.toast(err.message, 'error'); } }
    function doDecode() { try { var e = getEnc(current); if (!inP.ta.value) throw new Error('Input is empty'); outP.ta.value = e.dec(inP.ta.value); clearVerify(); ctx.toast(e.label + ' decoded', 'success'); } catch (err) { ctx.toast(err.message, 'error'); } }
    function doSwap() { inP.ta.value = outP.ta.value; outP.ta.value = ''; clearVerify(); ctx.toast('Output moved to input', 'success'); }
    function doVerify() {
      try {
        var left = inP.ta.value.trim(), right = outP.ta.value.trim();
        if (!left || !right) throw new Error('Both panels need content');
        var e = getEnc(current), match = (e.enc(left).trim() === right);
        if (!match) { try { match = (e.dec(right).trim() === left); } catch (x) { } }
        clearVerify(); outP.ta.classList.add(match ? 'verify-match' : 'verify-fail');
        ctx.toast(match ? 'Match: panels are equivalent' : 'No match', match ? 'success' : 'error');
      } catch (err) { ctx.toast(err.message, 'error'); }
    }
    function doDetect() {
      var s = inP.ta.value.trim() || outP.ta.value.trim();
      if (!s) { ctx.toast('Enter data first', 'warn'); return; }
      var id = detect(s);
      if (id) { select(id); ctx.toast('Detected: ' + getEnc(id).label, 'success'); }
      else ctx.toast('Could not detect encoding', 'warn');
    }
    function doShare() {
      var st = { enc: current, in: inP.ta.value, out: outP.ta.value };
      var url = location.href.split('#')[0] + '#tool=encode&s=' + b64uEnc(JSON.stringify(st));
      CK.copy(url);
    }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; select('base64'); ctx.toast('Reset complete', 'success'); }

    // Restore shared state, if any
    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); if (st.in != null) inP.ta.value = st.in; if (st.out != null) outP.ta.value = st.out; if (st.enc) current = st.enc; } catch (e) { } }
    select(current);

    return {
      reset: doReset,
      onKey: function (e) {
        if (!(e.ctrlKey || e.metaKey)) return;
        var k = String(e.key).toLowerCase();
        if (k === 'e') { e.preventDefault(); doEncode(); }
        else if (k === 'd') { e.preventDefault(); doDecode(); }
      }
    };
  });
})();

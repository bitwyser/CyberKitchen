/*
   classical.js - Classical Ciphers (27)
   Shift, polyalphabetic, substitution, transposition and XOR ciphers. Pure JS.
*/
(function () {
  'use strict';
  var E = new TextEncoder(), D = new TextDecoder();
  function s2b(s) { return E.encode(s); }
  function b2s(b) { return D.decode(b); }
  function toHex(b) { var s = ''; for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; }
  function hexToBytes(h) { h = h.replace(/[^0-9a-fA-F]/g, ''); var a = new Uint8Array(h.length / 2); for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
  function cleanKey(k) { return (k || '').toUpperCase().replace(/[^A-Z]/g, ''); }
  function shiftLetters(t, fn) { return t.replace(/[a-z]/gi, function (c) { var b = c <= 'Z' ? 65 : 97; return String.fromCharCode(((fn(c.charCodeAt(0) - b) % 26) + 26) % 26 + b); }); }

  function caesar(t, s) { return shiftLetters(t, function (x) { return x + s; }); }
  function atbash(t) { return shiftLetters(t, function (x) { return 25 - x; }); }
  function rot47(t) { return t.replace(/[!-~]/g, function (c) { return String.fromCharCode(33 + (c.charCodeAt(0) - 33 + 47) % 94); }); }
  function modInv(a) { a = ((a % 26) + 26) % 26; for (var x = 1; x < 26; x++) if ((a * x) % 26 === 1) return x; return -1; }
  function affine(t, key, dec) { var m = /(-?\d+)\s*,\s*(-?\d+)/.exec(key || ''); if (!m) throw new Error('Key must be "a, b"'); var a = +m[1], b = +m[2], ai = modInv(a); if (ai < 0) throw new Error('a must be coprime with 26'); return shiftLetters(t, function (x) { return dec ? ai * (x - b) : a * x + b; }); }
  function a1z26e(t) { return t.toUpperCase().split('').map(function (c) { return c >= 'A' && c <= 'Z' ? (c.charCodeAt(0) - 64) : (c === ' ' ? '/' : ''); }).filter(function (x) { return x !== ''; }).join(' '); }
  function a1z26d(t) { return t.split(/\s+/).map(function (x) { if (x === '/') return ' '; var n = +x; return n >= 1 && n <= 26 ? String.fromCharCode(n + 64) : ''; }).join(''); }

  function poly(t, key, fn) { key = cleanKey(key); if (!key) throw new Error('Keyword required'); var ki = 0; return t.replace(/[a-z]/gi, function (c) { var b = c <= 'Z' ? 65 : 97, k = key.charCodeAt(ki % key.length) - 65, p = c.charCodeAt(0) - b; ki++; return String.fromCharCode(fn(p, k) + b); }); }
  function vigenere(t, key, dec) { return poly(t, key, function (p, k) { return (dec ? (p - k + 26) : (p + k)) % 26; }); }
  function variantbf(t, key, dec) { return poly(t, key, function (p, k) { return (dec ? (p + k) : (p - k + 26)) % 26; }); }
  function beaufort(t, key) { return poly(t, key, function (p, k) { return (k - p + 26) % 26; }); }
  function gronsfeld(t, key, dec) { var d = (key || '').replace(/[^0-9]/g, ''); if (!d) throw new Error('Numeric key required'); var ki = 0; return t.replace(/[a-z]/gi, function (c) { var b = c <= 'Z' ? 65 : 97, k = +d[ki % d.length], p = c.charCodeAt(0) - b; ki++; return String.fromCharCode((dec ? (p - k + 260) : (p + k)) % 26 + b); }); }
  function porta(t, key) { key = cleanKey(key); if (!key) throw new Error('Keyword required'); var ki = 0; return t.replace(/[a-z]/gi, function (ch) { var up = ch <= 'Z', c = ch.toUpperCase().charCodeAt(0) - 65, k = key.charCodeAt(ki % key.length) - 65, row = Math.floor(k / 2), r; ki++; if (c < 13) r = (c + row) % 13 + 13; else { r = ((c - 13 - row) % 13 + 13) % 13; } var o = String.fromCharCode(r + 65); return up ? o : o.toLowerCase(); }); }
  function autokey(t, key, dec) { key = cleanKey(key); if (!key) throw new Error('Keyword required'); var ks = key.split(''), ki = 0; return t.replace(/[a-z]/gi, function (c) { var b = c <= 'Z' ? 65 : 97, k = ks[ki].charCodeAt(0) - 65; if (!dec) { var p = c.charCodeAt(0) - b; ks.push(String.fromCharCode(p + 65)); ki++; return String.fromCharCode((p + k) % 26 + b); } var ct = c.charCodeAt(0) - b, pp = (ct - k + 26) % 26; ks.push(String.fromCharCode(pp + 65)); ki++; return String.fromCharCode(pp + b); }); }
  function runningkey(t, key, dec) { var kk = cleanKey(key); if (!kk) throw new Error('Running key text required'); var ki = 0; return t.replace(/[a-z]/gi, function (c) { var b = c <= 'Z' ? 65 : 97, k = kk.charCodeAt(ki % kk.length) - 65, p = c.charCodeAt(0) - b; ki++; return String.fromCharCode((dec ? (p - k + 26) : (p + k)) % 26 + b); }); }

  var MORSE = { A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---', K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.' };
  var MORSE_R = (function () { var m = {}; Object.keys(MORSE).forEach(function (k) { m[MORSE[k]] = k; }); return m; })();
  function morseE(t) { return t.toUpperCase().split('').map(function (c) { return c === ' ' ? '/' : (MORSE[c] || ''); }).filter(function (x) { return x !== ''; }).join(' '); }
  function morseD(t) { return t.trim().split(/\s+/).map(function (x) { return x === '/' ? ' ' : (MORSE_R[x] || ''); }).join(''); }

  function baconE(t) { return t.toUpperCase().replace(/[^A-Z]/g, '').split('').map(function (c) { return (c.charCodeAt(0) - 65).toString(2).padStart(5, '0').replace(/0/g, 'a').replace(/1/g, 'b'); }).join(' '); }
  function baconD(t) { var b = t.toLowerCase().replace(/[^ab]/g, ''), r = ''; for (var i = 0; i + 5 <= b.length; i += 5) r += String.fromCharCode(parseInt(b.substr(i, 5).replace(/a/g, '0').replace(/b/g, '1'), 2) + 65); return r; }

  var POL = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
  function polybiusE(t) { t = t.toUpperCase().replace(/J/g, 'I'); var r = []; for (var i = 0; i < t.length; i++) { var idx = POL.indexOf(t[i]); if (idx < 0) continue; r.push('' + (Math.floor(idx / 5) + 1) + (idx % 5 + 1)); } return r.join(' '); }
  function polybiusD(t) { var d = t.replace(/[^1-5]/g, ''), r = ''; for (var i = 0; i + 2 <= d.length; i += 2) { var idx = (+d[i] - 1) * 5 + (+d[i + 1] - 1); if (idx >= 0 && idx < 25) r += POL[idx]; } return r; }

  function subAlpha(key) { key = cleanKey(key); var seen = {}, a = '', i; for (i = 0; i < key.length; i++) if (!seen[key[i]]) { seen[key[i]] = 1; a += key[i]; } for (i = 65; i <= 90; i++) { var ch = String.fromCharCode(i); if (!seen[ch]) a += ch; } return a; }
  function substitution(t, key, dec) { var a = subAlpha(key); return t.replace(/[a-z]/gi, function (c) { var up = c <= 'Z', i = up ? c.charCodeAt(0) - 65 : c.charCodeAt(0) - 97; var o = dec ? String.fromCharCode(a.indexOf(String.fromCharCode(i + 65)) + 65) : a[i]; return up ? o : o.toLowerCase(); }); }

  /* 5x5 square helpers (Playfair / four-square / two-square) */
  function square(key) { key = cleanKey(key).replace(/J/g, 'I'); var seen = {}, s = '', i; for (i = 0; i < key.length; i++) if (!seen[key[i]]) { seen[key[i]] = 1; s += key[i]; } for (i = 0; i < 25; i++) { var ch = POL[i]; if (!seen[ch]) s += ch; } return s; }
  function digraphs(t) { t = t.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, ''); var out = [], i = 0; while (i < t.length) { var a = t[i], b = t[i + 1]; if (!b) { out.push(a + 'X'); i += 1; } else if (a === b) { out.push(a + 'X'); i += 1; } else { out.push(a + b); i += 2; } } return out; }
  function playfair(t, key, dec) { var sq = square(key), d = digraphs(t), r = '', s = dec ? -1 : 1; d.forEach(function (pair) { var i1 = sq.indexOf(pair[0]), i2 = sq.indexOf(pair[1]); var r1 = i1 / 5 | 0, c1 = i1 % 5, r2 = i2 / 5 | 0, c2 = i2 % 5; if (r1 === r2) { r += sq[r1 * 5 + (c1 + s + 5) % 5] + sq[r2 * 5 + (c2 + s + 5) % 5]; } else if (c1 === c2) { r += sq[((r1 + s + 5) % 5) * 5 + c1] + sq[((r2 + s + 5) % 5) * 5 + c2]; } else { r += sq[r1 * 5 + c2] + sq[r2 * 5 + c1]; } }); return r; }
  function twoKeys(key) { var m = (key || '').split(','); return [square(m[0] || ''), square(m[1] || '')]; }
  function foursquare(t, key, dec) {
    var k = twoKeys(key), plain = square(''), tr = k[0], bl = k[1], d = digraphs(t), r = '';
    d.forEach(function (p) {
      var i1 = plain.indexOf(p[0]), i2 = plain.indexOf(p[1]);
      var r1 = i1 / 5 | 0, c1 = i1 % 5, r2 = i2 / 5 | 0, c2 = i2 % 5;
      if (!dec) { r += tr[r1 * 5 + c2] + bl[r2 * 5 + c1]; }
      else { var a = tr.indexOf(p[0]), b = bl.indexOf(p[1]); var ar = a / 5 | 0, ac = a % 5, br = b / 5 | 0, bc = b % 5; r += plain[ar * 5 + bc] + plain[br * 5 + ac]; }
    });
    return r;
  }
  function twosquare(t, key) { var k = twoKeys(key), top = k[0], bot = k[1], d = digraphs(t), r = ''; d.forEach(function (p) { var i1 = top.indexOf(p[0]), i2 = bot.indexOf(p[1]); var r1 = i1 / 5 | 0, c1 = i1 % 5, r2 = i2 / 5 | 0, c2 = i2 % 5; if (c1 === c2) { r += p[0] + p[1]; } else { r += top[r1 * 5 + c2] + bot[r2 * 5 + c1]; } }); return r; }

  /* Transposition */
  function railE(t, n) { n = Math.max(2, n | 0); var rows = []; for (var i = 0; i < n; i++) rows.push(''); var r = 0, dir = 1; for (i = 0; i < t.length; i++) { rows[r] += t[i]; r += dir; if (r === 0 || r === n - 1) dir = -dir; } return rows.join(''); }
  function railD(t, n) { n = Math.max(2, n | 0); var len = t.length, pat = [], r = 0, dir = 1, i; for (i = 0; i < len; i++) { pat.push(r); r += dir; if (r === 0 || r === n - 1) dir = -dir; } var cnt = []; for (i = 0; i < n; i++) cnt.push(0); for (i = 0; i < len; i++) cnt[pat[i]]++; var pos = [], acc = 0; for (r = 0; r < n; r++) { pos.push(acc); acc += cnt[r]; } var out = []; for (i = 0; i < len; i++) out[i] = t[pos[pat[i]]++]; return out.join(''); }
  function scytaleE(t, n) { n = Math.max(2, n | 0); var out = ''; for (var c = 0; c < n; c++) for (var k = c; k < t.length; k += n) out += t[k]; return out; }
  function scytaleD(t, n) { n = Math.max(2, n | 0); var len = t.length, map = [], idx = 0; for (var c = 0; c < n; c++) for (var k = c; k < len; k += n) map[k] = idx++; var out = []; for (var i = 0; i < len; i++) out[i] = t[map[i]]; return out.join(''); }
  function colOrder(key) { var k = cleanKey(key); if (!k) throw new Error('Keyword required'); var idx = k.split('').map(function (ch, i) { return [ch, i]; }); idx.sort(function (a, b) { return a[0] === b[0] ? a[1] - b[1] : a[0] < b[0] ? -1 : 1; }); return idx.map(function (x) { return x[1]; }); }
  function columnarE(t, key) { var order = colOrder(key), n = order.length, rows = Math.ceil(t.length / n), out = ''; order.forEach(function (col) { for (var r = 0; r < rows; r++) { var p = r * n + col; if (p < t.length) out += t[p]; } }); return out; }
  function columnarD(t, key) { var order = colOrder(key), n = order.length, len = t.length, rows = Math.ceil(len / n); var colLen = []; var full = len % n; for (var c = 0; c < n; c++) colLen[c] = rows - (full === 0 ? 0 : (c >= full ? 1 : 0)); var grid = [], pos = 0; order.forEach(function (col) { grid[col] = t.substr(pos, colLen[col]); pos += colLen[col]; }); var out = '', ptr = []; for (c = 0; c < n; c++) ptr[c] = 0; for (var r = 0; r < rows; r++) for (c = 0; c < n; c++) { if (ptr[c] < grid[c].length) { out += grid[c][ptr[c]++]; } } return out; }
  function spiralPos(rows, cols) { var order = [], top = 0, bottom = rows - 1, left = 0, right = cols - 1; while (top <= bottom && left <= right) { for (var c = left; c <= right; c++) order.push(top * cols + c); top++; for (var r = top; r <= bottom; r++) order.push(r * cols + right); right--; if (top <= bottom) { for (c = right; c >= left; c--) order.push(bottom * cols + c); bottom--; } if (left <= right) { for (r = bottom; r >= top; r--) order.push(r * cols + left); left++; } } return order; }
  function routeE(t, cols) { cols = Math.max(2, cols | 0); var rows = Math.ceil(t.length / cols), pad = t + 'X'.repeat(rows * cols - t.length), order = spiralPos(rows, cols); return order.map(function (i) { return pad[i]; }).join(''); }
  function routeD(t, cols) { cols = Math.max(2, cols | 0); var rows = Math.ceil(t.length / cols), order = spiralPos(rows, cols), grid = []; for (var i = 0; i < order.length; i++) grid[order[i]] = t[i] || ''; return grid.join('').replace(/X+$/, ''); }

  /* XOR (text -> hex, hex -> text) */
  function xorConstE(t, c) { var b = s2b(t), o = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) o[i] = b[i] ^ c; return toHex(o); }
  function xorConstD(t, c) { var b = hexToBytes(t), o = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) o[i] = b[i] ^ c; return b2s(o); }
  function xorKeyE(t, key) { if (!key) throw new Error('Key required'); var b = s2b(t), k = s2b(key), o = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) o[i] = b[i] ^ k[i % k.length]; return toHex(o); }
  function xorKeyD(t, key) { if (!key) throw new Error('Key required'); var b = hexToBytes(t), k = s2b(key), o = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) o[i] = b[i] ^ k[i % k.length]; return b2s(o); }

  var LIST = [
    { id: 'caesar', label: 'Caesar', group: 'Shift', badge: 'Shift', desc: 'Caesar shift', num: 'Shift', numDef: 3, enc: function (t, p) { return caesar(t, p.num); }, dec: function (t, p) { return caesar(t, -p.num); } },
    { id: 'rot13', label: 'ROT13', group: 'Shift', badge: 'Shift', desc: 'Rotate by 13', enc: function (t) { return caesar(t, 13); }, dec: function (t) { return caesar(t, 13); } },
    { id: 'rot47', label: 'ROT47', group: 'Shift', badge: 'ASCII', desc: 'Rotate ASCII by 47', enc: rot47, dec: rot47 },
    { id: 'atbash', label: 'Atbash', group: 'Shift', badge: 'Mirror', desc: 'Atbash mirror', enc: atbash, dec: atbash },
    { id: 'affine', label: 'Affine', group: 'Shift', badge: 'Math', desc: 'Affine a*x+b', key: 'a, b', keyPh: '5, 8', enc: function (t, p) { return affine(t, p.key, false); }, dec: function (t, p) { return affine(t, p.key, true); } },
    { id: 'a1z26', label: 'A1Z26', group: 'Shift', badge: 'Numeric', desc: 'Letters to numbers', enc: a1z26e, dec: a1z26d },

    { id: 'vigenere', label: 'Vigenere', group: 'Polyalphabetic', badge: 'Key', desc: 'Vigenere', key: 'Keyword', keyPh: 'LEMON', enc: function (t, p) { return vigenere(t, p.key, false); }, dec: function (t, p) { return vigenere(t, p.key, true); } },
    { id: 'beaufort', label: 'Beaufort', group: 'Polyalphabetic', badge: 'Key', desc: 'Beaufort (reciprocal)', key: 'Keyword', keyPh: 'LEMON', enc: function (t, p) { return beaufort(t, p.key); }, dec: function (t, p) { return beaufort(t, p.key); } },
    { id: 'variantbf', label: 'Variant BF', group: 'Polyalphabetic', badge: 'Key', desc: 'Variant Beaufort', key: 'Keyword', keyPh: 'LEMON', enc: function (t, p) { return variantbf(t, p.key, false); }, dec: function (t, p) { return variantbf(t, p.key, true); } },
    { id: 'gronsfeld', label: 'Gronsfeld', group: 'Polyalphabetic', badge: 'Digits', desc: 'Numeric Vigenere', key: 'Numeric key', keyPh: '31415', enc: function (t, p) { return gronsfeld(t, p.key, false); }, dec: function (t, p) { return gronsfeld(t, p.key, true); } },
    { id: 'porta', label: 'Porta', group: 'Polyalphabetic', badge: 'Key', desc: 'Porta (reciprocal)', key: 'Keyword', keyPh: 'LEMON', enc: function (t, p) { return porta(t, p.key); }, dec: function (t, p) { return porta(t, p.key); } },
    { id: 'autokey', label: 'Autokey', group: 'Polyalphabetic', badge: 'Key', desc: 'Autokey', key: 'Keyword', keyPh: 'LEMON', enc: function (t, p) { return autokey(t, p.key, false); }, dec: function (t, p) { return autokey(t, p.key, true); } },
    { id: 'runningkey', label: 'Running Key', group: 'Polyalphabetic', badge: 'Text', desc: 'Running-key Vigenere', key: 'Key text', keyPh: 'a long passage', enc: function (t, p) { return runningkey(t, p.key, false); }, dec: function (t, p) { return runningkey(t, p.key, true); } },

    { id: 'substitution', label: 'Substitution', group: 'Substitution', badge: 'Key', desc: 'Monoalphabetic', key: 'Keyword / 26 letters', keyPh: 'CIPHER', enc: function (t, p) { return substitution(t, p.key, false); }, dec: function (t, p) { return substitution(t, p.key, true); } },
    { id: 'bacon', label: 'Bacon', group: 'Substitution', badge: 'Binary', desc: "Bacon's cipher", enc: baconE, dec: baconD },
    { id: 'polybius', label: 'Polybius', group: 'Substitution', badge: 'Grid', desc: 'Polybius square', enc: polybiusE, dec: polybiusD },
    { id: 'morse', label: 'Morse', group: 'Substitution', badge: 'ITU', desc: 'Morse code', enc: morseE, dec: morseD },
    { id: 'playfair', label: 'Playfair', group: 'Substitution', badge: 'Digraph', desc: 'Playfair (5x5)', key: 'Keyword', keyPh: 'MONARCHY', enc: function (t, p) { return playfair(t, p.key, false); }, dec: function (t, p) { return playfair(t, p.key, true); } },
    { id: 'foursquare', label: 'Four-Square', group: 'Substitution', badge: 'Digraph', desc: 'Four-square', key: 'Key 1, Key 2', keyPh: 'EXAMPLE, KEYWORD', enc: function (t, p) { return foursquare(t, p.key, false); }, dec: function (t, p) { return foursquare(t, p.key, true); } },
    { id: 'twosquare', label: 'Two-Square', group: 'Substitution', badge: 'Digraph', desc: 'Two-square (reciprocal)', key: 'Key 1, Key 2', keyPh: 'EXAMPLE, KEYWORD', enc: function (t, p) { return twosquare(t, p.key); }, dec: function (t, p) { return twosquare(t, p.key); } },

    { id: 'railfence', label: 'Rail Fence', group: 'Transposition', badge: 'Zigzag', desc: 'Rail fence', num: 'Rails', numDef: 3, enc: function (t, p) { return railE(t, p.num); }, dec: function (t, p) { return railD(t, p.num); } },
    { id: 'columnar', label: 'Columnar', group: 'Transposition', badge: 'Key', desc: 'Columnar transposition', key: 'Keyword', keyPh: 'ZEBRA', enc: function (t, p) { return columnarE(t, p.key); }, dec: function (t, p) { return columnarD(t, p.key); } },
    { id: 'scytale', label: 'Scytale', group: 'Transposition', badge: 'Rows', desc: 'Scytale transposition', num: 'Columns', numDef: 4, enc: function (t, p) { return scytaleE(t, p.num); }, dec: function (t, p) { return scytaleD(t, p.num); } },
    { id: 'routecipher', label: 'Route', group: 'Transposition', badge: 'Spiral', desc: 'Route (spiral) transposition', num: 'Columns', numDef: 5, enc: function (t, p) { return routeE(t, p.num); }, dec: function (t, p) { return routeD(t, p.num); } },

    { id: 'xorbyte', label: 'XOR Byte', group: 'XOR', badge: 'Hex out', desc: 'XOR with a constant byte', num: 'Byte (0-255)', numDef: 255, enc: function (t, p) { return xorConstE(t, p.num & 255); }, dec: function (t, p) { return xorConstD(t, p.num & 255); } },
    { id: 'xorff', label: 'XOR 0xFF', group: 'XOR', badge: 'Hex out', desc: 'XOR every byte with 0xFF', enc: function (t) { return xorConstE(t, 255); }, dec: function (t) { return xorConstD(t, 255); } },
    { id: 'xorkey', label: 'XOR Key', group: 'XOR', badge: 'Hex out', desc: 'Repeating-key XOR', key: 'Key', keyPh: 'secret', enc: function (t, p) { return xorKeyE(t, p.key); }, dec: function (t, p) { return xorKeyD(t, p.key); } }
  ];
  function get(id) { for (var i = 0; i < LIST.length; i++) if (LIST[i].id === id) return LIST[i]; return null; }
  var GROUPS = ['Shift', 'Polyalphabetic', 'Substitution', 'Transposition', 'XOR'];

  var I_SCROLL = '<path d="M4 7V5h16v2M9 20h6M12 5v15"/>';
  var I_LOCK = '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';
  var I_SWAP = '<path d="M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4"/>';
  var I_CHECK = '<path d="M20 6 9 17l-5-5"/>';
  var I_DETECT = '<path d="m12 3 1.9 4.6L18 9l-4.1 1.4L12 15l-1.9-4.6L6 9l4.1-1.4zM19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9z"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  CK.registerTool('classical', function (root, ctx) {
    var ui = CK.ui, el = CK.el, current = 'caesar';

    root.appendChild(ui.head('Classical Ciphers', LIST.length + ' ciphers'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_SCROLL);
    strip.acts.appendChild(ui.iconBtn(I_DETECT, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(I_CHECK, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(I_SWAP, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var keyInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off' });
    var numInput = el('input', { class: 'inp sm', type: 'number', value: '3' });
    var keyField = ui.field('Key', keyInput);
    var numField = ui.field('Shift', numInput);

    var groups = GROUPS.map(function (g) { return { label: g, items: LIST.filter(function (c) { return c.group === g; }).map(function (c) { return { id: c.id, label: c.label, title: c.desc }; }) }; });
    var pk = ui.picker(groups, select);
    pk.el.classList.add('stacked');

    // Left column: cipher picker. Right column: extra input (content hugging the left).
    var grid = el('div', { class: 'cfg-grid split-73' });
    var colL = el('div', { class: 'col' });
    var colR = el('div', { class: 'col', style: 'align-items:flex-start;' });
    keyInput.style.width = '180px';
    colL.appendChild(pk.el);
    colR.appendChild(keyField); colR.appendChild(numField);
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: I_SCROLL, placeholder: 'Plaintext to encipher, or ciphertext to decipher...', primaries: [{ label: 'Encipher', cls: 'enc', onClick: doEncrypt }, { label: 'Decipher', cls: 'dec', onClick: doDecrypt }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'input.txt' });
    var outP = ui.textPanel({ title: 'OUTPUT', icon: I_LOCK, placeholder: 'Result appears here...', actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'output.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearVerify() { outP.ta.classList.remove('verify-match', 'verify-fail'); inP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearVerify);
    outP.ta.addEventListener('input', clearVerify);

    function params() { return { key: keyInput.value, num: parseInt(numInput.value, 10) || 0 }; }
    function select(id) {
      var c = get(id); if (!c) return; current = id; pk.setActive(id); ui.setSel(strip, c.label, c.badge, c.desc);
      keyField.style.display = c.key ? '' : 'none';
      if (c.key) { keyField.querySelector('label').textContent = c.key; keyInput.placeholder = c.keyPh || ''; }
      numField.style.display = c.num ? '' : 'none';
      if (c.num) { numField.querySelector('label').textContent = c.num; if (c.numDef != null && !numInput.dataset.touched) numInput.value = c.numDef; }
    }
    numInput.addEventListener('input', function () { numInput.dataset.touched = '1'; });
    function doEncrypt() { try { var c = get(current); if (!inP.ta.value) throw new Error('Input is empty'); outP.ta.value = c.enc(inP.ta.value, params()); clearVerify(); ctx.toast(c.label + ' enciphered', 'success'); } catch (e) { ctx.toast(e.message, 'error'); } }
    function doDecrypt() { try { var c = get(current); if (!inP.ta.value) throw new Error('Input is empty'); outP.ta.value = c.dec(inP.ta.value, params()); clearVerify(); ctx.toast(c.label + ' deciphered', 'success'); } catch (e) { ctx.toast(e.message, 'error'); } }
    function doSwap() { inP.ta.value = outP.ta.value; outP.ta.value = ''; clearVerify(); ctx.toast('Output moved to input', 'success'); }
    function doVerify() {
      clearVerify();
      var c = get(current), a = inP.ta.value, b = outP.ta.value;
      if (!a || !b) { ctx.toast('Both panels need content', 'warn'); return; }
      var p = params();
      function tryE(src) { try { return c.enc(src, p); } catch (e) { return null; } }
      function tryD(src) { try { return c.dec(src, p); } catch (e) { return null; } }
      var match = (tryE(a) === b) || (tryD(a) === b) || (tryE(b) === a) || (tryD(b) === a);
      CK.flashVerify(match, inP.ta, outP.ta);
      ctx.toast(match ? 'Match: input and output are a valid pair' : 'No match', match ? 'success' : 'error');
    }
    function doDetect() {
      var s = inP.ta.value.trim();
      if (!s) { ctx.toast('Enter data in the input first', 'warn'); return; }
      var clean = s.replace(/\s/g, ''), id = null;
      if (/^[.\-\/\s]+$/.test(s) && /[.\-]/.test(s)) id = 'morse';
      else if (/^[ab\s]+$/i.test(s) && clean.length >= 5) id = 'bacon';
      else if (/^[0-9a-fA-F\s]+$/.test(s) && /[a-fA-F]/.test(s) && clean.length % 2 === 0) id = 'xorkey';
      else if (/^[1-5\s]+$/.test(s) && clean.length % 2 === 0) id = 'polybius';
      else if (/^[\d\s\/]+$/.test(s) && /\d/.test(s)) id = 'a1z26';
      if (id) { select(id); ctx.toast('Guessed cipher: ' + get(id).label + ' (best-effort)', 'success'); }
      else ctx.toast('Could not detect a cipher (best-effort)', 'warn');
    }
    function doShare() { var st = { c: current, k: keyInput.value, n: numInput.value, in: inP.ta.value, out: outP.ta.value }; CK.copy(location.href.split('#')[0] + '#tool=classical&s=' + b64uEnc(JSON.stringify(st))); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; keyInput.value = ''; numInput.value = '3'; delete numInput.dataset.touched; clearVerify(); select('caesar'); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); if (st.c) current = st.c; if (st.k != null) keyInput.value = st.k; if (st.n != null) { numInput.value = st.n; numInput.dataset.touched = '1'; } if (st.in != null) inP.ta.value = st.in; if (st.out != null) outP.ta.value = st.out; } catch (e) { } }
    select(current);
  });
})();

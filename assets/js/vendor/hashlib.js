/*
   hashlib.js - pure-JS hash algorithms not provided by Web Crypto.
   Self-authored, offline. Exposes window.HashLib: md5, sha3, keccak, crc32.
   Web Crypto covers SHA-1/256/384/512; this fills MD5, SHA-3/Keccak, CRC32.
*/
window.HashLib = (function () {
  'use strict';

  function toHex(bytes) { var s = ''; for (var i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0'); return s; }

  /* MD5 (RFC 1321) on a Uint8Array, returns hex */
  var MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  var MD5_K = (function () { var k = []; for (var i = 0; i < 64; i++) k[i] = (Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296)) | 0; return k; })();
  function md5(bytes) {
    function add(a, b) { return (a + b) | 0; }
    function rol(n, c) { return (n << c) | (n >>> (32 - c)); }
    var len = bytes.length, padLen = (((len + 8) >> 6) + 1) << 6;
    var msg = new Uint8Array(padLen); msg.set(bytes); msg[len] = 0x80;
    var bits = len * 8;
    msg[padLen - 8] = bits & 0xff; msg[padLen - 7] = (bits >>> 8) & 0xff; msg[padLen - 6] = (bits >>> 16) & 0xff; msg[padLen - 5] = (bits >>> 24) & 0xff;
    var hi = Math.floor(len / 536870912); msg[padLen - 4] = hi & 0xff; msg[padLen - 3] = (hi >>> 8) & 0xff; msg[padLen - 2] = (hi >>> 16) & 0xff; msg[padLen - 1] = (hi >>> 24) & 0xff;
    var a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    for (var off = 0; off < padLen; off += 64) {
      var M = []; for (var j = 0; j < 16; j++) M[j] = msg[off + j * 4] | (msg[off + j * 4 + 1] << 8) | (msg[off + j * 4 + 2] << 16) | (msg[off + j * 4 + 3] << 24);
      var A = a0, B = b0, C = c0, D = d0;
      for (var i = 0; i < 64; i++) {
        var F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; }
        else { F = C ^ (B | ~D); g = (7 * i) & 15; }
        F = add(add(add(F, A), MD5_K[i]), M[g]);
        A = D; D = C; C = B; B = add(B, rol(F, MD5_S[i]));
      }
      a0 = add(a0, A); b0 = add(b0, B); c0 = add(c0, C); d0 = add(d0, D);
    }
    function h(n) { var s = ''; for (var i = 0; i < 4; i++) s += ((n >>> (i * 8)) & 0xff).toString(16).padStart(2, '0'); return s; }
    return h(a0) + h(b0) + h(c0) + h(d0);
  }

  /* Keccak-f[1600] sponge (BigInt lanes) - powers SHA-3 and Keccak */
  var MASK = (1n << 64n) - 1n;
  var RC = [0x1n, 0x8082n, 0x800000000000808An, 0x8000000080008000n, 0x808Bn, 0x80000001n, 0x8000000080008081n, 0x8000000000008009n, 0x8An, 0x88n, 0x80008009n, 0x8000000An, 0x8000808Bn, 0x800000000000008Bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 0x800An, 0x800000008000000An, 0x8000000080008081n, 0x8000000000008080n, 0x80000001n, 0x8000000080008008n];
  var ROFF = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];
  function rotl(x, n) { n = BigInt(n); return ((x << n) | (x >> (64n - n))) & MASK; }
  function keccakF(A) {
    for (var round = 0; round < 24; round++) {
      var C = [], x, y;
      for (x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
      var D = [];
      for (x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
      for (x = 0; x < 5; x++) for (y = 0; y < 5; y++) A[x + 5 * y] = A[x + 5 * y] ^ D[x];
      var B = [];
      for (x = 0; x < 5; x++) for (y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(A[x + 5 * y], ROFF[x][y]);
      for (x = 0; x < 5; x++) for (y = 0; y < 5; y++) A[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y] & MASK) & B[((x + 2) % 5) + 5 * y]);
      A[0] = A[0] ^ RC[round];
    }
  }
  function sponge(rateBytes, padByte, outLen, input) {
    var A = []; for (var i = 0; i < 25; i++) A.push(0n);
    var p = 0, len = input.length, j;
    while (p + rateBytes <= len) {
      for (j = 0; j < rateBytes; j++) A[j >> 3] = A[j >> 3] ^ (BigInt(input[p + j]) << BigInt(8 * (j % 8)));
      keccakF(A); p += rateBytes;
    }
    var last = new Uint8Array(rateBytes), rem = len - p;
    for (j = 0; j < rem; j++) last[j] = input[p + j];
    last[rem] ^= padByte; last[rateBytes - 1] ^= 0x80;
    for (j = 0; j < rateBytes; j++) A[j >> 3] = A[j >> 3] ^ (BigInt(last[j]) << BigInt(8 * (j % 8)));
    keccakF(A);
    var out = new Uint8Array(outLen), got = 0;
    while (got < outLen) {
      for (j = 0; j < rateBytes && got < outLen; j++) out[got++] = Number((A[j >> 3] >> BigInt(8 * (j % 8))) & 0xffn);
      if (got < outLen) keccakF(A);
    }
    return out;
  }
  function sha3(bits, bytes) { return toHex(sponge(200 - 2 * (bits / 8), 0x06, bits / 8, bytes)); }
  function keccak(bits, bytes) { return toHex(sponge(200 - 2 * (bits / 8), 0x01, bits / 8, bytes)); }

  /* RIPEMD-160 (on a Uint8Array, returns hex) */
  function ripemd160(bytes) {
    function rol(x, n) { return (x << n) | (x >>> (32 - n)); }
    var zl = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
    var zr = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
    var sl = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
    var sr = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];
    var hl = [0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
    var hr = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0];
    function f(j, x, y, z) { return j < 16 ? (x ^ y ^ z) : j < 32 ? ((x & y) | (~x & z)) : j < 48 ? ((x | ~y) ^ z) : j < 64 ? ((x & z) | (y & ~z)) : (x ^ (y | ~z)); }
    var len = bytes.length, padLen = (((len + 8) >> 6) + 1) << 6;
    var m = new Uint8Array(padLen); m.set(bytes); m[len] = 0x80;
    var bits = len * 8; m[padLen - 8] = bits & 0xff; m[padLen - 7] = (bits >>> 8) & 0xff; m[padLen - 6] = (bits >>> 16) & 0xff; m[padLen - 5] = (bits >>> 24) & 0xff;
    var hiB = Math.floor(len / 536870912); m[padLen - 4] = hiB & 0xff;
    var h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    for (var off = 0; off < padLen; off += 64) {
      var X = []; for (var i = 0; i < 16; i++) X[i] = m[off + i * 4] | (m[off + i * 4 + 1] << 8) | (m[off + i * 4 + 2] << 16) | (m[off + i * 4 + 3] << 24);
      var al = h0, bl = h1, cl = h2, dl = h3, el2 = h4, ar = h0, br = h1, cr = h2, dr = h3, er = h4, t;
      for (var j = 0; j < 80; j++) {
        t = (rol((al + f(j, bl, cl, dl) + X[zl[j]] + hl[(j / 16) | 0]) | 0, sl[j]) + el2) | 0;
        al = el2; el2 = dl; dl = rol(cl, 10); cl = bl; bl = t;
        t = (rol((ar + f(79 - j, br, cr, dr) + X[zr[j]] + hr[(j / 16) | 0]) | 0, sr[j]) + er) | 0;
        ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t;
      }
      t = (h1 + cl + dr) | 0; h1 = (h2 + dl + er) | 0; h2 = (h3 + el2 + ar) | 0; h3 = (h4 + al + br) | 0; h4 = (h0 + bl + cr) | 0; h0 = t;
    }
    function le(n) { var s = ''; for (var i = 0; i < 4; i++) s += ((n >>> (i * 8)) & 0xff).toString(16).padStart(2, '0'); return s; }
    return le(h0) + le(h1) + le(h2) + le(h3) + le(h4);
  }

  /* CRC32 */
  var CRCT = (function () { var t = []; for (var n = 0; n < 256; n++) { var c = n; for (var k = 0; k < 8; k++) c = c & 1 ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c >>> 0; } return t; })();
  function crc32(bytes) { var c = 0xFFFFFFFF; for (var i = 0; i < bytes.length; i++) c = CRCT[(c ^ bytes[i]) & 0xff] ^ (c >>> 8); return ((c ^ 0xFFFFFFFF) >>> 0).toString(16).padStart(8, '0'); }

  return { md5: md5, sha3: sha3, keccak: keccak, crc32: crc32, ripemd160: ripemd160, toHex: toHex };
})();

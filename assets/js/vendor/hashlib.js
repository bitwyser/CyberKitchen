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

  /* CRC32 */
  var CRCT = (function () { var t = []; for (var n = 0; n < 256; n++) { var c = n; for (var k = 0; k < 8; k++) c = c & 1 ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c >>> 0; } return t; })();
  function crc32(bytes) { var c = 0xFFFFFFFF; for (var i = 0; i < bytes.length; i++) c = CRCT[(c ^ bytes[i]) & 0xff] ^ (c >>> 8); return ((c ^ 0xFFFFFFFF) >>> 0).toString(16).padStart(8, '0'); }

  return { md5: md5, sha3: sha3, keccak: keccak, crc32: crc32, toHex: toHex };
})();

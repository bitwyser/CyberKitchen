/*
   x509.js - X.509 / Certificate decoder
   Parse a PEM (or bare Base64) certificate: version, serial, signature
   algorithm, issuer / subject distinguished names, validity, public key
   algorithm and size, common extensions (SAN, basic constraints, key usage),
   plus SHA-1 / SHA-256 fingerprints. Self-contained ASN.1 DER parser. Offline.
*/
(function () {
  'use strict';
  var DEC = new TextDecoder();

  function b64ToBytes(s) { s = s.trim().replace(/\s/g, ''); var bin = atob(s), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  function ascii(b) { return DEC.decode(b); }
  function colonHex(b) { var s = []; for (var i = 0; i < b.length; i++) s.push(b[i].toString(16).padStart(2, '0')); return s.join(':'); }

  /* ---- minimal DER parser ----
     Returns a node: { tag, tagNum, cls, constructed, start, contentStart, contentEnd, children? } */
  function parseTLV(b, off) {
    var start = off, tag = b[off++];
    if ((tag & 0x1f) === 0x1f) { while (b[off] & 0x80) off++; off++; } // high-tag-number form
    var lenByte = b[off++], len;
    if (lenByte < 0x80) len = lenByte;
    else { var n = lenByte & 0x7f; len = 0; for (var i = 0; i < n; i++) len = len * 256 + b[off++]; }
    var contentStart = off, contentEnd = off + len, constructed = (tag & 0x20) !== 0;
    var node = { tag: tag, tagNum: tag & 0x1f, cls: (tag >> 6) & 3, constructed: constructed, start: start, contentStart: contentStart, contentEnd: contentEnd };
    if (constructed) { node.children = []; var p = contentStart; while (p < contentEnd) { var c = parseTLV(b, p); node.children.push(c); p = c.contentEnd; } }
    return node;
  }
  function content(b, node) { return b.subarray(node.contentStart, node.contentEnd); }

  function oidToString(bytes) {
    if (!bytes.length) return '';
    var first = bytes[0], s = Math.floor(first / 40) + '.' + (first % 40), val = 0;
    for (var i = 1; i < bytes.length; i++) { val = val * 128 + (bytes[i] & 0x7f); if (!(bytes[i] & 0x80)) { s += '.' + val; val = 0; } }
    return s;
  }

  var OIDS = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber', '2.5.4.4': 'SN', '2.5.4.42': 'GN', '2.5.4.9': 'STREET', '2.5.4.17': 'postalCode', '2.5.4.15': 'businessCategory', '1.2.840.113549.1.9.1': 'emailAddress', '0.9.2342.19200300.100.1.25': 'DC',
    '1.2.840.113549.1.1.1': 'RSA', '1.2.840.10045.2.1': 'EC', '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption', '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption', '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption', '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption', '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256', '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384', '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
    '1.2.840.10045.3.1.7': 'P-256 (prime256v1)', '1.3.132.0.34': 'P-384 (secp384r1)', '1.3.132.0.35': 'P-521 (secp521r1)',
    '2.5.29.17': 'subjectAltName', '2.5.29.19': 'basicConstraints', '2.5.29.15': 'keyUsage', '2.5.29.37': 'extKeyUsage', '2.5.29.14': 'subjectKeyIdentifier', '2.5.29.35': 'authorityKeyIdentifier', '2.5.29.31': 'cRLDistributionPoints', '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess', '2.5.29.32': 'certificatePolicies',
    '1.3.6.1.5.5.7.3.1': 'serverAuth', '1.3.6.1.5.5.7.3.2': 'clientAuth', '1.3.6.1.5.5.7.3.3': 'codeSigning', '1.3.6.1.5.5.7.3.4': 'emailProtection'
  };
  function oidName(b, node) { var s = oidToString(content(b, node)); return OIDS[s] || s; }

  var KU = ['Digital Signature', 'Non Repudiation', 'Key Encipherment', 'Data Encipherment', 'Key Agreement', 'Certificate Sign', 'CRL Sign', 'Encipher Only', 'Decipher Only'];

  function parseName(b, node) {
    if (!node.children) return '';
    var parts = [];
    node.children.forEach(function (rdn) { // SET
      (rdn.children || []).forEach(function (atv) { // SEQUENCE {OID, value}
        var t = oidName(b, atv.children[0]), v = ascii(content(b, atv.children[1]));
        parts.push(t + '=' + v);
      });
    });
    return parts.join(', ');
  }
  function parseTime(b, node) {
    var s = ascii(content(b, node)), m;
    if (node.tag === 0x17) { m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/.exec(s); if (!m) return s; var yy = +m[1], year = yy < 50 ? 2000 + yy : 1900 + yy; return year + '-' + m[2] + '-' + m[3] + 'T' + m[4] + ':' + m[5] + ':' + (m[6] || '00') + 'Z'; }
    m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/.exec(s); if (!m) return s; return m[1] + '-' + m[2] + '-' + m[3] + 'T' + m[4] + ':' + m[5] + ':' + (m[6] || '00') + 'Z';
  }
  function intBits(b, node) { var c = content(b, node), i = 0; while (i < c.length && c[i] === 0) i++; if (i >= c.length) return 0; var first = c[i], bl = 0; while (first) { bl++; first >>= 1; } return (c.length - i - 1) * 8 + bl; }
  function intNum(b, node) { var c = content(b, node), n = 0; for (var i = 0; i < c.length; i++) n = n * 256 + c[i]; return n; }

  function parseSPKI(b, spki) {
    var algSeq = spki.children[0], algOidNode = algSeq.children[0];
    var algName = oidName(b, algOidNode), oid = oidToString(content(b, algOidNode)), detail = algName;
    if (oid === '1.2.840.113549.1.1.1') { // RSA
      var bit = spki.children[1], inner = parseTLV(b, bit.contentStart + 1); // skip unused-bits byte
      if (inner.children && inner.children.length >= 2) { detail = 'RSA ' + intBits(b, inner.children[0]) + '-bit (exponent ' + intNum(b, inner.children[1]) + ')'; }
      else detail = 'RSA';
    } else if (oid === '1.2.840.10045.2.1') { // EC
      var curve = algSeq.children[1] ? oidName(b, algSeq.children[1]) : 'unknown curve';
      detail = 'EC (' + curve + ')';
    } else if (oid === '1.3.101.112') detail = 'Ed25519';
    else if (oid === '1.3.101.113') detail = 'Ed448';
    return detail;
  }

  function parseSAN(b, seq) {
    if (!seq.children) return '';
    return seq.children.map(function (gn) {
      var v = ascii(content(b, gn));
      if (gn.tagNum === 2) return 'DNS:' + v;
      if (gn.tagNum === 1) return 'email:' + v;
      if (gn.tagNum === 6) return 'URI:' + v;
      if (gn.tagNum === 7) { var c = content(b, gn); return 'IP:' + Array.prototype.join.call(c, '.'); }
      return 'name:' + v;
    }).join(', ');
  }

  function decodeCert(bytes) {
    var cert = parseTLV(bytes, 0), tbs = cert.children[0], ch = tbs.children, idx = 0, r = {};
    if (ch[0].cls === 2 && ch[0].tagNum === 0) { r.version = intNum(bytes, ch[0].children[0]) + 1; idx = 1; } else r.version = 1;
    r.serial = colonHex(content(bytes, ch[idx++]));
    r.sigAlgo = oidName(bytes, ch[idx].children[0]); idx++;
    r.issuer = parseName(bytes, ch[idx++]);
    var val = ch[idx++]; r.notBefore = parseTime(bytes, val.children[0]); r.notAfter = parseTime(bytes, val.children[1]);
    r.subject = parseName(bytes, ch[idx++]);
    r.pubkey = parseSPKI(bytes, ch[idx++]);
    r.ext = {};
    for (; idx < ch.length; idx++) {
      if (ch[idx].cls === 2 && ch[idx].tagNum === 3) {
        var extSeq = ch[idx].children[0];
        (extSeq.children || []).forEach(function (ext) {
          var name = oidName(bytes, ext.children[0]);
          var valNode = ext.children[ext.children.length - 1]; // OCTET STRING
          var inner; try { inner = parseTLV(bytes, valNode.contentStart); } catch (e) { inner = null; }
          if (name === 'subjectAltName' && inner) r.ext.san = parseSAN(bytes, inner);
          else if (name === 'basicConstraints' && inner) { var ca = inner.children && inner.children[0] && inner.children[0].tag === 0x01 ? (content(bytes, inner.children[0])[0] ? 'TRUE' : 'FALSE') : 'FALSE'; r.ext.basic = 'CA:' + ca; }
          else if (name === 'keyUsage' && inner) { var kb = content(bytes, inner), bitsByte = kb[1] || 0, used = []; for (var i = 0; i < 8; i++) if (bitsByte & (0x80 >> i)) used.push(KU[i]); r.ext.keyUsage = used.join(', '); }
          else if (name === 'extKeyUsage' && inner && inner.children) r.ext.eku = inner.children.map(function (o2) { return oidName(bytes, o2); }).join(', ');
        });
      }
    }
    return r;
  }

  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return DEC.decode(a); }

  var I_CERT = '<rect x="4" y="3" width="16" height="13" rx="2"/><circle cx="12" cy="8" r="2.5"/><path d="M9.5 14l-1 6 3.5-2 3.5 2-1-6"/>';
  var I_FILE = '<path d="M14 3v5h5M6 3h9l5 5v13H6z"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('x509', function (root, ctx) {
    var ui = CK.ui;

    root.appendChild(ui.head('X.509 Certificate Decoder', 'ASN.1'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_CERT);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);
    ui.setSel(strip, 'X.509 Certificate', 'PEM', 'Paste a PEM certificate (-----BEGIN CERTIFICATE-----) to read its fields and fingerprints. Parsed locally, nothing leaves your browser.');
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'CERTIFICATE (PEM)', icon: I_FILE, placeholder: '-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----', primaries: [{ label: 'Decode', cls: 'enc', onClick: doDecode }], actions: ['copy', 'paste', 'clear'] });
    var outP = ui.textPanel({ title: 'DECODED', icon: I_CERT, placeholder: 'Certificate fields appear here...', readonly: true, actions: ['copy', 'download'], downloadName: 'certificate.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function certBytes() {
      var s = inP.ta.value.trim();
      if (!s) throw new Error('Paste a certificate first');
      var m = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(s);
      var body = m ? m[1] : s;
      var bytes = b64ToBytes(body.replace(/\s+/g, ''));
      if (!bytes.length || bytes[0] !== 0x30) throw new Error('Not a DER SEQUENCE (is this a valid certificate?)');
      return bytes;
    }
    function pad(k) { return (k + ':').padEnd(20, ' '); }
    function doDecode() {
      var bytes, r;
      try { bytes = certBytes(); r = decodeCert(bytes); } catch (e) { ctx.toast('Parse failed: ' + e.message, 'error'); return; }
      var lines = [];
      lines.push(pad('Version') + 'v' + r.version);
      lines.push(pad('Serial number') + r.serial);
      lines.push(pad('Signature algorithm') + r.sigAlgo);
      lines.push('');
      lines.push(pad('Issuer') + r.issuer);
      lines.push(pad('Subject') + r.subject);
      lines.push('');
      var now = Date.now(), expired = Date.parse(r.notAfter) < now, notYet = Date.parse(r.notBefore) > now;
      lines.push(pad('Not before') + r.notBefore + (notYet ? '  (not yet valid)' : ''));
      lines.push(pad('Not after') + r.notAfter + (expired ? '  (EXPIRED)' : '  (valid)'));
      lines.push('');
      lines.push(pad('Public key') + r.pubkey);
      if (r.ext.san) lines.push(pad('Subject alt names') + r.ext.san);
      if (r.ext.basic) lines.push(pad('Basic constraints') + r.ext.basic);
      if (r.ext.keyUsage) lines.push(pad('Key usage') + r.ext.keyUsage);
      if (r.ext.eku) lines.push(pad('Extended key usage') + r.ext.eku);
      outP.ta.value = lines.join('\n');
      ctx.toast('Certificate decoded', 'success');
      // Fingerprints (async)
      Promise.all([crypto.subtle.digest('SHA-1', bytes), crypto.subtle.digest('SHA-256', bytes)]).then(function (d) {
        outP.ta.value += '\n\nFingerprints:\n' + pad('  SHA-1') + colonHex(new Uint8Array(d[0])) + '\n' + pad('  SHA-256') + colonHex(new Uint8Array(d[1]));
      }).catch(function () { });
    }
    function doShare() { CK.copy(location.href.split('#')[0] + '#tool=x509&s=' + b64uEnc(JSON.stringify({ in: inP.ta.value }))); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); inP.ta.value = st.in || ''; if (inP.ta.value) doDecode(); } catch (e) { } }
  });
})();

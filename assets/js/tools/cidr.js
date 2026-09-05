/*
   cidr.js - CIDR / Subnet Calculator (IPv4)
   Given an address and prefix, compute network, broadcast, host range,
   netmask, wildcard, host counts, class and type, plus optional subnetting
   into smaller blocks. Pure math, no dependencies.
*/
(function () {
  'use strict';

  function parseIp(s) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim());
    if (!m) return null;
    var o = [+m[1], +m[2], +m[3], +m[4]];
    for (var i = 0; i < 4; i++) if (o[i] > 255) return null;
    return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
  }
  function ipStr(n) { n = n >>> 0; return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); }
  function maskFromPrefix(p) { return p === 0 ? 0 : (0xFFFFFFFF << (32 - p)) >>> 0; }
  function prefixFromMask(n) { n = n >>> 0; var c = 0; for (var i = 31; i >= 0; i--) { if (n & (1 << i)) c++; else break; } return c; }
  function isContiguousMask(n) { n = n >>> 0; var seenZero = false; for (var i = 31; i >= 0; i--) { if (n & (1 << i)) { if (seenZero) return false; } else seenZero = true; } return true; }

  function classify(ip) {
    var a = (ip >>> 24) & 255;
    if (a < 128) return 'A'; if (a < 192) return 'B'; if (a < 224) return 'C'; if (a < 240) return 'D (multicast)'; return 'E (reserved)';
  }
  function ipType(ip) {
    var a = (ip >>> 24) & 255, b = (ip >>> 16) & 255;
    if (a === 10) return 'Private (RFC 1918)';
    if (a === 172 && b >= 16 && b <= 31) return 'Private (RFC 1918)';
    if (a === 192 && b === 168) return 'Private (RFC 1918)';
    if (a === 127) return 'Loopback';
    if (a === 169 && b === 254) return 'Link-local (APIPA)';
    if (a === 100 && b >= 64 && b <= 127) return 'Carrier-grade NAT (RFC 6598)';
    if (a >= 224) return 'Multicast / reserved';
    if (a === 0) return 'This network';
    return 'Public';
  }

  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  var I_NET = '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-2h12v2"/>';
  var I_OUT = '<path d="M4 7h16M4 12h16M4 17h10"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('cidr', function (root, ctx) {
    var ui = CK.ui, el = CK.el;

    root.appendChild(ui.head('CIDR / Subnet Calculator', 'IPv4'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_NET);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col' });
    var colR = el('div', { class: 'col' });

    // Prefix length: slim slider + number, mirrored from the CIDR in the input
    var pfxRange = el('input', { type: 'range', min: '0', max: '32', value: '24' });
    var pfxNum = el('input', { class: 'inp sm', type: 'number', min: '0', max: '32', value: '24' });
    var pfxRow = el('div', { class: 'length-row' }); pfxRow.appendChild(pfxRange); pfxRow.appendChild(pfxNum);
    colL.appendChild(ui.field('Prefix length', pfxRow));

    // Optional subnetting into a longer prefix
    var subInput = el('input', { class: 'inp sm', type: 'number', min: '0', max: '32', placeholder: 'e.g. 26' }); subInput.style.width = '100px';
    colR.appendChild(ui.field('Subnet into (prefix)', subInput));

    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'IP ADDRESS / CIDR', icon: I_NET, placeholder: '192.168.1.0/24  or  10.0.0.5', primaries: [{ label: 'Calculate', cls: 'enc', onClick: run }], actions: ['copy', 'paste', 'clear'], onInput: run });
    var outP = ui.textPanel({ title: 'SUBNET DETAILS', icon: I_OUT, placeholder: 'Network details appear here...', readonly: true, actions: ['copy', 'download'], downloadName: 'subnet.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function setPrefix(p) { pfxRange.value = p; pfxNum.value = p; }
    pfxRange.addEventListener('input', function () { pfxNum.value = pfxRange.value; run(); });
    pfxNum.addEventListener('input', function () { pfxRange.value = pfxNum.value; run(); });
    subInput.addEventListener('input', run);

    // Parse the input into { ip, prefix }. Accepts ip/prefix, ip netmask, or ip (uses slider).
    function parseInput() {
      var s = inP.ta.value.trim();
      if (!s) return null;
      var parts = s.split(/[\s/]+/);
      var ip = parseIp(parts[0]);
      if (ip == null) return null;
      var prefix = +pfxNum.value;
      if (parts[1] != null && parts[1] !== '') {
        if (/^\d+$/.test(parts[1])) { var p = +parts[1]; if (p >= 0 && p <= 32) prefix = p; else return null; }
        else { var mask = parseIp(parts[1]); if (mask == null || !isContiguousMask(mask)) return null; prefix = prefixFromMask(mask); }
        setPrefix(prefix);
      }
      return { ip: ip, prefix: prefix };
    }
    function pad(k) { return (k + ':').padEnd(20, ' '); }

    function run() {
      var pi = parseInput();
      if (!pi) { outP.ta.value = ''; ui.setSel(strip, 'CIDR / Subnet', 'IPv4', 'Enter an IPv4 address, optionally with a prefix or netmask.'); return; }
      var ip = pi.ip, p = pi.prefix, mask = maskFromPrefix(p), wild = (~mask) >>> 0;
      var network = (ip & mask) >>> 0, broadcast = (network | wild) >>> 0, hostBits = 32 - p;
      var total = Math.pow(2, hostBits), first, last, usable;
      if (p === 32) { first = last = network; usable = 1; }
      else if (p === 31) { first = network; last = broadcast; usable = 2; }
      else { first = (network + 1) >>> 0; last = (broadcast - 1) >>> 0; usable = total - 2; }

      ui.setSel(strip, ipStr(network) + '/' + p, ipStr(mask), usable.toLocaleString() + ' usable hosts · ' + total.toLocaleString() + ' addresses · ' + classify(ip) + ' · ' + ipType(ip));

      var lines = [];
      lines.push(pad('CIDR notation') + ipStr(network) + '/' + p);
      lines.push(pad('Netmask') + ipStr(mask));
      lines.push(pad('Wildcard mask') + ipStr(wild));
      lines.push('');
      lines.push(pad('Network address') + ipStr(network));
      lines.push(pad('Broadcast address') + ipStr(broadcast));
      lines.push(pad('Usable host range') + (usable > 0 ? ipStr(first) + ' - ' + ipStr(last) : 'none'));
      lines.push('');
      lines.push(pad('Total addresses') + total.toLocaleString());
      lines.push(pad('Usable hosts') + usable.toLocaleString());
      lines.push(pad('Host bits') + hostBits);
      lines.push(pad('IP class') + classify(ip));
      lines.push(pad('Type') + ipType(ip));
      lines.push('');
      lines.push(pad('Network (integer)') + network);
      lines.push(pad('Network (hex)') + '0x' + network.toString(16).toUpperCase().padStart(8, '0'));

      // Optional subnetting
      var np = subInput.value === '' ? null : +subInput.value;
      if (np != null) {
        if (np < p || np > 32) lines.push('\nSubnet into /' + np + ': prefix must be between ' + p + ' and 32');
        else {
          var count = Math.pow(2, np - p), step = Math.pow(2, 32 - np), limit = Math.min(count, 128);
          lines.push('\nSubnets (/' + np + ', ' + count.toLocaleString() + ' total' + (count > limit ? ', first ' + limit + ' shown' : '') + '):');
          for (var i = 0; i < limit; i++) {
            var sn = (network + i * step) >>> 0, snb = (sn | ((~maskFromPrefix(np)) >>> 0)) >>> 0;
            var range = np >= 31 ? ipStr(sn) + ' - ' + ipStr(snb) : ipStr((sn + 1) >>> 0) + ' - ' + ipStr((snb - 1) >>> 0);
            lines.push('  ' + (ipStr(sn) + '/' + np).padEnd(19, ' ') + 'hosts ' + range);
          }
        }
      }
      outP.ta.value = lines.join('\n');
    }
    function doShare() { CK.copy(location.href.split('#')[0] + '#tool=cidr&s=' + b64uEnc(JSON.stringify({ in: inP.ta.value, p: pfxNum.value, sub: subInput.value }))); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; setPrefix(24); subInput.value = ''; run(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); setPrefix(st.p || 24); subInput.value = st.sub || ''; inP.ta.value = st.in || ''; } catch (e) { } }
    run();
  });
})();

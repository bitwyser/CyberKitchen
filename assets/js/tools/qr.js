/*
   qr.js - QR Code Generator
   Renders a QR code from text or a URL as inline SVG (offline), with error
   correction level, custom colors, and SVG / PNG download. Uses the vendored
   qrcode-generator library (assets/js/vendor/qrcode.min.js).
*/
(function () {
  'use strict';
  if (typeof qrcode !== 'undefined' && qrcode.stringToBytesFuncs && qrcode.stringToBytesFuncs['UTF-8']) {
    qrcode.stringToBytes = qrcode.stringToBytesFuncs['UTF-8']; // encode input as UTF-8
  }

  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  // Build the smallest QR that fits the data at the given level, or null if it does not fit
  function build(text, ecl) {
    for (var t = 1; t <= 40; t++) { try { var qr = qrcode(t, ecl); qr.addData(text); qr.make(); return qr; } catch (e) { } }
    return null;
  }
  function svgFrom(qr, fg, bg, margin) {
    var n = qr.getModuleCount(), size = n + margin * 2, rects = '';
    for (var r = 0; r < n; r++) for (var c = 0; c < n; c++) if (qr.isDark(r, c)) rects += '<rect x="' + (c + margin) + '" y="' + (r + margin) + '" width="1" height="1"/>';
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" shape-rendering="crispEdges" width="100%" height="100%" style="max-width:300px;max-height:300px;">' +
      '<rect width="' + size + '" height="' + size + '" fill="' + bg + '"/><g fill="' + fg + '">' + rects + '</g></svg>';
  }

  var I_QR = '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3M20 14v.01M14 20v.01M20 20v.01M17 17v.01"/>';
  var IC_COPY = '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>';
  var IC_DL = '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>';
  var I_SHUF = '<path d="M18 4l3 3-3 3M21 7H8a4 4 0 0 0-4 4M6 20l-3-3 3-3M3 17h12a4 4 0 0 0 4-4"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';
  var LEVELS = ['L', 'M', 'Q', 'H'];

  CK.registerTool('qr', function (root, ctx) {
    var ui = CK.ui, el = CK.el, iconSvg = CK.iconSvg, ecl = 'M', lastQR = null;

    root.appendChild(ui.head('QR Code Generator', 'offline'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_QR);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col' });
    var colR = el('div', { class: 'col2' });

    // Error correction level buttons
    var eclBtns = {}, eclRow = el('div', { style: 'display:flex; gap:5px; align-items:center; flex-wrap:wrap;' });
    LEVELS.forEach(function (v) { var b = el('button', { class: 'eb', title: 'Level ' + v }); b.textContent = v; b.addEventListener('click', function () { ecl = v; markEcl(); run(); }); eclBtns[v] = b; eclRow.appendChild(b); });
    colL.appendChild(ui.field('Error correction', eclRow));

    var fgInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', value: '#000000' });
    var bgInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', value: '#ffffff' });
    fgInput.addEventListener('input', run); bgInput.addEventListener('input', run);
    colR.appendChild(ui.field('Foreground', fgInput)); colR.appendChild(ui.field('Background', bgInput));
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'TEXT / URL', icon: I_QR, placeholder: 'https://example.com  or any text...', primaries: [{ label: 'Generate', cls: 'enc', onClick: run }], actions: ['copy', 'paste', 'clear'], onInput: run });
    io.appendChild(inP.panel);

    // Custom output panel holding the rendered SVG
    var outPanel = el('div', { class: 'panel io-p' });
    var hdr = el('div', { class: 'panel-hdr', html: iconSvg(I_QR, 12) + ' ' });
    hdr.appendChild(document.createTextNode('QR CODE'));
    var fill = el('span', { class: 'fill' }); var tb = el('span', { class: 'tb' });
    var copyBtn = ui.iconBtn(IC_COPY, 'Copy SVG', function () { if (lastSvg) CK.copy(lastSvg); else ctx.toast('Nothing to copy', 'warn'); });
    var dlSvg = ui.iconBtn(IC_DL, 'Download SVG', function () { if (lastSvg) CK.download(lastSvg, 'qrcode.svg', 'image/svg+xml'); else ctx.toast('Nothing to save', 'warn'); });
    var dlPng = ui.iconBtn(IC_DL, 'Download PNG', downloadPng);
    tb.appendChild(copyBtn); tb.appendChild(dlSvg); tb.appendChild(dlPng);
    hdr.appendChild(fill); hdr.appendChild(tb);
    var box = el('div', { class: 'qr-box' });
    outPanel.appendChild(hdr); outPanel.appendChild(box);
    io.appendChild(outPanel);
    root.appendChild(io);

    var lastSvg = '';
    function markEcl() { LEVELS.forEach(function (v) { eclBtns[v].classList.toggle('active', v === ecl); }); }
    function run() {
      var text = inP.ta.value;
      if (!text) { box.innerHTML = ''; lastQR = null; lastSvg = ''; ui.setSel(strip, 'QR Code Generator', ecl, 'Enter text or a URL to generate a QR code.'); return; }
      var qr = build(text, ecl);
      if (!qr) { box.innerHTML = ''; lastQR = null; lastSvg = ''; ui.setSel(strip, 'Too much data', 'error', 'The text is too long for a QR code at level ' + ecl + '. Try a lower error correction level.'); ctx.toast('Text too long for a QR code', 'error'); return; }
      lastQR = qr;
      lastSvg = svgFrom(qr, fgInput.value || '#000000', bgInput.value || '#ffffff', 4);
      box.innerHTML = lastSvg;
      var n = qr.getModuleCount(), version = (n - 17) / 4;
      ui.setSel(strip, 'QR version ' + version, 'level ' + ecl, n + '×' + n + ' modules · error correction level ' + ecl + ' · ' + text.length + ' characters');
    }
    function downloadPng() {
      if (!lastQR) { ctx.toast('Nothing to save', 'warn'); return; }
      var n = lastQR.getModuleCount(), scale = 8, margin = 4, size = (n + margin * 2) * scale;
      var cv = document.createElement('canvas'); cv.width = cv.height = size; var g = cv.getContext('2d');
      g.fillStyle = bgInput.value || '#ffffff'; g.fillRect(0, 0, size, size); g.fillStyle = fgInput.value || '#000000';
      for (var r = 0; r < n; r++) for (var c = 0; c < n; c++) if (lastQR.isDark(r, c)) g.fillRect((c + margin) * scale, (r + margin) * scale, scale, scale);
      var a = el('a'); a.href = cv.toDataURL('image/png'); a.download = 'qrcode.png'; a.click();
      ctx.toast('PNG download started', 'success');
    }
    function doShare() { CK.copy(location.href.split('#')[0] + '#tool=qr&s=' + b64uEnc(JSON.stringify({ in: inP.ta.value, e: ecl, fg: fgInput.value, bg: bgInput.value }))); }
    function doReset() { inP.ta.value = ''; box.innerHTML = ''; lastQR = null; lastSvg = ''; ecl = 'M'; fgInput.value = '#000000'; bgInput.value = '#ffffff'; markEcl(); run(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); inP.ta.value = st.in || ''; ecl = st.e || 'M'; fgInput.value = st.fg || '#000000'; bgInput.value = st.bg || '#ffffff'; } catch (e) { } }
    markEcl(); run();
  });
})();

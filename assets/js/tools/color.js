/*
   color.js - Color Converter + WCAG contrast checker
   Parse hex / rgb() / hsl() / named colors and show hex, rgb, hsl, hsv and
   cmyk, plus the WCAG contrast ratio against a chosen background with AA/AAA
   pass/fail for normal and large text. Pure JS, no dependencies.
*/
(function () {
  'use strict';

  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }
  function hslToRgb(h, s, l) {
    h = ((h % 360) + 360) % 360; s /= 100; l /= 100;
    var c = (1 - Math.abs(2 * l - 1)) * s, x = c * (1 - Math.abs((h / 60) % 2 - 1)), mm = l - c / 2, r = 0, g = 0, b = 0;
    if (h < 60) { r = c; g = x; } else if (h < 120) { r = x; g = c; } else if (h < 180) { g = c; b = x; }
    else if (h < 240) { g = x; b = c; } else if (h < 300) { r = x; b = c; } else { r = c; b = x; }
    return { r: Math.round((r + mm) * 255), g: Math.round((g + mm) * 255), b: Math.round((b + mm) * 255) };
  }
  function parseColor(s) {
    s = s.trim(); var m;
    if ((m = /^#([0-9a-f]{3})$/i.exec(s))) { var h = m[1]; return { r: parseInt(h[0] + h[0], 16), g: parseInt(h[1] + h[1], 16), b: parseInt(h[2] + h[2], 16), a: 1 }; }
    if ((m = /^#([0-9a-f]{6})$/i.exec(s))) { return { r: parseInt(m[1].slice(0, 2), 16), g: parseInt(m[1].slice(2, 4), 16), b: parseInt(m[1].slice(4, 6), 16), a: 1 }; }
    if ((m = /^#([0-9a-f]{8})$/i.exec(s))) { return { r: parseInt(m[1].slice(0, 2), 16), g: parseInt(m[1].slice(2, 4), 16), b: parseInt(m[1].slice(4, 6), 16), a: parseInt(m[1].slice(6, 8), 16) / 255 }; }
    if ((m = /^rgba?\(([^)]+)\)$/i.exec(s))) { var p = m[1].split(',').map(function (x) { return parseFloat(x); }); if (p.length >= 3) return { r: clamp(p[0], 0, 255) | 0, g: clamp(p[1], 0, 255) | 0, b: clamp(p[2], 0, 255) | 0, a: p[3] != null ? p[3] : 1 }; }
    if ((m = /^hsla?\(([^)]+)\)$/i.exec(s))) { var q = m[1].split(',').map(function (x) { return parseFloat(x); }); if (q.length >= 3) { var rgb = hslToRgb(q[0], q[1], q[2]); rgb.a = q[3] != null ? q[3] : 1; return rgb; } }
    // Named colors: let the browser resolve, guarding against invalid values
    try { var d = document.createElement('span'); d.style.color = ''; d.style.color = s; if (!d.style.color) return null; document.body.appendChild(d); var cs = getComputedStyle(d).color; document.body.removeChild(d); var mm = /rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)/.exec(cs); if (mm) return { r: +mm[1], g: +mm[2], b: +mm[3], a: mm[4] != null ? +mm[4] : 1 }; } catch (e) { }
    return null;
  }
  function toHex(c) { function h(n) { return n.toString(16).padStart(2, '0'); } return '#' + h(c.r) + h(c.g) + h(c.b) + (c.a < 1 ? h(Math.round(c.a * 255)) : ''); }
  function rgbToHsl(c) {
    var r = c.r / 255, g = c.g / 255, b = c.b / 255, max = Math.max(r, g, b), min = Math.min(r, g, b), d = max - min, h = 0, s = 0, l = (max + min) / 2;
    if (d) { s = d / (1 - Math.abs(2 * l - 1)); h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4; h *= 60; if (h < 0) h += 360; }
    return { h: Math.round(h), s: Math.round(s * 100), l: Math.round(l * 100) };
  }
  function rgbToHsv(c) {
    var r = c.r / 255, g = c.g / 255, b = c.b / 255, max = Math.max(r, g, b), min = Math.min(r, g, b), d = max - min, h = 0, s = max ? d / max : 0, v = max;
    if (d) { h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4; h *= 60; if (h < 0) h += 360; }
    return { h: Math.round(h), s: Math.round(s * 100), v: Math.round(v * 100) };
  }
  function rgbToCmyk(c) { var r = c.r / 255, g = c.g / 255, b = c.b / 255, k = 1 - Math.max(r, g, b); if (k === 1) return { c: 0, m: 0, y: 0, k: 100 }; return { c: Math.round((1 - r - k) / (1 - k) * 100), m: Math.round((1 - g - k) / (1 - k) * 100), y: Math.round((1 - b - k) / (1 - k) * 100), k: Math.round(k * 100) }; }
  function luminance(c) { function ch(v) { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); } return 0.2126 * ch(c.r) + 0.7152 * ch(c.g) + 0.0722 * ch(c.b); }
  function contrast(a, b) { var l1 = luminance(a), l2 = luminance(b); return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05); }

  var I_DROP = '<path d="M12 3s6 6.5 6 11a6 6 0 0 1-12 0c0-4.5 6-11 6-11z"/>';
  var I_OUT = '<path d="M4 7h16M4 12h16M4 17h10"/>';
  var I_SHUF = '<path d="M18 4l3 3-3 3M21 7H8a4 4 0 0 0-4 4M6 20l-3-3 3-3M3 17h12a4 4 0 0 0 4-4"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';
  function rndHex() { var n = Math.floor(Math.random() * 0x1000000); return '#' + n.toString(16).padStart(6, '0'); }

  CK.registerTool('color', function (root, ctx) {
    var ui = CK.ui, el = CK.el;

    root.appendChild(ui.head('Color Converter', 'WCAG'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_DROP);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col' });
    var colR = el('div', { class: 'col' });
    var bgInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', value: '#ffffff', placeholder: 'Background color' });
    bgInput.addEventListener('input', run);
    var bgGen = ui.iconBtn(I_SHUF, 'Random background', function () { bgInput.value = rndHex(); run(); });
    var bgWrap = el('div', { style: 'display:flex; gap:5px; align-items:center;' });
    bgInput.style.flex = '1'; bgInput.style.minWidth = '0'; bgWrap.appendChild(bgInput); bgWrap.appendChild(bgGen);
    colL.appendChild(ui.field('Background (for contrast)', bgWrap));
    // Live preview swatch
    var swatch = el('div', { style: 'height:52px; border-radius:9px; border:1px solid var(--cbdr); display:flex; align-items:center; justify-content:center; font-weight:700; font-size:14px;' });
    swatch.textContent = 'Aa  Sample text';
    colR.appendChild(ui.field('Preview', swatch));
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'COLOR', icon: I_DROP, placeholder: '#3b82f6  ·  rgb(59,130,246)  ·  hsl(217,91%,60%)  ·  royalblue', primaries: [{ label: 'Convert', cls: 'enc', onClick: run }], actions: ['copy', 'paste', 'clear'], onInput: run });
    var outP = ui.textPanel({ title: 'FORMATS', icon: I_OUT, placeholder: 'Color formats and contrast appear here...', readonly: true, actions: ['copy', 'download'], downloadName: 'color.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function pad(k) { return (k + ':').padEnd(14, ' '); }
    function grade(ratio) {
      function yn(ok) { return ok ? 'PASS' : 'fail'; }
      return 'AA normal ' + yn(ratio >= 4.5) + ' · AA large ' + yn(ratio >= 3) + ' · AAA normal ' + yn(ratio >= 7) + ' · AAA large ' + yn(ratio >= 4.5);
    }
    function run() {
      var fg = parseColor(inP.ta.value);
      var bg = parseColor(bgInput.value) || { r: 255, g: 255, b: 255, a: 1 };
      if (!fg) { outP.ta.value = ''; ui.setSel(strip, 'Color Converter', 'sRGB', 'Enter a color as hex, rgb(), hsl() or a CSS name.'); swatch.style.background = ''; swatch.style.color = ''; return; }
      var hsl = rgbToHsl(fg), hsv = rgbToHsv(fg), cmyk = rgbToCmyk(fg), ratio = contrast(fg, bg);
      swatch.style.background = 'rgb(' + bg.r + ',' + bg.g + ',' + bg.b + ')';
      swatch.style.color = 'rgb(' + fg.r + ',' + fg.g + ',' + fg.b + ')';
      ui.setSel(strip, toHex(fg), 'contrast ' + ratio.toFixed(2) + ':1', 'rgb(' + fg.r + ', ' + fg.g + ', ' + fg.b + ') · contrast ' + ratio.toFixed(2) + ':1 vs background');
      outP.ta.value = [
        pad('HEX') + toHex(fg),
        pad('RGB') + 'rgb(' + fg.r + ', ' + fg.g + ', ' + fg.b + ')' + (fg.a < 1 ? '  alpha ' + fg.a : ''),
        pad('HSL') + 'hsl(' + hsl.h + ', ' + hsl.s + '%, ' + hsl.l + '%)',
        pad('HSV') + 'hsv(' + hsv.h + ', ' + hsv.s + '%, ' + hsv.v + '%)',
        pad('CMYK') + 'cmyk(' + cmyk.c + '%, ' + cmyk.m + '%, ' + cmyk.y + '%, ' + cmyk.k + '%)',
        pad('Luminance') + luminance(fg).toFixed(4),
        '',
        'Contrast vs ' + toHex(bg) + ': ' + ratio.toFixed(2) + ':1',
        grade(ratio)
      ].join('\n');
    }
    function doShare() { CK.copy(location.href.split('#')[0] + '#tool=color&s=' + b64uEnc(JSON.stringify({ in: inP.ta.value, bg: bgInput.value }))); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; bgInput.value = '#ffffff'; swatch.style.background = ''; swatch.style.color = ''; run(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); inP.ta.value = st.in || ''; bgInput.value = st.bg || '#ffffff'; } catch (e) { } }
    run();
  });
})();

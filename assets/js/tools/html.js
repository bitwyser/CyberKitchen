/*
   html.js - HTML Viewer
   Edit HTML, CSS and JavaScript and see the page rendered live in a sandboxed
   iframe, with captured console output. The frame gets allow-scripts but not
   allow-same-origin, so rendered code cannot reach CyberKitchen or its storage.
   Pure JS, no dependencies.
*/
(function () {
  'use strict';

  // Injected into every rendered page to forward console output and errors to
  // the parent for display. Must never contain a closing script tag.
  var HOOK = '(function(){' +
    'function f(v){try{return typeof v==="object"?JSON.stringify(v):String(v);}catch(e){return String(v);}}' +
    'function s(t,a){try{parent.postMessage({__ck:"console",t:t,m:Array.prototype.map.call(a,f).join(" ")},"*");}catch(e){}}' +
    '["log","info","warn","error","debug"].forEach(function(k){var o=console[k]?console[k].bind(console):function(){};console[k]=function(){s(k,arguments);o.apply(null,arguments);};});' +
    'window.addEventListener("error",function(e){s("error",[String(e.message).replace(/Failed to execute .appendChild. on .Node.: /,"")+(e.lineno?(" (line "+e.lineno+")"):"")]);});' +
    'window.addEventListener("unhandledrejection",function(e){var r=e.reason;s("error",["Uncaught (in promise) "+((r&&r.message)||r)]);});' +
    '})();';

  // Stop user code from closing the wrapping <style> / <script> tag early
  function guard(s, tag) { return String(s).replace(new RegExp('<\\/' + tag, 'gi'), '<\\/' + tag); }
  // JS source as a string literal that is safe inside a <script> element
  function jsString(s) {
    // Escape '<' (60) and the line/paragraph separators (8232, 8233) as unicode escapes
    var j = JSON.stringify(String(s)), out = '';
    for (var i = 0; i < j.length; i++) { var c = j.charCodeAt(i); out += (c === 60 || c === 8232 || c === 8233) ? '\\u' + ('000' + c.toString(16)).slice(-4) : j.charAt(i); }
    return out;
  }
  var HEAD = '<!doctype html>\n<html>\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n';

  /* Preview page. Everything injected lives in <head>, ahead of the user's
     HTML, so incomplete markup (e.g. a half-typed "<div") cannot swallow it.
     The user's JS is added as a script element once the body is parsed: it
     still runs as a classic global script, and error line numbers match the
     JavaScript panel. */
  function buildDoc(html, css, js) {
    var load = js.trim() ? '<script>(function(){var src=' + jsString(js) + ';document.addEventListener("DOMContentLoaded",function(){var s=document.createElement("script");s.textContent=src;(document.body||document.documentElement).appendChild(s);});})();</' + 'script>\n' : '';
    return HEAD + '<script>' + HOOK + '</' + 'script>\n' + load +
      '<style>\n' + guard(css, 'style') + '\n</style>\n</head>\n<body>\n' +
      html + '\n</body>\n</html>';
  }
  // Clean page for download / new tab: no console hook, JS at the end of body
  function cleanDoc(html, css, js) {
    return HEAD + '<style>\n' + guard(css, 'style') + '\n</style>\n</head>\n<body>\n' +
      html + '\n' + (js.trim() ? '<script>\n' + guard(js, 'script') + '\n</' + 'script>\n' : '') +
      '</body>\n</html>';
  }

  function b64uEnc(str) { var b = new TextEncoder().encode(str), s = ''; b.forEach(function (x) { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  var I_HTML = '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M9.5 13l-2 2 2 2M14.5 13l2 2-2 2"/>';
  var I_CODE = '<path d="M8 4H6a2 2 0 0 0-2 2v4l-2 2 2 2v4a2 2 0 0 0 2 2h2M16 4h2a2 2 0 0 1 2 2v4l2 2-2 2v4a2 2 0 0 1-2 2h-2"/>';
  var I_EYE = '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>';
  var I_TERM = '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>';
  var I_REFRESH = '<path d="M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5"/>';
  var I_NEW = '<path d="M14 3h7v7M21 3l-9 9M19 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h5"/>';
  var IC_CLEAR = '<path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 13a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-13"/>';
  var IC_DL = '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  var LANGS = [
    { id: 'html', label: 'HTML', placeholder: '<!-- HTML markup -->', file: 'index.html' },
    { id: 'css', label: 'CSS', placeholder: '/* CSS styles */', file: 'style.css' },
    { id: 'js', label: 'JavaScript', placeholder: '// JavaScript', file: 'script.js' }
  ];

  CK.registerTool('html', function (root, ctx) {
    var ui = CK.ui, el = CK.el, iconSvg = CK.iconSvg;

    root.appendChild(ui.head('HTML Viewer', 'live'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_HTML);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);
    ui.setSel(strip, 'HTML Viewer', 'live', 'Write HTML, CSS and JavaScript and preview the page live in an isolated sandbox.');

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col2' });
    var colR = el('div', { class: 'col' });
    // Editor: which source panel is shown, all on one line
    var langBtns = {}, langRow = el('div', { style: 'display:flex; gap:5px; align-items:center;' });
    LANGS.forEach(function (l) {
      var b = el('button', { class: 'eb', title: 'Edit ' + l.label }); b.textContent = l.label;
      b.addEventListener('click', function () { showLang(l.id); });
      langBtns[l.id] = b; langRow.appendChild(b);
    });
    var autoCb = el('input', { type: 'checkbox' }); autoCb.checked = true;
    var autoSwitch = el('label', { class: 'switch' }); autoSwitch.appendChild(autoCb); autoSwitch.appendChild(el('span', { class: 'track' })); autoSwitch.appendChild(el('span', {}, 'Auto-run'));
    autoCb.addEventListener('change', function () { if (autoCb.checked) run(); });
    colL.appendChild(ui.field('Editor', langRow)); colL.appendChild(ui.field('Options', autoSwitch));
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();

    // One source panel per language (same EDITOR title; the Editor selector
    // above shows which is active); only the selected one is shown
    var srcP = {};
    LANGS.forEach(function (l) {
      var p = ui.textPanel({ title: 'EDITOR', icon: I_CODE, placeholder: l.placeholder, actions: ['copy', 'paste', 'clear', 'download'], downloadName: l.file, onInput: schedule });
      // Run stays enabled even when this panel is empty (the others may not be)
      var runBtn = el('button', { class: 'prim enc' }); runBtn.textContent = 'Run';
      runBtn.addEventListener('click', run);
      var tb = p.panel.querySelector('.tb'); tb.insertBefore(runBtn, tb.firstChild);
      p.ta.spellcheck = false;
      p.ta.addEventListener('keydown', tabKey);
      srcP[l.id] = p;
      io.appendChild(p.panel);
    });

    // Preview panel: sandboxed iframe + console
    var outP = el('div', { class: 'panel io-p' });
    var hdr = el('div', { class: 'panel-hdr', html: iconSvg(I_EYE, 12) + ' ' });
    hdr.appendChild(document.createTextNode('PREVIEW'));
    var fill = el('span', { class: 'fill' }), tb = el('span', { class: 'tb' });
    tb.appendChild(ui.iconBtn(I_REFRESH, 'Refresh', run));
    tb.appendChild(ui.iconBtn(I_NEW, 'Open in new tab', doOpen));
    tb.appendChild(ui.iconBtn(IC_DL, 'Download page', function () { CK.download(page(), 'page.html', 'text/html'); }));
    hdr.appendChild(fill); hdr.appendChild(tb);
    var frame = el('iframe', { class: 'html-frame', title: 'Preview', sandbox: 'allow-scripts allow-modals allow-forms allow-popups' });
    var con = el('div', { class: 'html-console' });
    var conHdr = el('div', { class: 'html-console-hdr', html: iconSvg(I_TERM, 11) + ' ' });
    conHdr.appendChild(document.createTextNode('CONSOLE'));
    conHdr.appendChild(el('span', { class: 'fill' }));
    conHdr.appendChild(ui.iconBtn(IC_CLEAR, 'Clear console', function () { conBody.innerHTML = ''; }));
    var conBody = el('div', { class: 'html-console-body' });
    con.appendChild(conHdr); con.appendChild(conBody);
    outP.appendChild(hdr); outP.appendChild(frame); outP.appendChild(con);
    io.appendChild(outP);
    root.appendChild(io);

    var lang = 'html', timer = null;
    function showLang(id) {
      lang = id;
      LANGS.forEach(function (l) {
        srcP[l.id].panel.style.display = l.id === id ? '' : 'none';
        langBtns[l.id].classList.toggle('active', l.id === id);
      });
    }
    function page() { return cleanDoc(srcP.html.ta.value, srcP.css.ta.value, srcP.js.ta.value); }
    function run() { clearTimeout(timer); conBody.innerHTML = ''; frame.srcdoc = buildDoc(srcP.html.ta.value, srcP.css.ta.value, srcP.js.ta.value); }
    function schedule() { if (!autoCb.checked) return; clearTimeout(timer); timer = setTimeout(run, 500); }

    // Tab inserts two spaces instead of leaving the editor
    function tabKey(e) {
      if (e.key !== 'Tab') return;
      e.preventDefault();
      var t = e.target, s = t.selectionStart, en = t.selectionEnd;
      t.value = t.value.slice(0, s) + '  ' + t.value.slice(en);
      t.selectionStart = t.selectionEnd = s + 2;
      schedule();
    }

    function log(type, text) {
      var line = el('div', { class: 'html-log ' + (type || 'log') });
      line.textContent = text;
      conBody.appendChild(line);
      conBody.scrollTop = conBody.scrollHeight;
    }
    window.addEventListener('message', function (e) {
      if (e.source !== frame.contentWindow) return;
      var d = e.data;
      if (d && d.__ck === 'console') log(d.t, d.m);
    });

    function doOpen() {
      var url = URL.createObjectURL(new Blob([page()], { type: 'text/html' }));
      window.open(url, '_blank', 'noopener');
      setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    }
    function doShare() { CK.copy(location.href.split('#')[0] + '#tool=html&s=' + b64uEnc(JSON.stringify({ html: srcP.html.ta.value, css: srcP.css.ta.value, js: srcP.js.ta.value, auto: autoCb.checked ? 1 : 0 }))); }
    function doReset() {
      LANGS.forEach(function (l) { srcP[l.id].ta.value = ''; });
      autoCb.checked = true; showLang('html'); run(); ctx.toast('Reset complete', 'success');
    }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); srcP.html.ta.value = st.html || ''; srcP.css.ta.value = st.css || ''; srcP.js.ta.value = st.js || ''; autoCb.checked = st.auto !== 0; } catch (e) { } }
    showLang('html');
    run();
  });
})();

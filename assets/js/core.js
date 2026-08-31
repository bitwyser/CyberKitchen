/*
   core.js - CyberKitchen dashboard engine
   Generic, tool-agnostic: theme, toast, clipboard, download, storage, DOM
   helpers, tool registry, hash router, mount manager, keyboard dispatcher.
   Tools register a mount function by id via CK.registerTool(id, mountFn).
   Fully offline: no external dependencies.
*/
var CK = (function () {
  'use strict';

  var SVG_MOON = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
  var SVG_SUN  = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';

  /* Storage (namespaced, failure-safe) */
  var PREFIX = 'ck.';
  var store = {
    get: function (k, d) {
      try { var v = localStorage.getItem(PREFIX + k); return v === null ? d : v; }
      catch (e) { return d; }
    },
    set: function (k, v) { try { localStorage.setItem(PREFIX + k, v); } catch (e) {} }
  };

  /* DOM helpers */
  function $(sel, root) { return (root || document).querySelector(sel); }
  function iconSvg(inner, size) {
    size = size || 15;
    return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 24 24" fill="none" ' +
      'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + inner + '</svg>';
  }
  function el(tag, attrs, html) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === 'class') n.className = attrs[k];
      else if (k === 'html') n.innerHTML = attrs[k];
      else n.setAttribute(k, attrs[k]);
    });
    if (html != null) n.innerHTML = html;
    return n;
  }

  /* Theme */
  var theme = {
    load: function () {
      var t = store.get('theme', 'dark');
      document.documentElement.setAttribute('data-theme', t);
      this._icon(t);
    },
    toggle: function () {
      var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      store.set('theme', next);
      this._icon(next);
    },
    _icon: function (t) {
      var i = document.getElementById('themeIcon');
      if (i) i.innerHTML = t === 'dark' ? SVG_SUN : SVG_MOON;
    }
  };

  /* Toast */
  var _toastEl = null, _toastTimer = null;
  function toast(msg, type) {
    type = type || 'success';
    if (!_toastEl) {
      _toastEl = el('div', { class: 'toast' });
      document.body.appendChild(_toastEl);
    }
    _toastEl.textContent = msg;
    _toastEl.className = 'toast ' + type;
    // force reflow so re-triggering the transition works
    void _toastEl.offsetWidth;
    _toastEl.classList.add('show');
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(function () { _toastEl.classList.remove('show'); }, 2600);
  }

  /* Clipboard */
  function copy(text) {
    if (text == null || text === '') { toast('Nothing to copy', 'warn'); return; }
    var ok = function () { toast('Copied to clipboard', 'success'); };
    var fallback = function () {
      try {
        var ta = el('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;top:-9999px;opacity:0';
        document.body.appendChild(ta);
        ta.focus(); ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        ok();
      } catch (e) { toast('Copy failed', 'error'); }
    };
    if (navigator.clipboard && navigator.clipboard.writeText)
      navigator.clipboard.writeText(text).then(ok).catch(fallback);
    else fallback();
  }

  /* Clipboard paste (returns a promise of text, or null) */
  function paste() {
    if (navigator.clipboard && navigator.clipboard.readText)
      return navigator.clipboard.readText().catch(function () { return null; });
    return Promise.resolve(null);
  }

  /* Download */
  function download(text, filename, mime) {
    if (text == null || text === '') { toast('Nothing to save', 'warn'); return; }
    var a = el('a');
    a.href = URL.createObjectURL(new Blob([text], { type: mime || 'text/plain' }));
    a.download = filename || 'cyberkitchen.txt';
    a.click();
    URL.revokeObjectURL(a.href);
    toast('Download started', 'success');
  }

  /* Tool registry */
  var _tools = [];          // manifest: {id,label,category,tag,icon,libs,desc}
  var _categoryOrder = [];
  var _mounts = {};         // id -> mount function
  var _containers = {};     // id -> DOM element (created lazily)
  var _apis = {};           // id -> object returned by mount (optional)
  var _active = null;

  function defineTools(list, categoryOrder) {
    _tools = list || [];
    _categoryOrder = categoryOrder || [];
  }
  function getTool(id) {
    for (var i = 0; i < _tools.length; i++) if (_tools[i].id === id) return _tools[i];
    return null;
  }
  function registerTool(id, mountFn) {
    _mounts[id] = mountFn;
    // if this tool is already the active one showing a placeholder, mount it now
    if (_active === id && _containers[id]) {
      _containers[id].innerHTML = '';
      delete _apis[id];
      _doMount(id);
    }
  }

  /* Rail */
  function buildRail() {
    var scroll = document.getElementById('railScroll');
    if (!scroll) return;
    scroll.innerHTML = '';
    var cats = _categoryOrder.slice();
    // append any categories not listed, in first-seen order
    _tools.forEach(function (t) { if (cats.indexOf(t.category) === -1) cats.push(t.category); });
    cats.forEach(function (cat) {
      var inCat = _tools.filter(function (t) { return t.category === cat; });
      if (!inCat.length) return;
      scroll.appendChild(el('div', { class: 'grp' }, cat));
      inCat.forEach(function (t) {
        var btn = el('button', { class: 'item', 'data-id': t.id, title: t.label });
        btn.innerHTML = iconSvg(t.icon) +
          '<span class="nm">' + t.label + '</span>';
        btn.addEventListener('click', function () {
          navigate(t.id);
          document.body.classList.remove('drawer-open');
        });
        scroll.appendChild(btn);
      });
    });
  }
  function _markActiveRail(id) {
    var items = document.querySelectorAll('#railScroll .item');
    for (var i = 0; i < items.length; i++)
      items[i].classList.toggle('active', items[i].getAttribute('data-id') === id);
  }

  /* Mount management */
  function _doMount(id) {
    var tool = getTool(id);
    var root = _containers[id];
    var mountFn = _mounts[id];
    var ctx = { tool: tool, toast: toast, copy: copy, paste: paste, download: download,
                store: store, el: el, iconSvg: iconSvg, $: $ };
    if (mountFn) {
      var api = mountFn(root, ctx);
      _apis[id] = api || {};
    } else {
      _renderPlaceholder(root, tool);
    }
  }

  function _renderPlaceholder(root, tool) {
    var head = el('div', { class: 'tool-head' });
    head.innerHTML = '<h1>' + tool.label + '</h1>';
    var panel = el('div', { class: 'panel' });
    var ph = el('div', { class: 'ph' });
    ph.innerHTML =
      '<div class="ph-ico">' + iconSvg(tool.icon, 26) + '</div>' +
      '<div class="ph-title">' + tool.label + '</div>' +
      '<div class="ph-note">This tool is wired into the dashboard and will be implemented in an upcoming phase. ' +
      'The shell, theme, routing, and shared actions below are already live.</div>';
    var demoRow = el('div', { class: 'tb', style: 'margin-top:4px' });
    var bCopy = el('button', { class: 'btn mini' }, 'Copy demo');
    var bToast = el('button', { class: 'btn mini' }, 'Toast');
    var bDl = el('button', { class: 'btn mini' }, 'Download');
    bCopy.addEventListener('click', function () { copy('Hello from ' + tool.label + ' (CyberKitchen)'); });
    bToast.addEventListener('click', function () { toast(tool.label + ' ready', 'success'); });
    bDl.addEventListener('click', function () { download(tool.label + ' placeholder', tool.id + '.txt'); });
    demoRow.appendChild(bCopy); demoRow.appendChild(bToast); demoRow.appendChild(bDl);
    ph.appendChild(demoRow);
    panel.appendChild(ph);
    root.appendChild(head);
    root.appendChild(panel);
  }

  function activate(id) {
    if (!getTool(id)) id = _tools.length ? _tools[0].id : null;
    if (!id) return;
    _active = id;
    var main = document.getElementById('main');
    if (!_containers[id]) {
      var c = el('div', { class: 'tool', 'data-id': id });
      _containers[id] = c;
      main.appendChild(c);
      _doMount(id);
    }
    Object.keys(_containers).forEach(function (k) {
      _containers[k].hidden = (k !== id);
    });
    _markActiveRail(id);
    var t = getTool(id);
    if (t) document.title = t.label + ' - CyberKitchen';
    var api = _apis[id];
    if (api && typeof api.onActivate === 'function') api.onActivate();
  }

  /* Router */
  function currentId() {
    var m = /(?:^|[#&])tool=([\w-]+)/.exec(location.hash || '');
    return m ? m[1] : null;
  }
  function navigate(id) {
    if (id === _active) return;
    location.hash = 'tool=' + id;
  }
  function _onHash() {
    var id = currentId();
    if (id && id !== _active) activate(id);
  }

  /* Shell wiring */
  function _wireShell() {
    var themeBtn = document.getElementById('themeBtn');
    if (themeBtn) themeBtn.addEventListener('click', function () { theme.toggle(); });

    var collapseBtn = document.getElementById('collapseBtn');
    if (collapseBtn) collapseBtn.addEventListener('click', function () {
      document.body.classList.toggle('nav-collapsed');
      store.set('nav.collapsed', document.body.classList.contains('nav-collapsed') ? '1' : '0');
    });

    var hamb = document.getElementById('hamburger');
    if (hamb) hamb.addEventListener('click', function () { document.body.classList.toggle('drawer-open'); });

    var backdrop = document.getElementById('backdrop');
    if (backdrop) backdrop.addEventListener('click', function () { document.body.classList.remove('drawer-open'); });
  }

  function boot() {
    theme.load();
    if (store.get('nav.collapsed', '0') === '1') document.body.classList.add('nav-collapsed');
    buildRail();
    _wireShell();
    activate(currentId() || (_tools[0] && _tools[0].id));
    window.addEventListener('hashchange', _onHash);
  }

  // Rough password strength: 6-point score to a labelled, colour-coded rating
  function pwStrength(pw) {
    var s = 0;
    if (pw.length >= 8) s++; if (pw.length >= 12) s++;
    if (/[A-Z]/.test(pw)) s++; if (/[a-z]/.test(pw)) s++;
    if (/[0-9]/.test(pw)) s++; if (/[^A-Za-z0-9]/.test(pw)) s++;
    var i = Math.min(s, 6);
    return { label: ['Too short', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong', 'Excellent'][i], cls: ['err', 'err', 'warn', 'warn', 'ok', 'ok', 'ok'][i] };
  }
  // Attach a live strength pill to a text panel's input, sitting just left of the char-count
  function attachStrength(panelObj) {
    var panel = panelObj.panel, ta = panelObj.ta;
    var badge = el('span', { class: 'pw-strength' });
    panel.appendChild(badge);
    var cc = panel.querySelector('.char-count');
    function update() {
      var pw = ta.value;
      if (!pw) { badge.style.display = 'none'; return; }
      badge.style.display = '';
      var r = pwStrength(pw);
      badge.textContent = r.label;
      badge.className = 'pw-strength ' + r.cls;
      badge.style.right = (23 + (cc ? cc.offsetWidth : 0) + 8) + 'px';
    }
    if (panelObj.onContent) panelObj.onContent(update); else ta.addEventListener('input', update);
    update();
    return update;
  }

  // Flash a pass/fail highlight on one or more textareas, auto-clearing after 5s
  function flashVerify(match) {
    var els = Array.prototype.slice.call(arguments, 1).filter(Boolean);
    els.forEach(function (t) {
      clearTimeout(t._vfTimer);
      t.classList.remove('verify-match', 'verify-fail');
      t.classList.add(match ? 'verify-match' : 'verify-fail');
      t._vfTimer = setTimeout(function () { t.classList.remove('verify-match', 'verify-fail'); }, 5000);
    });
  }

  return {
    boot: boot, defineTools: defineTools, registerTool: registerTool,
    navigate: navigate, getTool: getTool,
    theme: theme, toast: toast, copy: copy, paste: paste, download: download,
    store: store, el: el, iconSvg: iconSvg, $: $, flashVerify: flashVerify,
    pwStrength: pwStrength, attachStrength: attachStrength
  };
})();

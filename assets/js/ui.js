/*
   ui.js - shared UI builders for CyberKitchen tools
   Composes the standard tool layout (head, config strip, picker, I/O panels)
   from the design-system classes in dashboard.css. Depends on core.js (CK).
*/
CK.ui = (function () {
  'use strict';
  var el = CK.el, iconSvg = CK.iconSvg;

  var IC = {
    copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
    paste: '<rect x="8" y="3" width="8" height="4" rx="1"/><path d="M8 5H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2"/>',
    clear: '<path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 13a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-13"/>',
    download: '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>'
  };

  function head(label) {
    var h = el('div', { class: 'tool-head' });
    var h1 = el('h1'); h1.textContent = label; h.appendChild(h1);
    return h;
  }

  function iconBtn(inner, label, onClick) {
    var b = el('button', { class: 'ib', title: label });
    b.innerHTML = iconSvg(inner, 15) + '<span class="lbl"></span>';
    b.querySelector('.lbl').textContent = label;
    if (onClick) b.addEventListener('click', onClick);
    return b;
  }

  function miniBtn(label, onClick) {
    var b = el('button', { class: 'btn mini' });
    b.textContent = label;
    if (onClick) b.addEventListener('click', onClick);
    return b;
  }

  /* Selected-item strip with an actions area.
     Returns { strip, name, badge, desc, acts } */
  function selStrip(iconInner) {
    var strip = el('div', { class: 'cfg-strip' });
    var sel = el('div', { class: 'sel' });
    var ico = el('div', { class: 'sel-ico', html: iconSvg(iconInner, 17) });
    var txt = el('div', { class: 'sel-txt' });
    var name = el('span', { class: 'sel-name' });
    var nmText = el('span');
    var badge = el('span', { class: 'badge' });
    name.appendChild(nmText); name.appendChild(badge);
    var desc = el('span', { class: 'sel-desc' });
    txt.appendChild(name); txt.appendChild(desc);
    sel.appendChild(ico); sel.appendChild(txt);
    var acts = el('div', { class: 'acts' });
    strip.appendChild(sel); strip.appendChild(acts);
    return { strip: strip, nmText: nmText, badge: badge, desc: desc, acts: acts };
  }

  function setSel(refs, label, badge, desc) {
    refs.nmText.textContent = label + ' ';
    refs.badge.textContent = badge || '';
    refs.badge.style.display = badge ? '' : 'none';
    refs.desc.textContent = desc || '';
  }

  /* Grouped picker grid.
     groups: [{ label, items:[{id,label,title}] }]
     Returns { el, setActive(id) } */
  function picker(groups, onSelect) {
    var wrap = el('div', { class: 'picker' });
    var byId = {};
    groups.forEach(function (g) {
      wrap.appendChild(el('span', { class: 'pk-label' }, g.label));
      var grid = el('div', { class: 'pk-grid' });
      g.items.forEach(function (it) {
        var b = el('button', { class: 'eb', 'data-id': it.id, title: it.title || it.label });
        b.textContent = it.label;
        b.addEventListener('click', function () { onSelect(it.id); });
        byId[it.id] = b;
        grid.appendChild(b);
      });
      wrap.appendChild(grid);
    });
    return {
      el: wrap,
      setActive: function (id) {
        Object.keys(byId).forEach(function (k) { byId[k].classList.toggle('active', k === id); });
      }
    };
  }

  /* Text I/O panel with a header toolbar.
     cfg: { title, icon, placeholder, readonly, downloadName, onInput,
            primary:{label,cls,onClick}, actions:['copy','paste','clear','download'] }
     Returns { panel, ta } */
  function textPanel(cfg) {
    cfg = cfg || {};
    var panel = el('div', { class: 'panel io-p' });
    var hdr = el('div', { class: 'panel-hdr' });
    if (cfg.icon) hdr.innerHTML = iconSvg(cfg.icon, 12) + ' ';
    hdr.appendChild(document.createTextNode(cfg.title || ''));
    var fill = el('span', { class: 'fill' });
    var tb = el('span', { class: 'tb' });
    var ta = el('textarea', { class: 'ta' });
    if (cfg.placeholder) ta.placeholder = cfg.placeholder;
    if (cfg.readonly) ta.readOnly = true;
    var fire = function () { if (cfg.onInput) cfg.onInput(); };
    var prims = cfg.primaries || (cfg.primary ? [cfg.primary] : []);
    prims.forEach(function (pr) {
      var p = el('button', { class: 'prim ' + (pr.cls || '') });
      p.textContent = pr.label;
      p.addEventListener('click', pr.onClick);
      tb.appendChild(p);
    });
    (cfg.actions || []).forEach(function (a) {
      if (a === 'copy') tb.appendChild(iconBtn(IC.copy, 'Copy', function () { CK.copy(ta.value); }));
      else if (a === 'paste') tb.appendChild(iconBtn(IC.paste, 'Paste', function () {
        CK.paste().then(function (t) { if (t != null) { ta.value = t; fire(); } });
      }));
      else if (a === 'clear') tb.appendChild(iconBtn(IC.clear, 'Clear', function () { ta.value = ''; fire(); }));
      else if (a === 'download') tb.appendChild(iconBtn(IC.download, 'Download', function () {
        CK.download(ta.value, cfg.downloadName || 'output.txt');
      }));
    });
    hdr.appendChild(fill); hdr.appendChild(tb);
    panel.appendChild(hdr); panel.appendChild(ta);
    if (cfg.onInput) ta.addEventListener('input', cfg.onInput);
    return { panel: panel, ta: ta };
  }

  function ioRow(oneCol) { return el('div', { class: 'io' + (oneCol ? ' io-1col' : '') }); }

  function configPanel() { return el('div', { class: 'panel config' }); }

  /* A labelled field row (label + control) */
  function field(labelText, control) {
    var f = el('div', { class: 'field' });
    var l = el('label'); l.textContent = labelText;
    f.appendChild(l); f.appendChild(control);
    return f;
  }

  /* <select> from [{value,label}] (or ['a','b']); onChange(value) */
  function select(items, onChange, current) {
    var s = el('select', { class: 'inp' });
    items.forEach(function (it) {
      var v = it.value != null ? it.value : it, t = it.label != null ? it.label : it;
      var o = el('option'); o.value = v; o.textContent = t; s.appendChild(o);
    });
    if (current != null) s.value = current;
    if (onChange) s.addEventListener('change', function () { onChange(s.value); });
    return s;
  }

  /* A checkbox toggle row; onChange(checked) */
  function toggle(labelText, checked, onChange) {
    var wrap = el('label', { class: 'toggle-row' });
    var cb = el('input', { type: 'checkbox' }); cb.checked = !!checked;
    wrap.appendChild(cb); wrap.appendChild(document.createTextNode(labelText));
    if (onChange) cb.addEventListener('change', function () { onChange(cb.checked); });
    return { wrap: wrap, cb: cb };
  }

  return {
    head: head, iconBtn: iconBtn, miniBtn: miniBtn,
    selStrip: selStrip, setSel: setSel, picker: picker,
    textPanel: textPanel, ioRow: ioRow, configPanel: configPanel, field: field,
    select: select, toggle: toggle
  };
})();

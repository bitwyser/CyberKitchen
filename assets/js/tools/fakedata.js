/*
   fakedata.js - Fake Data Generator tool
   Random test data (names, emails, IDs, etc). Pure JS, secure randomness.
*/
(function () {
  'use strict';

  function randInt(max) {
    var limit = Math.floor(0x100000000 / max) * max, a = new Uint32Array(1);
    do { crypto.getRandomValues(a); } while (a[0] >= limit);
    return a[0] % max;
  }
  function pick(arr) { return arr[randInt(arr.length)]; }
  function digits(n) { var s = ''; for (var i = 0; i < n; i++) s += randInt(10); return s; }
  function hex(n) { var s = '', h = '0123456789abcdef'; for (var i = 0; i < n; i++) s += h[randInt(16)]; return s; }

  var FIRST = ['James', 'Mary', 'Liam', 'Olivia', 'Noah', 'Emma', 'Ava', 'Ethan', 'Sophia', 'Mason', 'Isabella', 'Lucas', 'Mia', 'Aiden', 'Riya', 'Arjun', 'Zara', 'Diego', 'Yuki', 'Priya', 'Omar', 'Nina', 'Leo', 'Chloe'];
  var LAST = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Patel', 'Kim', 'Nguyen', 'Khan', 'Silva', 'Rossi', 'Chen', 'Kumar', 'Ali', 'Costa', 'Novak', 'Haas'];
  var CITY = ['London', 'Mumbai', 'Berlin', 'Tokyo', 'Austin', 'Toronto', 'Sydney', 'Lisbon', 'Nairobi', 'Oslo', 'Denver', 'Pune', 'Madrid', 'Seoul', 'Cairo'];
  var COUNTRY = ['United States', 'India', 'Germany', 'Japan', 'Canada', 'Australia', 'Portugal', 'Kenya', 'Norway', 'Brazil', 'Spain', 'South Korea', 'Egypt'];
  var STREET = ['Maple Ave', 'Oak St', 'Pine Rd', 'Cedar Ln', 'Elm St', 'Sunset Blvd', 'Hill Rd', '2nd Ave', 'Park Lane', 'River Rd'];
  var COMPANY = ['Acme', 'Globex', 'Initech', 'Umbrella', 'Hooli', 'Stark', 'Wayne', 'Wonka', 'Cyberdyne', 'Soylent', 'Vandelay', 'Pied Piper'];
  var CSUFFIX = ['Inc', 'LLC', 'Corp', 'Labs', 'Group', 'Systems', 'Technologies'];
  var JOB = ['Software Engineer', 'Product Manager', 'Data Analyst', 'Designer', 'DevOps Engineer', 'Security Analyst', 'QA Engineer', 'Architect', 'Researcher', 'Consultant'];
  var DOMAIN = ['example.com', 'mail.com', 'test.org', 'demo.net', 'inbox.io', 'sample.co'];
  var LOREM = 'lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua enim ad minim veniam quis nostrud'.split(' ');

  function uuid() {
    var b = new Uint8Array(16); crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
    var h = []; for (var i = 0; i < 16; i++) h.push(b[i].toString(16).padStart(2, '0'));
    return h.slice(0, 4).join('') + '-' + h.slice(4, 6).join('') + '-' + h.slice(6, 8).join('') + '-' + h.slice(8, 10).join('') + '-' + h.slice(10, 16).join('');
  }
  function luhn(prefix, len) {
    var num = prefix; while (num.length < len - 1) num += randInt(10);
    var sum = 0, alt = true;
    for (var i = num.length - 1; i >= 0; i--) { var d = +num[i]; if (alt) { d *= 2; if (d > 9) d -= 9; } sum += d; alt = !alt; }
    return num + ((10 - (sum % 10)) % 10);
  }

  function name() { return pick(FIRST) + ' ' + pick(LAST); }
  function email() { var f = pick(FIRST).toLowerCase(), l = pick(LAST).toLowerCase(); return pick([f + '.' + l, f + l + digits(2), f[0] + l]) + '@' + pick(DOMAIN); }
  function username() { return pick(FIRST).toLowerCase() + pick(['_', '.', '']) + pick(LAST).toLowerCase() + digits(randInt(3)); }
  function phone() { return '+1 (' + digits(3) + ') ' + digits(3) + '-' + digits(4); }
  function ipv4() { return randInt(256) + '.' + randInt(256) + '.' + randInt(256) + '.' + randInt(256); }
  function ipv6() { var p = []; for (var i = 0; i < 8; i++) p.push(hex(4)); return p.join(':'); }
  function mac() { var p = []; for (var i = 0; i < 6; i++) p.push(hex(2)); return p.join(':'); }
  function creditcard() { var t = pick([['4', 16], ['51', 16], ['37', 15]]); return luhn(t[0], t[1]).replace(/(.{4})/g, '$1 ').trim(); }
  function address() { return (randInt(9000) + 100) + ' ' + pick(STREET) + ', ' + pick(CITY); }
  function company() { return pick(COMPANY) + ' ' + pick(CSUFFIX); }
  function isodate() { var y = 1970 + randInt(60), m = 1 + randInt(12), d = 1 + randInt(28); return y + '-' + ('' + m).padStart(2, '0') + '-' + ('' + d).padStart(2, '0'); }
  function colorhex() { return '#' + hex(6); }
  function lorem() { var n = 6 + randInt(8), w = []; for (var i = 0; i < n; i++) w.push(pick(LOREM)); var s = w.join(' '); return s.charAt(0).toUpperCase() + s.slice(1) + '.'; }
  function bool() { return pick(['true', 'false']); }

  var TYPES = [
    { id: 'name', label: 'Full Name', group: 'Person', desc: 'Random full name', fn: name },
    { id: 'first', label: 'First Name', group: 'Person', desc: 'Random first name', fn: function () { return pick(FIRST); } },
    { id: 'last', label: 'Last Name', group: 'Person', desc: 'Random last name', fn: function () { return pick(LAST); } },
    { id: 'job', label: 'Job Title', group: 'Person', desc: 'Random job title', fn: function () { return pick(JOB); } },
    { id: 'company', label: 'Company', group: 'Person', desc: 'Random company name', fn: company },

    { id: 'email', label: 'Email', group: 'Contact', desc: 'Random email address', fn: email },
    { id: 'username', label: 'Username', group: 'Contact', desc: 'Random username', fn: username },
    { id: 'phone', label: 'Phone', group: 'Contact', desc: 'Random phone number', fn: phone },
    { id: 'address', label: 'Address', group: 'Contact', desc: 'Random street address', fn: address },
    { id: 'city', label: 'City', group: 'Contact', desc: 'Random city', fn: function () { return pick(CITY); } },
    { id: 'country', label: 'Country', group: 'Contact', desc: 'Random country', fn: function () { return pick(COUNTRY); } },

    { id: 'uuid', label: 'UUID', group: 'Tech', desc: 'UUID v4', fn: uuid },
    { id: 'ipv4', label: 'IPv4', group: 'Tech', desc: 'Random IPv4 address', fn: ipv4 },
    { id: 'ipv6', label: 'IPv6', group: 'Tech', desc: 'Random IPv6 address', fn: ipv6 },
    { id: 'mac', label: 'MAC', group: 'Tech', desc: 'Random MAC address', fn: mac },
    { id: 'card', label: 'Credit Card', group: 'Tech', desc: 'Luhn-valid test card number', fn: creditcard },
    { id: 'color', label: 'Color Hex', group: 'Tech', desc: 'Random hex color', fn: colorhex },

    { id: 'date', label: 'Date', group: 'Misc', desc: 'Random ISO date', fn: isodate },
    { id: 'lorem', label: 'Lorem', group: 'Misc', desc: 'Lorem ipsum sentence', fn: lorem },
    { id: 'bool', label: 'Boolean', group: 'Misc', desc: 'true or false', fn: bool }
  ];
  function get(id) { for (var i = 0; i < TYPES.length; i++) if (TYPES[i].id === id) return TYPES[i]; return null; }
  var GROUPS = ['Person', 'Contact', 'Tech', 'Misc'];

  var I_USER = '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('fakedata', function (root, ctx) {
    var ui = CK.ui, el = CK.el, current = 'name';

    root.appendChild(ui.head('Fake Data', TYPES.length + ' types'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_USER);
    var countInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '500', value: '5' });
    var cf = ui.field('Count', countInput); cf.style.marginRight = '4px';
    strip.acts.appendChild(cf);
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var groups = GROUPS.map(function (g) { return { label: g, items: TYPES.filter(function (t) { return t.group === g; }).map(function (t) { return { id: t.id, label: t.label, title: t.desc }; }) }; });
    var pk = ui.picker(groups, function (id) { select(id); generate(); });
    cfg.appendChild(pk.el);
    root.appendChild(cfg);

    var io = ui.ioRow(true);
    var panel = el('div', { class: 'panel io-p' });
    var hdr = el('div', { class: 'panel-hdr' });
    hdr.innerHTML = CK.iconSvg(I_USER, 12) + ' OUTPUT';
    var fill = el('span', { class: 'fill' });
    var tb = el('span', { class: 'tb' });
    var genBtn = el('button', { class: 'prim enc' }, 'Generate');
    tb.appendChild(genBtn);
    tb.appendChild(ui.miniBtn('Copy', function () { CK.copy(ta.value); }));
    tb.appendChild(ui.miniBtn('Download', function () { CK.download(ta.value, 'fakedata.txt'); }));
    hdr.appendChild(fill); hdr.appendChild(tb);
    var ta = el('textarea', { class: 'ta', readonly: 'readonly' });
    panel.appendChild(hdr); panel.appendChild(ta);
    io.appendChild(panel); root.appendChild(io);

    function select(id) { var t = get(id); if (!t) return; current = id; pk.setActive(id); ui.setSel(strip, t.label, t.group, t.desc); }
    function generate() {
      var t = get(current), n = Math.max(1, Math.min(500, +countInput.value || 1)), out = [];
      for (var i = 0; i < n; i++) out.push(t.fn());
      ta.value = out.join('\n');
    }
    function doReset() { current = 'name'; countInput.value = '5'; select('name'); generate(); ctx.toast('Reset complete', 'success'); }

    genBtn.addEventListener('click', generate);
    countInput.addEventListener('input', generate);
    select(current); generate();

    return {
      reset: doReset,
      onKey: function (e) { if ((e.ctrlKey || e.metaKey) && String(e.key).toLowerCase() === 'g') { e.preventDefault(); generate(); } }
    };
  });
})();

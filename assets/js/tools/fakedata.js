/*
   fakedata.js - Fake Data Generator
   Per-type options (email domain, phone country, username/IP/MAC/UUID),
   Plain/JSON/CSV output, adjustable count. Secure randomness. Pure JS.
*/
(function () {
  'use strict';
  function randInt(max) { var limit = Math.floor(0x100000000 / max) * max, a = new Uint32Array(1); do { crypto.getRandomValues(a); } while (a[0] >= limit); return a[0] % max; }
  function pick(a) { return a[randInt(a.length)]; }
  function digits(n) { var s = ''; for (var i = 0; i < n; i++) s += randInt(10); return s; }
  function hex(n) { var s = '', h = '0123456789abcdef'; for (var i = 0; i < n; i++) s += h[randInt(16)]; return s; }

  var FIRST = ['James', 'Mary', 'Liam', 'Olivia', 'Noah', 'Emma', 'Ava', 'Ethan', 'Sophia', 'Mason', 'Isabella', 'Lucas', 'Mia', 'Aiden', 'Riya', 'Arjun', 'Zara', 'Diego', 'Yuki', 'Priya', 'Omar', 'Nina', 'Leo', 'Chloe'];
  var LAST = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Patel', 'Kim', 'Nguyen', 'Khan', 'Silva', 'Rossi', 'Chen', 'Kumar', 'Ali', 'Costa', 'Novak', 'Haas'];
  var ADJ = ['swift', 'brave', 'silent', 'cosmic', 'lunar', 'rapid', 'quiet', 'clever', 'mighty', 'noble', 'shadow', 'crimson', 'golden', 'frost', 'iron', 'wild'];
  var NOUN = ['tiger', 'falcon', 'wizard', 'ranger', 'nomad', 'phoenix', 'raven', 'comet', 'viper', 'yeti', 'otter', 'lynx', 'hawk', 'wolf', 'fox', 'orca'];
  var CITY = ['London', 'Mumbai', 'Berlin', 'Tokyo', 'Austin', 'Toronto', 'Sydney', 'Lisbon', 'Nairobi', 'Oslo', 'Denver', 'Pune', 'Madrid', 'Seoul', 'Cairo'];
  var COUNTRY = ['United States', 'India', 'Germany', 'Japan', 'Canada', 'Australia', 'Portugal', 'Kenya', 'Norway', 'Brazil', 'Spain', 'South Korea', 'Egypt'];
  var STREET = ['Maple Ave', 'Oak St', 'Pine Rd', 'Cedar Ln', 'Elm St', 'Sunset Blvd', 'Hill Rd', '2nd Ave', 'Park Lane', 'River Rd'];
  var COMPANY = ['Acme', 'Globex', 'Initech', 'Umbrella', 'Hooli', 'Stark', 'Wayne', 'Wonka', 'Cyberdyne', 'Soylent', 'Vandelay', 'Pied Piper'];
  var CSUFFIX = ['Inc', 'LLC', 'Corp', 'Labs', 'Group', 'Systems', 'Technologies'];
  var JOB = ['Software Engineer', 'Product Manager', 'Data Analyst', 'Designer', 'DevOps Engineer', 'Security Analyst', 'QA Engineer', 'Architect', 'Researcher', 'Consultant'];
  var DOMAINS = ['gmail.com', 'yahoo.com', 'outlook.com', 'icloud.com', 'proton.me'];
  var LOREM = 'lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua enim ad minim veniam quis nostrud'.split(' ');
  var OUI = ['00:1A:2B', '3C:5A:B4', 'F0:9F:C2', 'A4:C3:F0', 'B8:27:EB', 'DC:A6:32'];

  function uuid() { var b = new Uint8Array(16); crypto.getRandomValues(b); b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80; var h = []; for (var i = 0; i < 16; i++) h.push(b[i].toString(16).padStart(2, '0')); return h.slice(0, 4).join('') + '-' + h.slice(4, 6).join('') + '-' + h.slice(6, 8).join('') + '-' + h.slice(8, 10).join('') + '-' + h.slice(10, 16).join(''); }
  function luhn(prefix, len) { var num = prefix; while (num.length < len - 1) num += randInt(10); var sum = 0, alt = true; for (var i = num.length - 1; i >= 0; i--) { var d = +num[i]; if (alt) { d *= 2; if (d > 9) d -= 9; } sum += d; alt = !alt; } return num + ((10 - (sum % 10)) % 10); }
  var PHONE = { us: function () { return '+1 (' + digits(3) + ') ' + digits(3) + '-' + digits(4); }, uk: function () { return '+44 ' + digits(4) + ' ' + digits(6); }, de: function () { return '+49 ' + digits(3) + ' ' + digits(7); }, fr: function () { return '+33 ' + digits(1) + ' ' + digits(2) + ' ' + digits(2) + ' ' + digits(2) + ' ' + digits(2); }, jp: function () { return '+81 ' + digits(2) + '-' + digits(4) + '-' + digits(4); }, au: function () { return '+61 4' + digits(2) + ' ' + digits(3) + ' ' + digits(3); }, in: function () { return '+91 ' + digits(5) + ' ' + digits(5); }, br: function () { return '+55 (' + digits(2) + ') ' + digits(5) + '-' + digits(4); } };

  var I_USER = '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';

  CK.registerTool('fakedata', function (root, ctx) {
    var ui = CK.ui, el = CK.el, current = 'name';

    root.appendChild(ui.head('Fake Data', 'generator'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_USER);
    var countInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '1000', value: '5' });
    var cf = ui.field('Count', countInput); cf.style.marginRight = '4px'; strip.acts.appendChild(cf);
    var fmtSel = ui.select([['plain', 'Plain'], ['json', 'JSON'], ['csv', 'CSV']].map(function (a) { return { value: a[0], label: a[1] }; }), function () { generate(); }, 'plain');
    var ff = ui.field('Format', fmtSel); ff.style.marginRight = '4px'; strip.acts.appendChild(ff);
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var opt = el('div', { class: 'cfg-form' });
    cfg.appendChild(opt);

    // per-type option controls (built once, shown/hidden per type)
    var emailDomain = ui.select([['random', 'Random']].concat(DOMAINS.map(function (d) { return [d, d]; })).concat([['custom', 'Custom...']]).map(mk), function (v) { emailCustom.style.display = v === 'custom' ? '' : 'none'; generate(); }, 'random');
    var emailCustom = el('input', { class: 'inp sm', type: 'text', placeholder: 'domain.com' }); emailCustom.style.display = 'none'; emailCustom.addEventListener('input', generate);
    var emailField = ui.field('Domain', emailDomain), emailCustF = ui.field('Custom domain', emailCustom);
    var phoneCountry = ui.select([['random', 'Random']].concat(Object.keys(PHONE).map(function (k) { return [k, k.toUpperCase()]; })).map(mk), generate, 'us');
    var phoneField = ui.field('Country', phoneCountry);
    var userSource = ui.select([['adjnoun', 'adjective+noun'], ['name', 'name-based'], ['letters', 'random letters']].map(mk), generate, 'adjnoun');
    var userCase = ui.select([['lower', 'lowercase'], ['upper', 'UPPERCASE'], ['camel', 'CamelCase']].map(mk), generate, 'lower');
    var userSuffix = ui.toggle('Number suffix', true, generate);
    var userF1 = ui.field('Word source', userSource), userF2 = ui.field('Case', userCase), userF3 = ui.field('Suffix', userSuffix.wrap);
    var ipType = ui.select([['any', 'Any'], ['private', 'Private'], ['public', 'Public'], ['loopback', 'Loopback'], ['multicast', 'Multicast']].map(mk), generate, 'any');
    var ipCidr = ui.toggle('With CIDR', false, generate);
    var ipF1 = ui.field('Range', ipType), ipF2 = ui.field('CIDR', ipCidr.wrap);
    var macSep = ui.select([[':', 'Colon'], ['-', 'Dash'], ['.', 'Dot (Cisco)'], ['', 'None']].map(mk), generate, ':');
    var macVendor = ui.toggle('Real OUI prefix', false, generate);
    var macF1 = ui.field('Separator', macSep), macF2 = ui.field('Vendor', macVendor.wrap);
    var uuidUpper = ui.toggle('Uppercase', false, generate);
    var uuidF = ui.field('Case', uuidUpper.wrap);
    function mk(a) { return { value: a[0], label: a[1] }; }
    var OPT_FIELDS = { email: [emailField, emailCustF], phone: [phoneField], username: [userF1, userF2, userF3], ipv4: [ipF1, ipF2], ipv6: [], mac: [macF1, macF2], uuid: [uuidF] };
    Object.keys(OPT_FIELDS).forEach(function (k) { OPT_FIELDS[k].forEach(function (f) { opt.appendChild(f); }); });

    var TYPES = [
      { id: 'name', label: 'Full Name', group: 'Person', desc: 'Random full name', fn: function () { return pick(FIRST) + ' ' + pick(LAST); } },
      { id: 'first', label: 'First Name', group: 'Person', desc: 'Random first name', fn: function () { return pick(FIRST); } },
      { id: 'last', label: 'Last Name', group: 'Person', desc: 'Random last name', fn: function () { return pick(LAST); } },
      { id: 'job', label: 'Job Title', group: 'Person', desc: 'Random job title', fn: function () { return pick(JOB); } },
      { id: 'company', label: 'Company', group: 'Person', desc: 'Random company', fn: function () { return pick(COMPANY) + ' ' + pick(CSUFFIX); } },
      { id: 'email', label: 'Email', group: 'Contact', desc: 'Email with domain options', fn: genEmail },
      { id: 'username', label: 'Username', group: 'Contact', desc: 'Username with options', fn: genUser },
      { id: 'phone', label: 'Phone', group: 'Contact', desc: 'Phone by country', fn: genPhone },
      { id: 'address', label: 'Address', group: 'Contact', desc: 'Street address', fn: function () { return (randInt(9000) + 100) + ' ' + pick(STREET) + ', ' + pick(CITY); } },
      { id: 'city', label: 'City', group: 'Contact', desc: 'Random city', fn: function () { return pick(CITY); } },
      { id: 'country', label: 'Country', group: 'Contact', desc: 'Random country', fn: function () { return pick(COUNTRY); } },
      { id: 'uuid', label: 'UUID', group: 'Tech', desc: 'UUID v4', fn: genUuid },
      { id: 'ipv4', label: 'IPv4', group: 'Tech', desc: 'IPv4 with range options', fn: genIpv4 },
      { id: 'ipv6', label: 'IPv6', group: 'Tech', desc: 'IPv6 address', fn: genIpv6 },
      { id: 'mac', label: 'MAC', group: 'Tech', desc: 'MAC with format options', fn: genMac },
      { id: 'card', label: 'Credit Card', group: 'Tech', desc: 'Luhn-valid test card', fn: function () { var t = pick([['4', 16], ['51', 16], ['37', 15]]); return luhn(t[0], t[1]).replace(/(.{4})/g, '$1 ').trim(); } },
      { id: 'color', label: 'Color Hex', group: 'Tech', desc: 'Random hex color', fn: function () { return '#' + hex(6); } },
      { id: 'date', label: 'Date', group: 'Misc', desc: 'Random ISO date', fn: function () { var y = 1970 + randInt(60), m = 1 + randInt(12), d = 1 + randInt(28); return y + '-' + ('' + m).padStart(2, '0') + '-' + ('' + d).padStart(2, '0'); } },
      { id: 'lorem', label: 'Lorem', group: 'Misc', desc: 'Lorem ipsum sentence', fn: function () { var n = 6 + randInt(8), w = []; for (var i = 0; i < n; i++) w.push(pick(LOREM)); var s = w.join(' '); return s.charAt(0).toUpperCase() + s.slice(1) + '.'; } },
      { id: 'bool', label: 'Boolean', group: 'Misc', desc: 'true or false', fn: function () { return pick(['true', 'false']); } }
    ];
    function get(id) { for (var i = 0; i < TYPES.length; i++) if (TYPES[i].id === id) return TYPES[i]; return null; }

    function genEmail() { var d = emailDomain.value === 'random' ? pick(DOMAINS) : emailDomain.value === 'custom' ? (emailCustom.value || 'example.com') : emailDomain.value; var f = pick(FIRST).toLowerCase(), l = pick(LAST).toLowerCase(); return pick([f + '.' + l, f + l + digits(2), f[0] + l]) + '@' + d; }
    function genUser() { var base; if (userSource.value === 'name') base = pick(FIRST).toLowerCase() + pick(LAST).toLowerCase(); else if (userSource.value === 'letters') { base = ''; for (var i = 0; i < 6; i++) base += 'abcdefghijklmnopqrstuvwxyz'[randInt(26)]; } else base = pick(ADJ) + pick(NOUN); if (userCase.value === 'upper') base = base.toUpperCase(); else if (userCase.value === 'camel') base = base.replace(/(^|[^a-z])([a-z])/g, function (m, a, b) { return a + b.toUpperCase(); }); return base + (userSuffix.cb.checked ? digits(1 + randInt(3)) : ''); }
    function genPhone() { var c = phoneCountry.value === 'random' ? pick(Object.keys(PHONE)) : phoneCountry.value; return PHONE[c](); }
    function genUuid() { var u = uuid(); return uuidUpper.cb.checked ? u.toUpperCase() : u; }
    function genIpv4() { var o, t = ipType.value; if (t === 'private') o = pick([[10, randInt(256), randInt(256), randInt(256)], [172, 16 + randInt(16), randInt(256), randInt(256)], [192, 168, randInt(256), randInt(256)]]); else if (t === 'loopback') o = [127, randInt(256), randInt(256), 1 + randInt(254)]; else if (t === 'multicast') o = [224 + randInt(16), randInt(256), randInt(256), randInt(256)]; else if (t === 'public') { do { o = [1 + randInt(223), randInt(256), randInt(256), 1 + randInt(254)]; } while (o[0] === 10 || o[0] === 127 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168) || o[0] >= 224); } else o = [randInt(256), randInt(256), randInt(256), randInt(256)]; return o.join('.') + (ipCidr.cb.checked ? '/' + (8 + randInt(25)) : ''); }
    function genIpv6() { var p = []; for (var i = 0; i < 8; i++) p.push(hex(4)); return p.join(':'); }
    function genMac() { var first = parseInt(hex(2), 16); if (macVendor.cb.checked) { var pre = pick(OUI).split(':'); var rest = [hex(2), hex(2), hex(2)]; return join6(pre.concat(rest)); } first = (first & 0xFC) | (randInt(2) ? 0 : 0); var o = []; for (var i = 0; i < 6; i++) o.push(hex(2)); return join6(o); }
    function join6(o) { var sep = macSep.value; if (sep === '.') return o.join('').replace(/(.{4})/g, '$1.').replace(/\.$/, ''); return o.join(sep); }

    var groups = ['Person', 'Contact', 'Tech', 'Misc'].map(function (g) { return { label: g, items: TYPES.filter(function (t) { return t.group === g; }).map(function (t) { return { id: t.id, label: t.label, title: t.desc }; }) }; });
    var pk = ui.picker(groups, function (id) { select(id); generate(); });
    cfg.appendChild(pk.el);
    root.appendChild(cfg);

    var io = ui.ioRow(true);
    var panel = el('div', { class: 'panel io-p' });
    var hdr = el('div', { class: 'panel-hdr' }); hdr.innerHTML = CK.iconSvg(I_USER, 12) + ' OUTPUT';
    var fill = el('span', { class: 'fill' }); var tb = el('span', { class: 'tb' });
    var genBtn = el('button', { class: 'prim enc' }, 'Generate');
    tb.appendChild(genBtn); tb.appendChild(ui.miniBtn('Copy', function () { CK.copy(ta.value); })); tb.appendChild(ui.miniBtn('Download', function () { CK.download(ta.value, 'fakedata.' + (fmtSel.value === 'plain' ? 'txt' : fmtSel.value)); }));
    hdr.appendChild(fill); hdr.appendChild(tb);
    var ta = el('textarea', { class: 'ta', readonly: 'readonly' });
    panel.appendChild(hdr); panel.appendChild(ta);
    io.appendChild(panel); root.appendChild(io);

    function select(id) { var t = get(id); if (!t) return; current = id; pk.setActive(id); ui.setSel(strip, t.label, t.group, t.desc); Object.keys(OPT_FIELDS).forEach(function (k) { OPT_FIELDS[k].forEach(function (f) { f.style.display = k === id ? '' : 'none'; }); }); if (id === 'email' && emailDomain.value !== 'custom') emailCustF.style.display = 'none'; }
    function generate() {
      var t = get(current), n = Math.max(1, Math.min(1000, +countInput.value || 1)), vals = [];
      for (var i = 0; i < n; i++) vals.push(t.fn());
      if (fmtSel.value === 'json') ta.value = JSON.stringify(vals.map(function (v) { var o = {}; o[current] = v; return o; }), null, 2);
      else if (fmtSel.value === 'csv') ta.value = current + '\n' + vals.map(function (v) { return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }).join('\n');
      else ta.value = vals.join('\n');
    }
    function doReset() { current = 'name'; countInput.value = '5'; fmtSel.value = 'plain'; select('name'); generate(); ctx.toast('Reset complete', 'success'); }

    genBtn.addEventListener('click', generate);
    countInput.addEventListener('input', generate);
    select(current); generate();

    return { reset: doReset, onKey: function (e) { if ((e.ctrlKey || e.metaKey) && String(e.key).toLowerCase() === 'g') { e.preventDefault(); generate(); } } };
  });
})();

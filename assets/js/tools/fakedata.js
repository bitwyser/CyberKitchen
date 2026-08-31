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
  function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

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
  // Real issuer prefixes (IIN) with correct lengths; each number is completed with a Luhn check digit
  var CARD_BRANDS = [['4', 16], ['51', 16], ['52', 16], ['53', 16], ['54', 16], ['55', 16], ['2221', 16], ['2720', 16], ['34', 15], ['37', 15], ['6011', 16], ['65', 16]];

  function uuid() { var b = new Uint8Array(16); crypto.getRandomValues(b); b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80; var h = []; for (var i = 0; i < 16; i++) h.push(b[i].toString(16).padStart(2, '0')); return h.slice(0, 4).join('') + '-' + h.slice(4, 6).join('') + '-' + h.slice(6, 8).join('') + '-' + h.slice(8, 10).join('') + '-' + h.slice(10, 16).join(''); }
  function luhn(prefix, len) { var num = prefix; while (num.length < len - 1) num += randInt(10); var sum = 0, alt = true; for (var i = num.length - 1; i >= 0; i--) { var d = +num[i]; if (alt) { d *= 2; if (d > 9) d -= 9; } sum += d; alt = !alt; } return num + ((10 - (sum % 10)) % 10); }
  var PHONE = { us: function () { return '+1 (' + digits(3) + ') ' + digits(3) + '-' + digits(4); }, uk: function () { return '+44 ' + digits(4) + ' ' + digits(6); }, de: function () { return '+49 ' + digits(3) + ' ' + digits(7); }, fr: function () { return '+33 ' + digits(1) + ' ' + digits(2) + ' ' + digits(2) + ' ' + digits(2) + ' ' + digits(2); }, jp: function () { return '+81 ' + digits(2) + '-' + digits(4) + '-' + digits(4); }, au: function () { return '+61 4' + digits(2) + ' ' + digits(3) + ' ' + digits(3); }, in: function () { return '+91 ' + digits(5) + ' ' + digits(5); }, br: function () { return '+55 (' + digits(2) + ') ' + digits(5) + '-' + digits(4); } };
  var PHONE_CODE = { us: '+1', uk: '+44', de: '+49', fr: '+33', jp: '+81', au: '+61', in: '+91', br: '+55' };

  var I_USER = '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>';
  var I_SHARE = '<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>';
  var I_RESET = '<path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/>';
  function b64uEnc(s) { var b = new TextEncoder().encode(s), x = ''; b.forEach(function (c) { x += String.fromCharCode(c); }); return btoa(x).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64uDec(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; var bin = atob(s), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return new TextDecoder().decode(a); }

  CK.registerTool('fakedata', function (root, ctx) {
    var ui = CK.ui, el = CK.el, current = 'name';

    root.appendChild(ui.head('Fake Data', 'generator'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_USER);
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var countRange = el('input', { type: 'range', class: 'slim', min: '1', max: '100', value: '5' });
    var countInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '1000', value: '5' });
    var countRow = el('div', { class: 'length-row' }); countRow.appendChild(countRange); countRow.appendChild(countInput);
    function setCount(v) { countRange.value = v; countInput.value = v; }
    var fmtSel = ui.select([['plain', 'Plain'], ['json', 'JSON'], ['csv', 'CSV']].map(function (a) { return { value: a[0], label: a[1] }; }), function () { updateDownloadName(); generate(); }, 'plain');
    var opt = el('div', { class: 'cfg-form' });

    // per-type option controls (built once, shown/hidden per type)
    var emailDomain = ui.select([['random', 'Random']].concat(DOMAINS.map(function (d) { return [d, d]; })).concat([['custom', 'Custom...']]).map(mk), function (v) { emailCustom.style.display = v === 'custom' ? '' : 'none'; generate(); }, 'random');
    var emailCustom = el('input', { class: 'inp sm', type: 'text', placeholder: 'domain.com' }); emailCustom.style.display = 'none'; emailCustom.addEventListener('input', generate);
    var emailField = ui.field('Domain', emailDomain), emailCustF = ui.field('Custom domain', emailCustom);
    var phoneCountry = ui.select([['random', 'Random']].concat(Object.keys(PHONE).map(function (k) { return [k, k.toUpperCase()]; })).map(mk), generate, 'in');
    var phoneField = ui.field('Country', phoneCountry);
    var userSrc = ui.select([['builtin', 'Built-in'], ['custom', 'My words'], ['mixed', 'Mix both']].map(mk), function () { userCustF.style.display = (userSrc.value === 'custom' || userSrc.value === 'mixed') ? '' : 'none'; generate(); }, 'builtin');
    var userCustom = el('input', { class: 'inp sm', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'ninja, cyber, storm' });
    userCustom.addEventListener('input', generate);
    var userStyle = ui.select([['word_num', 'word123'], ['word_word', 'word_word'], ['camel', 'CamelCase'], ['handle', '_handle_'], ['name', 'firstname'], ['letters', 'random letters']].map(mk), generate, 'word_num');
    var userF1 = ui.field('Word source', userSrc), userCustF = ui.field('Your words', userCustom), userF2 = ui.field('Style', userStyle);
    userCustF.style.display = 'none';
    var ipType = ui.select([['any', 'Any'], ['private', 'Private'], ['public', 'Public'], ['loopback', 'Loopback'], ['multicast', 'Multicast']].map(mk), generate, 'any');
    var ipFmt = ui.select([['plain', 'Plain'], ['cidr', 'With CIDR'], ['port', 'With port']].map(mk), generate, 'plain');
    var ipF1 = ui.field('Range', ipType), ipFmtF = ui.field('Format', ipFmt);
    var macSep = ui.select([[':', 'Colon'], ['-', 'Dash'], ['.', 'Dot (Cisco)'], ['', 'None']].map(mk), generate, ':');
    var macVendor = ui.toggle('Real OUI prefix', false, generate);
    var macF1 = ui.field('Separator', macSep), macF2 = ui.field('Vendor', macVendor.wrap);
    var uuidUpper = ui.toggle('Uppercase', false, generate);
    var uuidF = ui.field('Case', uuidUpper.wrap);
    var loremRange = el('input', { type: 'range', class: 'slim', min: '3', max: '40', value: '10' });
    var loremNum = el('input', { class: 'inp sm', type: 'number', min: '1', max: '100', value: '10' });
    var loremRow = el('div', { class: 'length-row' }); loremRow.appendChild(loremRange); loremRow.appendChild(loremNum);
    loremRange.addEventListener('input', function () { loremNum.value = loremRange.value; generate(); });
    loremNum.addEventListener('input', function () { loremRange.value = loremNum.value; generate(); });
    var loremF = ui.field('Words', loremRow);
    var dateFrom = el('input', { class: 'inp sm', type: 'date', value: '1990-01-01' });
    var dateTo = el('input', { class: 'inp sm', type: 'date', value: '2025-12-31' });
    dateFrom.addEventListener('input', generate); dateTo.addEventListener('input', generate);
    var dateF1 = ui.field('From', dateFrom), dateF2 = ui.field('To', dateTo);
    // Additional per-type options carried over from the standalone Fake Data tool
    var emailFmt = ui.select([['first.last', 'first.last'], ['flast', 'flast'], ['firstlast', 'firstlast'], ['random', 'random']].map(mk), generate, 'first.last');
    var emailNum = ui.select([['none', 'None'], ['sometimes', 'Sometimes'], ['always', 'Always']].map(mk), generate, 'none');
    var emailFmtF = ui.field('Format', emailFmt), emailNumF = ui.field('Number', emailNum);
    var phoneStyle = ui.select([['formatted', 'Formatted'], ['digits', 'Digits only'], ['e164', 'E.164']].map(mk), generate, 'formatted');
    var phoneStyleF = ui.field('Style', phoneStyle);
    var userSep = ui.select([['_', '_ underscore'], ['.', '. dot'], ['', 'none']].map(mk), generate, '_');
    var userMin = el('input', { class: 'inp sm', type: 'number', min: '3', max: '32', value: '6' });
    var userMax = el('input', { class: 'inp sm', type: 'number', min: '3', max: '64', value: '14' });
    userMin.addEventListener('input', generate); userMax.addEventListener('input', generate);
    var userSepF = ui.field('Separator', userSep), userMinF = ui.field('Min length', userMin), userMaxF = ui.field('Max length', userMax);
    var uuidVer = ui.select([['1', 'v1 (time)'], ['4', 'v4 (random)'], ['7', 'v7 (unix-ts)']].map(mk), generate, '4');
    var uuidFmt = ui.select([['hyphen', 'with hyphens'], ['compact', 'compact'], ['braced', '{braced}']].map(mk), generate, 'hyphen');
    var uuidVerF = ui.field('Version', uuidVer), uuidFmtF = ui.field('Format', uuidFmt);
    var ipv6Type = ui.select([['full', 'Full'], ['compressed', 'Compressed'], ['link-local', 'Link-local'], ['loopback', 'Loopback']].map(mk), generate, 'full');
    var ipv6Case = ui.select([['lower', 'lowercase'], ['upper', 'UPPERCASE']].map(mk), generate, 'lower');
    var ipv6TypeF = ui.field('Type', ipv6Type), ipv6CaseF = ui.field('Case', ipv6Case);
    var macCase = ui.select([['upper', 'UPPERCASE'], ['lower', 'lowercase']].map(mk), generate, 'upper');
    var macType = ui.select([['any', 'Any'], ['unicast', 'Unicast'], ['multicast', 'Multicast'], ['locally', 'Locally adm.']].map(mk), generate, 'any');
    var macCaseF = ui.field('Case', macCase), macTypeF = ui.field('Type', macType);
    function mk(a) { return { value: a[0], label: a[1] }; }
    var OPT_FIELDS = {
      email: [emailField, emailCustF, emailFmtF, emailNumF],
      phone: [phoneField, phoneStyleF],
      username: [userF1, userCustF, userF2, userSepF, userMinF, userMaxF],
      ipv4: [ipF1, ipFmtF],
      ipv6: [ipv6TypeF, ipv6CaseF],
      mac: [macF1, macF2, macCaseF, macTypeF],
      uuid: [uuidF, uuidVerF, uuidFmtF],
      date: [dateF1, dateF2],
      lorem: [loremF]
    };
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
      { id: 'card', label: 'Credit Card', group: 'Tech', desc: 'Luhn-valid test card', fn: genCard },
      { id: 'color', label: 'Color Hex', group: 'Tech', desc: 'Random hex color', fn: function () { return '#' + hex(6); } },
      { id: 'date', label: 'Date', group: 'Misc', desc: 'Random ISO date in a range', fn: genDate },
      { id: 'lorem', label: 'Lorem', group: 'Misc', desc: 'Lorem ipsum with word count', fn: genLorem }
    ];
    function get(id) { for (var i = 0; i < TYPES.length; i++) if (TYPES[i].id === id) return TYPES[i]; return null; }

    function genEmail() {
      var d = emailDomain.value === 'random' ? pick(DOMAINS) : emailDomain.value === 'custom' ? (emailCustom.value.trim() || 'example.com') : emailDomain.value;
      var f = pick(FIRST).toLowerCase(), l = pick(LAST).toLowerCase(), fmt = emailFmt.value, local;
      if (fmt === 'first.last') local = f + '.' + l;
      else if (fmt === 'flast') local = f[0] + l;
      else if (fmt === 'firstlast') local = f + l;
      else local = pick(ADJ) + pick(NOUN) + (1 + randInt(99));
      var np = emailNum.value, num = np === 'always' ? (1 + randInt(999)) : (np === 'sometimes' && randInt(2) === 0 ? (1 + randInt(99)) : '');
      return local + (num || '') + '@' + d;
    }
    function wordPool(fallback) {
      var src = userSrc.value, raw = (userCustom.value || '').split(',').map(function (w) { return w.trim().toLowerCase(); }).filter(Boolean);
      if (src === 'custom') return raw.length ? raw : fallback;
      if (src === 'mixed') return raw.length ? fallback.concat(raw) : fallback;
      return fallback;
    }
    function genUser() {
      var style = userStyle.value, sep = userSep.value, adjs = wordPool(ADJ), nns = wordPool(NOUN), u;
      if (style === 'word_num') u = pick(adjs) + sep + pick(nns) + (10 + randInt(990));
      else if (style === 'word_word') u = pick(adjs) + sep + pick(nns);
      else if (style === 'camel') u = cap(pick(adjs)) + cap(pick(nns));
      else if (style === 'handle') u = '_' + pick(adjs) + sep + pick(nns) + '_';
      else if (style === 'name') u = pick(FIRST).toLowerCase() + sep + pick(LAST).toLowerCase() + (1 + randInt(99));
      else { u = ''; for (var i = 0; i < 6; i++) u += 'abcdefghijklmnopqrstuvwxyz'[randInt(26)]; }
      var mn = Math.max(1, +userMin.value || 6), mx = Math.max(mn, +userMax.value || 14);
      while (u.length < mn) u += randInt(10);
      if (u.length > mx) u = u.slice(0, mx);
      return u;
    }
    function genPhone() {
      var c = phoneCountry.value === 'random' ? pick(Object.keys(PHONE)) : phoneCountry.value, style = phoneStyle.value;
      if (style === 'formatted') return PHONE[c]();
      var d = digits(10);
      if (style === 'e164') return (PHONE_CODE[c] || '+1') + d;
      return d;
    }
    function genUuid() {
      var ver = uuidVer.value, u;
      if (ver === '1') { var now = Date.now(); u = (now & 0xffffffff).toString(16).padStart(8, '0') + '-' + ((now / 0x100000000 | 0) & 0xffff).toString(16).padStart(4, '0') + '-' + (((now / 0x100000000 | 0) >> 16 & 0x0fff) | 0x1000).toString(16) + '-' + (8 + randInt(4)).toString(16) + hex(3) + '-' + hex(12); }
      else if (ver === '7') { var mh = Date.now().toString(16).padStart(12, '0'); u = mh.slice(0, 8) + '-' + mh.slice(8, 12) + '-7' + hex(3) + '-' + (8 + randInt(4)).toString(16) + hex(3) + '-' + hex(12); }
      else u = uuid();
      if (uuidUpper.cb.checked) u = u.toUpperCase();
      if (uuidFmt.value === 'compact') u = u.replace(/-/g, '');
      else if (uuidFmt.value === 'braced') u = '{' + u + '}';
      return u;
    }
    function genIpv4() {
      var o, t = ipType.value;
      if (t === 'private') o = pick([[10, randInt(256), randInt(256), randInt(256)], [172, 16 + randInt(16), randInt(256), randInt(256)], [192, 168, randInt(256), randInt(256)]]);
      else if (t === 'loopback') o = [127, randInt(256), randInt(256), 1 + randInt(254)];
      else if (t === 'multicast') o = [224 + randInt(16), randInt(256), randInt(256), randInt(256)];
      else if (t === 'public') { do { o = [1 + randInt(223), randInt(256), randInt(256), 1 + randInt(254)]; } while (o[0] === 10 || o[0] === 127 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168) || o[0] >= 224); }
      else o = [randInt(256), randInt(256), randInt(256), randInt(256)];
      var ip = o.join('.'), fmt = ipFmt.value;
      if (fmt === 'cidr') return ip + '/' + (8 + randInt(25));
      if (fmt === 'port') return ip + ':' + (1024 + randInt(64512));
      return ip;
    }
    function genIpv6() {
      var type = ipv6Type.value, u;
      if (type === 'loopback') u = '0000:0000:0000:0000:0000:0000:0000:0001';
      else if (type === 'link-local') { var g = ['fe80']; for (var i = 0; i < 7; i++) g.push(hex(4)); u = g.join(':'); }
      else {
        var gs = []; for (var j = 0; j < 8; j++) gs.push(hex(4)); u = gs.join(':');
        if (type === 'compressed') { u = u.replace(/(:?0000){2,}/, function (m) { return m.replace(/0000/g, '').replace(/::+/, '::').replace(/^:/, '::').replace(/:$/, '::'); }); if (u.indexOf('::') < 0) u = u.replace(/:0000/, '::').replace(/0000:/, '::'); }
      }
      return ipv6Case.value === 'upper' ? u.toUpperCase() : u;
    }
    function genMac() {
      var type = macType.value, first;
      if (type === 'unicast') first = (randInt(256) & 0xFE) & 0xFD;
      else if (type === 'multicast') first = randInt(256) | 0x01;
      else if (type === 'locally') first = (randInt(256) | 0x02) & 0xFE;
      else first = randInt(256);
      var bytes = [first]; for (var i = 1; i < 6; i++) bytes.push(randInt(256));
      if (macVendor.cb.checked) { var pre = pick(OUI).split(':'); for (var k = 0; k < 3; k++) bytes[k] = parseInt(pre[k], 16); }
      var h = bytes.map(function (b) { return b.toString(16).padStart(2, '0'); }), sep = macSep.value, mac;
      if (sep === ':') mac = h.join(':'); else if (sep === '-') mac = h.join('-'); else if (sep === '.') mac = h[0] + h[1] + '.' + h[2] + h[3] + '.' + h[4] + h[5]; else mac = h.join('');
      return macCase.value === 'upper' ? mac.toUpperCase() : mac.toLowerCase();
    }
    function genCard() { var t = pick(CARD_BRANDS); return luhn(t[0], t[1]).replace(/(.{4})/g, '$1 ').trim(); }
    function genDate() {
      var from = Date.parse(dateFrom.value), to = Date.parse(dateTo.value);
      if (isNaN(from)) from = Date.parse('1990-01-01'); if (isNaN(to)) to = Date.parse('2025-12-31');
      if (to < from) { var t = from; from = to; to = t; }
      var days = Math.max(0, Math.floor((to - from) / 86400000));
      return new Date(from + randInt(days + 1) * 86400000).toISOString().slice(0, 10);
    }
    function genLorem() { var n = Math.max(1, Math.min(200, +loremNum.value || 10)), w = []; for (var i = 0; i < n; i++) w.push(pick(LOREM)); var s = w.join(' '); return s.charAt(0).toUpperCase() + s.slice(1) + '.'; }

    var groups = ['Person', 'Contact', 'Tech', 'Misc'].map(function (g) { return { label: g, items: TYPES.filter(function (t) { return t.group === g; }).map(function (t) { return { id: t.id, label: t.label, title: t.desc }; }) }; });
    var pk = ui.picker(groups, function (id) { select(id); generate(); });
    // Column 1: the data-type picker. Column 2: settings (Count | Format on top, then per-type options).
    var grid = el('div', { class: 'fd-grid' });
    var colL = el('div', { class: 'col' }); colL.appendChild(pk.el);
    var colR = el('div', { class: 'col' });
    var topRow = el('div', { class: 'fd-top' });
    topRow.appendChild(ui.field('Count', countRow)); topRow.appendChild(ui.field('Format', fmtSel));
    colR.appendChild(topRow); colR.appendChild(opt);
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow(true);
    var outCfg = { title: 'OUTPUT', icon: I_USER, readonly: true, primaries: [{ label: 'Generate', cls: 'enc', onClick: generate }], actions: ['copy', 'download'], downloadName: 'fakedata.txt' };
    var outP = ui.textPanel(outCfg);
    var ta = outP.ta;
    io.appendChild(outP.panel); root.appendChild(io);
    function updateDownloadName() { outCfg.downloadName = 'fakedata.' + (fmtSel.value === 'plain' ? 'txt' : fmtSel.value); }

    function select(id) { var t = get(id); if (!t) return; current = id; pk.setActive(id); ui.setSel(strip, t.label, t.group, t.desc); Object.keys(OPT_FIELDS).forEach(function (k) { OPT_FIELDS[k].forEach(function (f) { f.style.display = k === id ? '' : 'none'; }); }); if (id === 'email' && emailDomain.value !== 'custom') emailCustF.style.display = 'none'; }
    function generate() {
      var t = get(current), n = Math.max(1, Math.min(1000, +countInput.value || 1)), vals = [];
      for (var i = 0; i < n; i++) vals.push(t.fn());
      if (fmtSel.value === 'json') ta.value = JSON.stringify(vals.map(function (v) { var o = {}; o[current] = v; return o; }), null, 2);
      else if (fmtSel.value === 'csv') ta.value = current + '\n' + vals.map(function (v) { return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }).join('\n');
      else ta.value = vals.join('\n');
    }
    function doReset() { current = 'name'; setCount(5); fmtSel.value = 'plain'; updateDownloadName(); select('name'); generate(); ctx.toast('Reset complete', 'success'); }
    function doShare() { CK.copy(location.href.split('#')[0] + '#tool=fakedata&s=' + b64uEnc(JSON.stringify({ t: current, c: +countInput.value, f: fmtSel.value }))); }

    countRange.addEventListener('input', function () { countInput.value = countRange.value; generate(); });
    countInput.addEventListener('input', function () { countRange.value = countInput.value; generate(); });
    countInput.addEventListener('change', function () { if (+countInput.value <= 100) countInput.value = countRange.value; });
    var sm = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (sm) { try { var st = JSON.parse(b64uDec(sm[1])); if (st.t && get(st.t)) current = st.t; if (st.c) setCount(st.c); if (st.f) fmtSel.value = st.f; } catch (e) { } }
    updateDownloadName();
    select(current); generate();

    return { reset: doReset, onKey: function (e) { if ((e.ctrlKey || e.metaKey) && String(e.key).toLowerCase() === 'g') { e.preventDefault(); generate(); } } };
  });
})();

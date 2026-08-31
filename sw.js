/*
   sw.js - CyberKitchen service worker
   Precaches the whole app so it runs fully offline after first load.
   Cache-first for known assets; network fallback populates the cache;
   navigations fall back to the app shell when offline.
   Relative paths keep it working under any base path (e.g. /CyberKitchen/).
*/
var CACHE = 'cyberkitchen-v3';
var ASSETS = [
  './',
  'index.html',
  'manifest.webmanifest',
  'assets/icon.svg',
  'assets/css/dashboard.css',
  'assets/js/core.js',
  'assets/js/ui.js',
  'assets/js/vendor/hashlib.js',
  'assets/js/vendor/crypto-js.min.js',
  'assets/js/vendor/bcrypt.min.js',
  'assets/js/vendor/argon2-bundled.min.js',
  'assets/js/tools/encode.js',
  'assets/js/tools/number.js',
  'assets/js/tools/classical.js',
  'assets/js/tools/password.js',
  'assets/js/tools/fakedata.js',
  'assets/js/tools/hash.js',
  'assets/js/tools/aes.js',
  'assets/js/tools/rsa.js',
  'assets/js/tools/bcrypt.js',
  'assets/js/tools/argon2.js'
];

self.addEventListener('install', function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(ASSETS); }).then(function () { return self.skipWaiting(); }));
});

self.addEventListener('activate', function (e) {
  e.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); }));
  }).then(function () { return self.clients.claim(); }));
});

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET') return;
  e.respondWith(caches.match(req).then(function (hit) {
    if (hit) return hit;
    return fetch(req).then(function (res) {
      if (res && res.status === 200 && res.type === 'basic') {
        var copy = res.clone();
        caches.open(CACHE).then(function (c) { c.put(req, copy); });
      }
      return res;
    }).catch(function () {
      if (req.mode === 'navigate') return caches.match('index.html').then(function (r) { return r || caches.match('./'); });
    });
  }));
});

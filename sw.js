/* Service worker: stale-while-revalidate app shell, network-first encrypted data. */
const VERSION = 'v2';
const SHELL = ['./', 'index.html', 'app.js', 'sync.js', 'styles.css', 'manifest.webmanifest', 'icon.svg', 'icon-192.png', 'icon-512.png'];
self.addEventListener('install', (e) => {
  e.waitUntil(caches.open('shell-' + VERSION).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(
    keys.filter((k) => k !== 'shell-' + VERSION && k !== 'data').map((k) => caches.delete(k))
  )).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  if (url.pathname.endsWith('/data.enc.json')) {
    e.respondWith(fetch(e.request).then((r) => {
      if (r.ok) { const copy = r.clone(); caches.open('data').then((c) => c.put('data.enc.json', copy)); }
      return r;
    }).catch(() => caches.open('data').then((c) => c.match('data.enc.json'))));
    return;
  }
  // stale-while-revalidate: serve cached shell instantly, refresh it in the background
  e.respondWith(caches.open('shell-' + VERSION).then((c) => c.match(e.request, { ignoreSearch: true }).then((hit) => {
    const net = fetch(e.request).then((r) => { if (r.ok) c.put(e.request, r.clone()); return r; }).catch(() => hit);
    return hit || net;
  })));
});

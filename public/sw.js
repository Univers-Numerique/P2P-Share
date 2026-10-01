const CACHE = 'p2pshare-v3';
const ASSETS = [
  '/', '/style.css', '/app.js', '/manifest.json', '/icon-192.png', '/icon-512.png', '/icon-maskable-512.png',
  '/socket.io/socket.io.min.js', '/vendor/peerjs.min.js', '/vendor/qrcode.min.js', '/vendor/jszip.min.js', '/vendor/jsQR.js'
];
const ASSET_PATHS = new Set(ASSETS);

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
  ));
  self.clients.claim();
});

// Network first (always fresh code), cache only as an offline fallback
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;
  const isPage = req.mode === 'navigate';
  if (!isPage && !ASSET_PATHS.has(url.pathname)) return;

  const key = isPage ? '/' : url.pathname;
  e.respondWith(
    fetch(req)
      .then(res => {
        if (res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(key, copy));
        }
        return res;
      })
      .catch(() => caches.match(key))
  );
});

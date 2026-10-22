// Altas de Obra: guarda la app en la computadora para que funcione sin internet.
const CACHE = "altas-obra-v1";
const FILES = ["./", "index.html", "manifest.webmanifest", "vendor/exceljs.min.js", "vendor/fonts/barlow-semi-condensed-latin-500-normal.woff2", "vendor/fonts/barlow-semi-condensed-latin-600-normal.woff2", "vendor/fonts/source-sans-3-latin-400-normal.woff2", "vendor/fonts/source-sans-3-latin-600-normal.woff2", "vendor/fonts/jetbrains-mono-latin-400-normal.woff2", "vendor/fonts/jetbrains-mono-latin-500-normal.woff2", "icons/icon-192.png", "icons/icon-512.png", "icons/maskable-512.png", "icons/apple-touch-icon.png", "icons/favicon-32.png"];
self.addEventListener("install", e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES)).then(() => self.skipWaiting())); });
self.addEventListener("activate", e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;
  // Primero intenta la versión nueva (si hay internet); si no, usa la guardada.
  e.respondWith(
    fetch(e.request).then(r => { if (r && r.ok && new URL(e.request.url).origin === location.origin) { const cp = r.clone(); caches.open(CACHE).then(c => c.put(e.request, cp)); } return r; })
      .catch(() => caches.match(e.request, {ignoreSearch: true}).then(m => m || caches.match("index.html")))
  );
});

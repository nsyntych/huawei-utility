// Huawei Password & Configuration Utility - Service Worker
// Enables 100% Offline Capability and PWA Installation

const CACHE_NAME = 'hw-util-v1.0.2';

const PRECACHE_ASSETS = [
	'./',
	'./index.html',
	'./manifest.json',
	'./favicon.svg',
	'./favicon.ico',
	'./icons/icon-192.png',
	'./icons/icon-512.png',
	'./icons/apple-touch-icon.png',
	'./css/style.css',
	'./js/constants.js',
	'./js/index.js',
	'./js/worker.js',
	'./js/vendor/crypto-js.min.js',
	'./js/vendor/enc-hex.min.js',
	'./js/vendor/he.min.js'
];

// Install: Pre-cache all core static assets for instant offline execution
self.addEventListener('install', (event) => {
	event.waitUntil(
		caches.open(CACHE_NAME).then((cache) => {
			return cache.addAll(PRECACHE_ASSETS);
		}).then(() => self.skipWaiting())
	);
});

// Activate: Clean up old cache versions and claim clients immediately
self.addEventListener('activate', (event) => {
	event.waitUntil(
		caches.keys().then((cacheNames) => {
			return Promise.all(
				cacheNames.map((name) => {
					if (name !== CACHE_NAME) {
						return caches.delete(name);
					}
				})
			);
		}).then(() => self.clients.claim())
	);
});

// Fetch: Network-First with Cache Fallback
self.addEventListener('fetch', (event) => {
	if (event.request.method !== 'GET') return;

	event.respondWith(
		fetch(event.request)
			.then((networkResponse) => {
				if (networkResponse && networkResponse.status === 200) {
					const responseToCache = networkResponse.clone();
					caches.open(CACHE_NAME).then((cache) => {
						cache.put(event.request, responseToCache);
					});
				}
				return networkResponse;
			})
			.catch(() => {
				return caches.match(event.request).then((cachedResponse) => {
					if (cachedResponse) {
						return cachedResponse;
					}
					if (event.request.mode === 'navigate') {
						return caches.match('./index.html');
					}
				});
			})
	);
});

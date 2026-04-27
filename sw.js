// GE Service Worker — push notifications + offline cache

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(clients.claim()));

self.addEventListener('push', event => {
  if (!event.data) return;
  let data;
  try { data = event.data.json(); } catch { data = { title: 'GE', body: event.data.text() }; }
  event.waitUntil(
    self.registration.showNotification(data.title || 'GE', {
      body:    data.body  || '',
      icon:    '/ge-icon-192.png',
      badge:   '/ge-icon-192.png',
      tag:     data.tag   || 'ge-push',
      data:    { action: data.action || 'open', url: data.url || '/' },
      requireInteraction: false,
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const notifData = event.notification.data || {};
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const client of list) {
        if ('focus' in client) {
          client.focus();
          client.postMessage({ type: 'ge-push-click', action: notifData.action || 'open' });
          return;
        }
      }
      return clients.openWindow(notifData.url || '/');
    })
  );
});

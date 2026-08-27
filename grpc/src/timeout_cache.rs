/*
 *
 * Copyright 2026 gRPC authors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

use crate::rt::GrpcRuntime;
use crate::rt::TaskHandle;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct ExpirationEntry<K> {
    expires_at: Instant,
    key: K,
}

struct CacheItem<V> {
    value: V,
    expires_at: Instant,
}

/// A thread-safe, in-memory key-value cache where entries expire after a fixed
/// timeout.
///
/// A background task handles automatic eviction of expired entries.
pub(crate) struct TimeoutCache<K, V> {
    inner: Arc<Mutex<CacheInner<K, V>>>,
    notify: Arc<Notify>,
    timeout: Duration,
    driver_handle: Box<dyn TaskHandle>,
}

impl<K, V> Drop for TimeoutCache<K, V> {
    fn drop(&mut self) {
        self.driver_handle.abort();
    }
}

struct CacheInner<K, V> {
    store: HashMap<K, CacheItem<V>>,
    expirations: BTreeSet<ExpirationEntry<K>>,
}

impl<K: Ord + Hash + Clone + Send + 'static, V: Send + 'static> TimeoutCache<K, V> {
    /// Creates a new [`TimeoutCache`] with the specified entry expiration
    /// `timeout` and async runtime.
    pub fn new(timeout: Duration, rt: GrpcRuntime) -> Self {
        let inner = Arc::new(Mutex::new(CacheInner {
            store: HashMap::new(),
            expirations: BTreeSet::new(),
        }));
        let notify = Arc::new(Notify::new());

        let inner_clone = inner.clone();
        let notify_clone = notify.clone();
        let rt_clone = rt.clone();

        // Driver future that performs the background eviction loop.
        let driver = async move {
            loop {
                let next_expiration = {
                    let guard = inner_clone.lock().unwrap();
                    guard.expirations.first().map(|entry| entry.expires_at)
                };

                let Some(next_expiration) = next_expiration else {
                    notify_clone.notified().await;
                    continue;
                };

                tokio::select! {
                    _ = rt_clone.sleep(next_expiration.saturating_duration_since(Instant::now())) => {
                        let mut guard = inner_clone.lock().unwrap();
                        let now = Instant::now();
                        while let Some(top) = guard.expirations.first() && top.expires_at <= now {
                            let entry = guard.expirations.pop_first().unwrap();
                            guard.store.remove(&entry.key);
                        }
                    }
                    _ = notify_clone.notified() => {
                        // Woken up because a new earlier expiration was added
                        // or an entry was removed.
                    }
                }
            }
        };

        Self {
            inner: inner.clone(),
            notify: notify.clone(),
            timeout,
            driver_handle: rt.spawn(Box::pin(driver)),
        }
    }

    /// Inserts a key-value pair into the cache with a fresh expiration
    /// deadline.
    ///
    /// If the key already exists, its value and expiration deadline are
    /// updated.
    ///
    /// Returns `true` if an existing entry was overwritten, or `false` if it
    /// was newly inserted.
    pub(crate) fn insert(&self, key: K, value: V) -> bool {
        let expires_at = Instant::now() + self.timeout;
        let mut guard = self.inner.lock().unwrap();

        let overwritten = if let Some(old) = guard
            .store
            .insert(key.clone(), CacheItem { value, expires_at })
        {
            guard.expirations.remove(&ExpirationEntry {
                expires_at: old.expires_at,
                key: key.clone(),
            });
            true
        } else {
            false
        };
        guard
            .expirations
            .insert(ExpirationEntry { expires_at, key });

        self.notify.notify_one();
        overwritten
    }

    /// Removes a key and its associated value from the cache, canceling its pending expiration.
    ///
    /// Returns `Some(V)` if the key was present in the cache, or `None` otherwise.
    pub(crate) fn remove(&self, key: &K) -> Option<V> {
        let mut guard = self.inner.lock().unwrap();
        if let Some(item) = guard.store.remove(key) {
            guard.expirations.remove(&ExpirationEntry {
                expires_at: item.expires_at,
                key: key.clone(),
            });
            self.notify.notify_one();
            return Some(item.value);
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        let guard = self.inner.lock().unwrap();
        assert_eq!(guard.store.len(), guard.expirations.len());
        guard.store.len()
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::sleep;

    use super::*;
    use crate::rt::default_runtime;

    #[tokio::test]
    async fn test_insert_and_remove() {
        let cache = TimeoutCache::new(Duration::from_secs(60), default_runtime());
        assert!(!cache.insert("a", 1));
        assert!(!cache.insert("b", 2));
        assert!(!cache.insert("c", 3));
        assert_eq!(cache.len(), 3);

        // Remove the middle entry
        assert_eq!(cache.remove(&"b"), Some(2));
        assert_eq!(cache.remove(&"b"), None);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.remove(&"a"), Some(1));
        assert_eq!(cache.remove(&"c"), Some(3));
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_overwrite_removes_old_expiration() {
        let cache = TimeoutCache::new(Duration::from_secs(60), default_runtime());
        assert!(!cache.insert("key1", 42));

        sleep(Duration::from_secs(59)).await;
        assert!(cache.insert("key1", 84));

        sleep(Duration::from_secs(59)).await;
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.remove(&"key1"), Some(84));
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_expiration() {
        let cache = TimeoutCache::new(Duration::from_secs(60), default_runtime());
        assert!(!cache.insert("key1", 100));

        sleep(Duration::from_secs(10)).await; // t=10s
        assert!(!cache.insert("key2", 200));
        assert_eq!(cache.len(), 2);

        sleep(Duration::from_secs(49)).await; // t=59s
        assert_eq!(cache.len(), 2);

        sleep(Duration::from_secs(2)).await; // t=61s
        assert_eq!(cache.remove(&"key1"), None);
        assert_eq!(cache.len(), 1);

        sleep(Duration::from_secs(10)).await; // t=71s
        assert_eq!(cache.remove(&"key2"), None);
        assert_eq!(cache.len(), 0);
    }
}

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

//! Recording of the loads reported to an LRS server.
//!
//! Load balancing policies get recorders from a [`LoadStore`]: a
//! [`ClusterLocalityStats`] for each locality they send calls to, and a
//! [`ClusterLevelStats`] for each cluster they drop calls for.
//!
//! # Design
//!
//! The counters of each recorder are shared, through an [`Arc`], between the
//! recorder (and its clones and call trackers) and a registry of all the
//! counters for one LRS server. Getting a recorder briefly locks the registry;
//! recording on it doesn't, except for categorized drops and backend metrics,
//! which lock the recorder's own maps. Dropping a recorder only decrements the
//! reference count: it doesn't lock anything or send a message.
//!
//! The LRS worker builds each load report while holding the registry lock.
//! Entries whose recorders have all been dropped are pruned then, lazily: if
//! the registry holds the only reference to some counters, no recorder for
//! them exists, and none can be created while the lock is held. That is
//! checked *before* taking the final snapshot of the counters, so no counts
//! are lost.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::mem;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::sync::Weak;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;
use std::time::Instant;

use crate::lrs::backend_metrics::BackendMetricPropagation;
use crate::lrs::backend_metrics::BackendMetrics;
use crate::lrs::message::ClusterStats;
use crate::lrs::message::DroppedRequests;
use crate::lrs::message::EndpointLoadMetricStats;
use crate::lrs::message::UnnamedEndpointLoadMetricStats;
use crate::lrs::message::UpstreamLocalityStats;
use crate::lrs::worker::WorkerHandle;
use crate::message::Locality;

/// Locks `mutex`, ignoring poisoning: the data protected by the mutexes in
/// this module is left consistent between operations, even if a thread
/// panicked while holding the lock.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Creates recorders for loads reported to one LRS server.
///
/// Cheap to clone. Reporting to the server continues while any `LoadStore`
/// for it, or any recorder or [`CallTracker`] created from one, exists, so
/// that calls in progress when the last `LoadStore` is dropped are still
/// reported. Getting a recorder briefly locks a registry shared with the LRS
/// worker. Recording call counts and uncategorized drops is lock-free;
/// categorized drops and backend metrics take a short per-recorder lock.
/// Recorders still work after reporting has stopped, but their loads are never
/// reported.
#[derive(Clone)]
pub struct LoadStore {
    inner: Arc<LoadStoreInner>,
}

impl fmt::Debug for LoadStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadStore").finish_non_exhaustive()
    }
}

/// State shared by all the clones of a [`LoadStore`].
pub(super) struct LoadStoreInner {
    /// Shared with the worker's `LoadReporter`. The worker outlives every
    /// `LoadStoreInner` (see `_worker`), so this keeps the registry alive
    /// only if the worker task ends abnormally, e.g. panics.
    registry: Arc<Mutex<Registry>>,
    /// Keeps the LRS worker for the server running: it holds the only strong
    /// sender of the worker's queue, so dropping the last reference to this
    /// `LoadStoreInner` closes the queue and stops the worker.
    _worker: WorkerHandle,
}

impl LoadStore {
    /// Returns a reference to this store that doesn't keep it, or the
    /// worker, alive.
    pub(super) fn downgrade(&self) -> Weak<LoadStoreInner> {
        Arc::downgrade(&self.inner)
    }

    /// Returns the store referenced by `weak`, if it's still alive.
    pub(super) fn upgrade(weak: &Weak<LoadStoreInner>) -> Option<Self> {
        weak.upgrade().map(|inner| Self { inner })
    }

    /// Returns a recorder for cluster-level stats, such as dropped calls.
    pub fn cluster_level_stats(
        &self,
        cluster_name: &str,
        eds_service_name: &str,
    ) -> ClusterLevelStats {
        let counters = lock(&self.inner.registry)
            .entry(cluster_name, eds_service_name)
            .cluster_level
            .get_or_insert_with(Arc::default)
            .clone();
        ClusterLevelStats {
            counters,
            _store: self.inner.clone(),
        }
    }

    /// Returns a recorder for calls sent to endpoints in `locality`.
    ///
    /// `propagation` selects which backend metrics passed to
    /// [`CallTracker::finish_with_metrics`] are recorded. Recorders for the
    /// same locality share counters even if their configs differ, as while a
    /// cluster update is rolled out.
    pub fn locality_stats(
        &self,
        cluster_name: &str,
        eds_service_name: &str,
        locality: &Locality,
        propagation: Arc<BackendMetricPropagation>,
    ) -> ClusterLocalityStats {
        let counters = {
            let mut registry = lock(&self.inner.registry);
            let localities = &mut registry.entry(cluster_name, eds_service_name).localities;
            // Look up before inserting, to clone the locality only when
            // creating new counters.
            match localities.get(locality) {
                Some(counters) => counters.clone(),
                None => localities.entry(locality.clone()).or_default().clone(),
            }
        };
        ClusterLocalityStats {
            recorder: Arc::new(LocalityRecorder {
                counters,
                propagation,
                _store: self.inner.clone(),
            }),
        }
    }
}

/// Records stats for one (cluster, EDS service) that aren't specific to a
/// locality. Cheap to clone. Keeps reporting to its server running.
#[derive(Clone)]
pub struct ClusterLevelStats {
    counters: Arc<ClusterLevelCounters>,
    /// Keeps reporting running, so that drops recorded after the last
    /// `LoadStore` was dropped are still reported.
    _store: Arc<LoadStoreInner>,
}

impl fmt::Debug for ClusterLevelStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterLevelStats").finish_non_exhaustive()
    }
}

impl ClusterLevelStats {
    /// Records a call dropped because of the EDS drop_overload `category`.
    pub fn record_drop(&self, category: &str) {
        let mut drops = lock(&self.counters.categorized_drops);
        if let Some(count) = drops.get_mut(category) {
            *count += 1;
        } else {
            drops.insert(category.to_owned(), 1);
        }
    }

    /// Records a call dropped for a reason without a category, such as
    /// circuit breaking. Counted only in the total.
    pub fn record_uncategorized_drop(&self) {
        self.counters.uncategorized_drops.fetch_add(1, Relaxed);
    }
}

/// Records calls for one (cluster, EDS service, locality). Cheap to clone.
/// It and its call trackers keep reporting to its server running.
#[derive(Clone)]
pub struct ClusterLocalityStats {
    recorder: Arc<LocalityRecorder>,
}

impl fmt::Debug for ClusterLocalityStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterLocalityStats")
            .finish_non_exhaustive()
    }
}

impl ClusterLocalityStats {
    /// Records a call start, and returns a tracker to record its end.
    pub fn start_call(&self) -> CallTracker {
        let counters = &self.recorder.counters;
        counters.issued.fetch_add(1, Relaxed);
        counters.in_progress.fetch_add(1, Relaxed);
        CallTracker {
            recorder: Some(self.recorder.clone()),
        }
    }
}

/// A locality's counters, and the propagation config of the `locality_stats`
/// call that returned them. Shared by a recorder's clones and call trackers.
struct LocalityRecorder {
    counters: Arc<LocalityCounters>,
    propagation: Arc<BackendMetricPropagation>,
    /// Keeps reporting running, so that calls finishing after the last
    /// `LoadStore` was dropped are still reported.
    _store: Arc<LoadStoreInner>,
}

/// Tracks one call started on a [`ClusterLocalityStats`].
///
/// Keeps the recorder's counters alive until the call ends. If dropped
/// without calling [`finish`](Self::finish) or
/// [`finish_with_metrics`](Self::finish_with_metrics), for example because the
/// call's future was cancelled, the call is recorded as failed, so the
/// in-progress count never leaks.
#[must_use = "dropping the tracker immediately records the call as failed"]
pub struct CallTracker {
    /// Set until the end of the call is recorded.
    recorder: Option<Arc<LocalityRecorder>>,
}

impl fmt::Debug for CallTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallTracker").finish_non_exhaustive()
    }
}

impl CallTracker {
    /// Records the end of a call that returned no backend metrics.
    pub fn finish(mut self, outcome: CallOutcome) {
        if let Some(recorder) = self.recorder.take() {
            recorder.counters.record_finish(outcome);
        }
    }

    /// Records the end of the call, and the backend metrics it returned, as
    /// allowed by the recorder's [`BackendMetricPropagation`].
    ///
    /// The named metrics are iterated while holding a lock on the locality's
    /// counters, so iterating them must not record on the same locality.
    pub fn finish_with_metrics<N, K, V>(mut self, outcome: CallOutcome, metrics: BackendMetrics<N>)
    where
        N: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: Borrow<f64>,
    {
        let Some(recorder) = self.recorder.take() else {
            return;
        };
        recorder.counters.record_finish(outcome);
        let propagation = &*recorder.propagation;
        if !propagation.propagates_any() {
            return;
        }
        let backend_metrics = &recorder.counters.backend_metrics;
        let mut sums = lock(backend_metrics);
        if propagation.propagates_cpu_utilization() {
            sums.cpu_utilization.add(metrics.cpu_utilization);
        }
        if propagation.propagates_mem_utilization() {
            sums.mem_utilization.add(metrics.mem_utilization);
        }
        if propagation.propagates_application_utilization() {
            sums.application_utilization
                .add(metrics.application_utilization);
        }
        if !propagation.propagates_named_metrics() {
            return;
        }
        // Iterating the caller's data with the lock held avoids
        // collecting it into a buffer first.
        for (key, value) in metrics.named_metrics {
            let key = key.as_ref();
            if !propagation.propagates_named_metric(key) {
                continue;
            }
            let value = *value.borrow();
            // Look up before inserting, to allocate a key only the
            // first time it is recorded.
            if let Some(sum) = sums.named_metrics.get_mut(key) {
                sum.add(value);
            } else {
                let mut sum = MetricSum::default();
                sum.add(value);
                sums.named_metrics.insert(key.to_owned(), sum);
            }
        }
    }
}

impl Drop for CallTracker {
    fn drop(&mut self) {
        // Records without backend metrics, so that it only uses atomics:
        // dropping a tracker never takes a lock.
        if let Some(recorder) = self.recorder.take() {
            recorder.counters.record_finish(CallOutcome::Failed);
        }
    }
}

/// How a tracked call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallOutcome {
    /// The call succeeded.
    Succeeded,
    /// The call failed.
    Failed,
}

/// Counters of a [`ClusterLevelStats`].
#[derive(Default)]
struct ClusterLevelCounters {
    uncategorized_drops: AtomicU64,
    /// Locked only by `record_drop` and snapshots.
    categorized_drops: Mutex<HashMap<String, u64>>,
}

impl ClusterLevelCounters {
    /// Returns the total number of drops and the drops per category since the
    /// previous snapshot, and resets them.
    fn snapshot_and_reset(&self) -> (u64, Vec<DroppedRequests>) {
        let uncategorized = self.uncategorized_drops.swap(0, Relaxed);
        let categorized = mem::take(&mut *lock(&self.categorized_drops));
        let mut total = uncategorized;
        let dropped_requests = categorized
            .into_iter()
            .map(|(category, dropped_count)| {
                total += dropped_count;
                DroppedRequests {
                    category,
                    dropped_count,
                }
            })
            .collect();
        (total, dropped_requests)
    }
}

/// Counters of a [`ClusterLocalityStats`].
#[derive(Default)]
struct LocalityCounters {
    issued: AtomicU64,
    /// A gauge: not reset by snapshots.
    in_progress: AtomicU64,
    succeeded: AtomicU64,
    failed: AtomicU64,
    /// Locked only by calls finished with metrics to propagate, and snapshots.
    backend_metrics: Mutex<BackendMetricSums>,
}

impl LocalityCounters {
    fn record_finish(&self, outcome: CallOutcome) {
        match outcome {
            CallOutcome::Succeeded => self.succeeded.fetch_add(1, Relaxed),
            CallOutcome::Failed => self.failed.fetch_add(1, Relaxed),
        };
        self.in_progress.fetch_sub(1, Relaxed);
    }

    /// Returns the stats since the previous snapshot, and resets them, except
    /// for the number of calls in progress. Returns `None` if there is nothing
    /// to report.
    fn snapshot_and_reset(&self, locality: &Locality) -> Option<UpstreamLocalityStats> {
        let issued = self.issued.swap(0, Relaxed);
        let succeeded = self.succeeded.swap(0, Relaxed);
        let failed = self.failed.swap(0, Relaxed);
        let in_progress = self.in_progress.load(Relaxed);
        let metrics = lock(&self.backend_metrics).snapshot_and_reset();
        if issued == 0 && succeeded == 0 && failed == 0 && in_progress == 0 && metrics.is_empty() {
            return None;
        }
        Some(UpstreamLocalityStats {
            locality: locality.clone(),
            total_successful_requests: succeeded,
            total_requests_in_progress: in_progress,
            total_error_requests: failed,
            total_issued_requests: issued,
            cpu_utilization: metrics.cpu_utilization,
            mem_utilization: metrics.mem_utilization,
            application_utilization: metrics.application_utilization,
            load_metric_stats: metrics.load_metric_stats,
        })
    }
}

/// Backend metrics recorded for a locality since the previous snapshot.
#[derive(Default)]
struct BackendMetricSums {
    cpu_utilization: MetricSum,
    mem_utilization: MetricSum,
    application_utilization: MetricSum,
    /// By key, without the `named_metrics.` prefix. Keys are kept across
    /// snapshots while they're recorded, so that recording them doesn't
    /// allocate.
    named_metrics: HashMap<String, MetricSum>,
}

impl BackendMetricSums {
    /// Returns the utilizations and named metrics recorded since the previous
    /// snapshot, and resets them. Removes the keys of named metrics that
    /// weren't recorded since then.
    fn snapshot_and_reset(&mut self) -> BackendMetricsSnapshot {
        let mut load_metric_stats = Vec::new();
        self.named_metrics.retain(|key, sum| {
            if sum.count == 0 {
                return false;
            }
            let sum = mem::take(sum);
            load_metric_stats.push(EndpointLoadMetricStats {
                metric_name: format!("{}{key}", BackendMetricPropagation::NAMED_METRICS_PREFIX),
                num_requests_finished_with_metric: sum.count,
                total_metric_value: sum.total,
            });
            true
        });
        BackendMetricsSnapshot {
            cpu_utilization: mem::take(&mut self.cpu_utilization).into_stats(),
            mem_utilization: mem::take(&mut self.mem_utilization).into_stats(),
            application_utilization: mem::take(&mut self.application_utilization).into_stats(),
            load_metric_stats,
        }
    }
}

/// Backend metrics of a locality to report, from
/// [`BackendMetricSums::snapshot_and_reset`].
struct BackendMetricsSnapshot {
    cpu_utilization: Option<UnnamedEndpointLoadMetricStats>,
    mem_utilization: Option<UnnamedEndpointLoadMetricStats>,
    application_utilization: Option<UnnamedEndpointLoadMetricStats>,
    load_metric_stats: Vec<EndpointLoadMetricStats>,
}

impl BackendMetricsSnapshot {
    fn is_empty(&self) -> bool {
        self.cpu_utilization.is_none()
            && self.mem_utilization.is_none()
            && self.application_utilization.is_none()
            && self.load_metric_stats.is_empty()
    }
}

/// Number and sum of the values reported for a backend metric.
#[derive(Default)]
struct MetricSum {
    count: u64,
    total: f64,
}

impl MetricSum {
    fn add(&mut self, value: f64) {
        self.count += 1;
        self.total += value;
    }

    /// Returns the stats to report, or `None` if nothing was recorded.
    fn into_stats(self) -> Option<UnnamedEndpointLoadMetricStats> {
        (self.count != 0).then_some(UnnamedEndpointLoadMetricStats {
            num_requests_finished_with_metric: self.count,
            total_metric_value: self.total,
        })
    }
}

/// Source of the current time. Replaced in tests.
pub(super) type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// All counters for one LRS server. Locked by [`LoadStore`] when getting a
/// recorder, and by [`LoadReporter`] while building a report.
struct Registry {
    clusters: HashMap<ClusterKey, ClusterEntry>,
    /// Called while the registry is locked, so it must not block or lock.
    clock: Clock,
}

impl Registry {
    /// Returns the entry for the given cluster, creating it if needed.
    fn entry(&mut self, cluster_name: &str, eds_service_name: &str) -> &mut ClusterEntry {
        let key = ClusterKey {
            cluster_name: cluster_name.to_owned(),
            eds_service_name: eds_service_name.to_owned(),
        };
        let clock = &self.clock;
        self.clusters
            .entry(key)
            .or_insert_with(|| ClusterEntry::new(clock()))
    }

    /// See [`LoadReporter::snapshot`].
    fn snapshot(&mut self, selection: &ClusterSelection) -> Vec<ClusterStats> {
        let now = (self.clock)();
        let mut reports = Vec::new();
        self.clusters.retain(|key, entry| {
            // Take the interval, and reset it, before pruning, and even if
            // the stats aren't reported.
            let interval = now.saturating_duration_since(entry.last_report_at);
            entry.last_report_at = now;
            let stats = entry.snapshot_and_prune(key, interval);
            let is_selected = match selection {
                ClusterSelection::All => true,
                ClusterSelection::Only(names) => names.contains(&key.cluster_name),
            };
            if let Some(stats) = stats.filter(|_| is_selected) {
                reports.push(stats);
            }
            !entry.is_empty()
        });
        reports
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ClusterKey {
    cluster_name: String,
    eds_service_name: String,
}

struct ClusterEntry {
    cluster_level: Option<Arc<ClusterLevelCounters>>,
    localities: HashMap<Locality, Arc<LocalityCounters>>,
    /// Start of the interval covered by this cluster's next report: when the
    /// entry was created, then the time of the previous report.
    last_report_at: Instant,
}

impl ClusterEntry {
    fn new(now: Instant) -> Self {
        Self {
            cluster_level: None,
            localities: HashMap::new(),
            last_report_at: now,
        }
    }

    fn is_empty(&self) -> bool {
        self.cluster_level.is_none() && self.localities.is_empty()
    }

    /// Snapshots and resets all the counters of this entry, and removes those
    /// with no recorders left. Returns `None` if there is nothing to report.
    ///
    /// Must be called with the registry locked, so that no recorder can be
    /// created for counters found to have none.
    fn snapshot_and_prune(&mut self, key: &ClusterKey, interval: Duration) -> Option<ClusterStats> {
        let mut total_dropped_requests = 0;
        let mut dropped_requests = Vec::new();
        if let Some(counters) = &mut self.cluster_level {
            // Check for remaining recorders before the final snapshot: if
            // there are none, nothing can be recorded after the snapshot.
            let unique = Arc::get_mut(counters).is_some();
            (total_dropped_requests, dropped_requests) = counters.snapshot_and_reset();
            if unique {
                self.cluster_level = None;
            }
        }
        let mut upstream_locality_stats = Vec::new();
        self.localities.retain(|locality, counters| {
            // Same order as above: check, snapshot, prune.
            let unique = Arc::get_mut(counters).is_some();
            if let Some(stats) = counters.snapshot_and_reset(locality) {
                upstream_locality_stats.push(stats);
            }
            !unique
        });
        if total_dropped_requests == 0 && upstream_locality_stats.is_empty() {
            return None;
        }
        Some(ClusterStats {
            cluster_name: key.cluster_name.clone(),
            eds_service_name: key.eds_service_name.clone(),
            upstream_locality_stats,
            total_dropped_requests,
            dropped_requests,
            load_report_interval: interval,
        })
    }
}

/// Builds load reports for one LRS server.
///
/// Owned by that server's LRS worker task, for as long as the worker runs,
/// across streams. Shares the registry of counters with the server's
/// `LoadStore`s.
pub(super) struct LoadReporter {
    registry: Arc<Mutex<Registry>>,
}

/// Which clusters a report covers, from the LRS server's response.
pub(super) enum ClusterSelection {
    /// `send_all_clusters` was set.
    All,
    /// Only the clusters with these names, with any EDS service name.
    Only(HashSet<String>),
}

impl LoadReporter {
    /// Creates a reporter measuring time with `clock`, and the `LoadStore` for
    /// its registry, which keeps `worker` running.
    ///
    /// This is the only `LoadStore` created for the registry; the others are
    /// its clones. So there is a single `LoadStoreInner`, holding the only
    /// `WorkerHandle`, whose lifetime is the worker's.
    pub(super) fn new(clock: Clock, worker: WorkerHandle) -> (Self, LoadStore) {
        let registry = Arc::new(Mutex::new(Registry {
            clusters: HashMap::new(),
            clock,
        }));
        let load_store = LoadStore {
            inner: Arc::new(LoadStoreInner {
                registry: registry.clone(),
                _worker: worker,
            }),
        };
        (Self { registry }, load_store)
    }

    /// Snapshots, resets and prunes every entry, and returns the stats of the
    /// selected clusters that have something to report.
    ///
    /// The stats of unselected clusters are discarded, so that if the LRS
    /// server asks for them later, their first report doesn't include loads
    /// from previous intervals.
    pub(super) fn snapshot(&mut self, selection: &ClusterSelection) -> Vec<ClusterStats> {
        lock(&self.registry).snapshot(selection)
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    /// A clock that only moves when told to.
    #[derive(Clone)]
    struct FakeClock(Arc<Mutex<Instant>>);

    impl FakeClock {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Instant::now())))
        }

        fn advance(&self, duration: Duration) {
            *lock(&self.0) += duration;
        }

        fn clock(&self) -> Clock {
            let now = self.0.clone();
            Arc::new(move || *lock(&now))
        }
    }

    fn new_reporter() -> (LoadReporter, LoadStore, FakeClock) {
        let clock = FakeClock::new();
        let (reporter, store) = LoadReporter::new(clock.clock(), WorkerHandle::detached());
        (reporter, store, clock)
    }

    fn locality(region: &str) -> Locality {
        Locality {
            region: region.to_owned(),
            ..Default::default()
        }
    }

    /// Returns the stats of the given cluster in `reports`, which must exist.
    fn cluster<'a>(
        reports: &'a [ClusterStats],
        cluster_name: &str,
        eds_service_name: &str,
    ) -> &'a ClusterStats {
        reports
            .iter()
            .find(|s| s.cluster_name == cluster_name && s.eds_service_name == eds_service_name)
            .unwrap_or_else(|| panic!("no stats for {cluster_name}/{eds_service_name}"))
    }

    /// Returns the stats of the given locality in `stats`, which must exist.
    fn locality_stats<'a>(stats: &'a ClusterStats, region: &str) -> &'a UpstreamLocalityStats {
        stats
            .upstream_locality_stats
            .iter()
            .find(|s| s.locality.region == region)
            .unwrap_or_else(|| panic!("no stats for locality {region}"))
    }

    fn num_entries(reporter: &LoadReporter) -> usize {
        lock(&reporter.registry).clusters.len()
    }

    fn no_propagation() -> Arc<BackendMetricPropagation> {
        Arc::default()
    }

    fn only(cluster_names: &[&str]) -> ClusterSelection {
        ClusterSelection::Only(cluster_names.iter().map(|&name| name.to_owned()).collect())
    }

    fn propagation(specs: &[&str]) -> Arc<BackendMetricPropagation> {
        Arc::new(BackendMetricPropagation::from_metric_specs(specs))
    }

    fn unnamed(count: u64, total: f64) -> Option<UnnamedEndpointLoadMetricStats> {
        Some(UnnamedEndpointLoadMetricStats {
            num_requests_finished_with_metric: count,
            total_metric_value: total,
        })
    }

    fn named(name: &str, count: u64, total: f64) -> EndpointLoadMetricStats {
        EndpointLoadMetricStats {
            metric_name: name.to_owned(),
            num_requests_finished_with_metric: count,
            total_metric_value: total,
        }
    }

    #[test]
    fn records_call_counts() {
        let (mut reporter, store, _) = new_reporter();
        let stats = store.locality_stats("cluster", "eds", &locality("r1"), no_propagation());
        let clone = stats.clone();
        stats.start_call().finish(CallOutcome::Succeeded);
        clone.start_call().finish(CallOutcome::Failed);
        let in_flight = stats.start_call();

        let reports = reporter.snapshot(&ClusterSelection::All);
        assert_eq!(reports.len(), 1);
        let got = locality_stats(cluster(&reports, "cluster", "eds"), "r1");
        assert_eq!(got.total_issued_requests, 3);
        assert_eq!(got.total_successful_requests, 1);
        assert_eq!(got.total_error_requests, 1);
        assert_eq!(got.total_requests_in_progress, 1);

        // The in-progress count isn't reset, so it's reported again.
        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = locality_stats(cluster(&reports, "cluster", "eds"), "r1");
        assert_eq!(got.total_issued_requests, 0);
        assert_eq!(got.total_requests_in_progress, 1);

        in_flight.finish(CallOutcome::Succeeded);
        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = locality_stats(cluster(&reports, "cluster", "eds"), "r1");
        assert_eq!(got.total_successful_requests, 1);
        assert_eq!(got.total_requests_in_progress, 0);
    }

    #[test]
    fn dropped_tracker_records_failure() {
        let (mut reporter, store, _) = new_reporter();
        let stats = store.locality_stats("cluster", "eds", &locality("r1"), no_propagation());
        drop(stats.start_call());

        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = locality_stats(cluster(&reports, "cluster", "eds"), "r1");
        assert_eq!(got.total_issued_requests, 1);
        assert_eq!(got.total_error_requests, 1);
        assert_eq!(got.total_requests_in_progress, 0);
        assert_eq!(got.cpu_utilization, None);
        assert!(got.load_metric_stats.is_empty());
    }

    #[test]
    fn records_no_metrics_without_propagation() {
        let (mut reporter, store, _) = new_reporter();
        let stats = store.locality_stats("cluster", "eds", &locality("r1"), no_propagation());
        // The named metrics aren't even iterated.
        let named_metrics = std::iter::from_fn(|| -> Option<(&str, f64)> {
            panic!("named metrics iterated without propagation")
        });
        stats.start_call().finish_with_metrics(
            CallOutcome::Succeeded,
            BackendMetrics::new()
                .with_cpu_utilization(0.5)
                .with_named_metrics(named_metrics),
        );

        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = locality_stats(cluster(&reports, "cluster", "eds"), "r1");
        assert_eq!(got.total_successful_requests, 1);
        assert_eq!(got.cpu_utilization, None);
        assert_eq!(got.mem_utilization, None);
        assert_eq!(got.application_utilization, None);
        assert!(got.load_metric_stats.is_empty());
    }

    #[test]
    fn records_propagated_utilizations() {
        let (mut reporter, store, _) = new_reporter();
        let stats = store.locality_stats(
            "cluster",
            "eds",
            &locality("r1"),
            propagation(&["cpu_utilization", "application_utilization"]),
        );
        let metrics = BackendMetrics::new()
            .with_cpu_utilization(0.5)
            .with_mem_utilization(0.7)
            .with_application_utilization(0.25)
            .with_named_metrics([("a", 1.0)]);
        stats
            .start_call()
            .finish_with_metrics(CallOutcome::Succeeded, metrics);
        // Values of 0 are recorded too.
        stats
            .start_call()
            .finish_with_metrics(CallOutcome::Failed, BackendMetrics::new());

        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = locality_stats(cluster(&reports, "cluster", "eds"), "r1");
        assert_eq!(got.cpu_utilization, unnamed(2, 0.5));
        assert_eq!(got.mem_utilization, None);
        assert_eq!(got.application_utilization, unnamed(2, 0.25));
        assert!(got.load_metric_stats.is_empty());

        // Metrics are reset by snapshots.
        stats.start_call().finish(CallOutcome::Succeeded);
        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = locality_stats(cluster(&reports, "cluster", "eds"), "r1");
        assert_eq!(got.cpu_utilization, None);
        assert_eq!(got.application_utilization, None);
    }

    #[test]
    fn records_propagated_named_metrics() {
        let (mut reporter, store, _) = new_reporter();
        let some = store.locality_stats(
            "cluster",
            "eds",
            &locality("some"),
            propagation(&["named_metrics.a", "named_metrics.c"]),
        );
        let all = store.locality_stats(
            "cluster",
            "eds",
            &locality("all"),
            propagation(&["named_metrics.*"]),
        );
        for stats in [&some, &all] {
            stats.start_call().finish_with_metrics(
                CallOutcome::Succeeded,
                BackendMetrics::new()
                    .with_cpu_utilization(0.5)
                    .with_named_metrics([("b", 4.0), ("a", 1.0)]),
            );
            stats.start_call().finish_with_metrics(
                CallOutcome::Failed,
                BackendMetrics::new().with_named_metrics([("a", 2.5)]),
            );
        }

        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = cluster(&reports, "cluster", "eds");
        let got_some = locality_stats(got, "some");
        assert_eq!(
            got_some.load_metric_stats,
            vec![named("named_metrics.a", 2, 3.5)]
        );
        assert_eq!(got_some.cpu_utilization, None);
        let got_all = locality_stats(got, "all");
        // Reports aren't in any particular order.
        let mut got_metrics = got_all.load_metric_stats.clone();
        got_metrics.sort_unstable_by(|a, b| a.metric_name.cmp(&b.metric_name));
        assert_eq!(
            got_metrics,
            vec![
                named("named_metrics.a", 2, 3.5),
                named("named_metrics.b", 1, 4.0),
            ]
        );
    }

    #[test]
    fn accepts_named_metrics_from_any_iterable() {
        let (mut reporter, store, _) = new_reporter();
        let stats = store.locality_stats(
            "cluster",
            "eds",
            &locality("r1"),
            propagation(&["named_metrics.*"]),
        );
        let hash_map = HashMap::from([("a".to_owned(), 1.0)]);
        stats.start_call().finish_with_metrics(
            CallOutcome::Succeeded,
            BackendMetrics::new().with_named_metrics(&hash_map),
        );
        let btree_map = std::collections::BTreeMap::from([("a", 1.0)]);
        stats.start_call().finish_with_metrics(
            CallOutcome::Succeeded,
            BackendMetrics::new().with_named_metrics(btree_map),
        );
        stats.start_call().finish_with_metrics(
            CallOutcome::Succeeded,
            BackendMetrics::new().with_named_metrics(vec![("a".to_owned(), 1.0)]),
        );
        stats.start_call().finish_with_metrics(
            CallOutcome::Succeeded,
            BackendMetrics::new().with_named_metrics([("a", 1.0)].iter().copied()),
        );
        stats.start_call().finish_with_metrics(
            CallOutcome::Succeeded,
            BackendMetrics::new()
                .with_named_metrics(hash_map.iter().map(|(k, v)| (k.as_str(), *v))),
        );

        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = locality_stats(cluster(&reports, "cluster", "eds"), "r1");
        assert_eq!(
            got.load_metric_stats,
            vec![named("named_metrics.a", 5, 5.0)]
        );
    }

    #[test]
    fn filters_metrics_with_each_recorder_config() {
        let (mut reporter, store, _) = new_reporter();
        let cpu = store.locality_stats(
            "cluster",
            "eds",
            &locality("r1"),
            propagation(&["cpu_utilization"]),
        );
        let named_a = store.locality_stats(
            "cluster",
            "eds",
            &locality("r1"),
            propagation(&["named_metrics.a"]),
        );
        for stats in [&cpu, &named_a] {
            stats.start_call().finish_with_metrics(
                CallOutcome::Succeeded,
                BackendMetrics::new()
                    .with_cpu_utilization(0.5)
                    .with_named_metrics([("a", 1.0)]),
            );
        }

        // Both recorders share counters, but each recorded only what its
        // config allows.
        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = cluster(&reports, "cluster", "eds");
        assert_eq!(got.upstream_locality_stats.len(), 1);
        let got = locality_stats(got, "r1");
        assert_eq!(got.total_successful_requests, 2);
        assert_eq!(got.cpu_utilization, unnamed(1, 0.5));
        assert_eq!(
            got.load_metric_stats,
            vec![named("named_metrics.a", 1, 1.0)]
        );
    }

    #[test]
    fn keeps_named_metric_keys_while_recorded() {
        let (mut reporter, store, _) = new_reporter();
        let stats = store.locality_stats(
            "cluster",
            "eds",
            &locality("r1"),
            propagation(&["named_metrics.*"]),
        );
        let has_key = |key: &str| {
            lock(&stats.recorder.counters.backend_metrics)
                .named_metrics
                .contains_key(key)
        };
        let record_a = || {
            stats.start_call().finish_with_metrics(
                CallOutcome::Succeeded,
                BackendMetrics::new().with_named_metrics([("a", 1.0)]),
            );
        };

        // A key recorded since the previous snapshot is kept, but reset.
        record_a();
        reporter.snapshot(&ClusterSelection::All);
        assert!(has_key("a"));
        record_a();
        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = locality_stats(cluster(&reports, "cluster", "eds"), "r1");
        assert_eq!(
            got.load_metric_stats,
            vec![named("named_metrics.a", 1, 1.0)]
        );
        assert!(has_key("a"));

        // A key not recorded since the previous snapshot is removed.
        reporter.snapshot(&ClusterSelection::All);
        assert!(!has_key("a"));
    }

    #[test]
    fn records_drops() {
        let (mut reporter, store, _) = new_reporter();
        let stats = store.cluster_level_stats("cluster", "eds");
        stats.record_drop("lb");
        stats.record_drop("throttle");
        stats.clone().record_drop("lb");
        // An empty category is a category like any other.
        stats.record_drop("");
        stats.record_uncategorized_drop();

        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = cluster(&reports, "cluster", "eds");
        assert_eq!(got.total_dropped_requests, 5);
        // Reports aren't in any particular order.
        let mut got_drops = got.dropped_requests.clone();
        got_drops.sort_unstable_by(|a, b| a.category.cmp(&b.category));
        assert_eq!(
            got_drops,
            vec![
                DroppedRequests {
                    category: "".to_owned(),
                    dropped_count: 1,
                },
                DroppedRequests {
                    category: "lb".to_owned(),
                    dropped_count: 2,
                },
                DroppedRequests {
                    category: "throttle".to_owned(),
                    dropped_count: 1,
                },
            ]
        );
        assert!(got.upstream_locality_stats.is_empty());

        // Drops are reset by snapshots.
        assert!(reporter.snapshot(&ClusterSelection::All).is_empty());
    }

    #[test]
    fn same_key_shares_counters() {
        let (mut reporter, store, _) = new_reporter();
        let s1 = store.locality_stats("cluster", "eds", &locality("r1"), no_propagation());
        let s2 = store.locality_stats("cluster", "eds", &locality("r1"), no_propagation());
        let other = store.locality_stats("cluster", "eds", &locality("r2"), no_propagation());
        s1.start_call().finish(CallOutcome::Succeeded);
        s2.start_call().finish(CallOutcome::Succeeded);
        other.start_call().finish(CallOutcome::Succeeded);
        let d1 = store.cluster_level_stats("cluster", "eds");
        let d2 = store.cluster_level_stats("cluster", "eds");
        d1.record_uncategorized_drop();
        d2.record_uncategorized_drop();

        let reports = reporter.snapshot(&ClusterSelection::All);
        assert_eq!(reports.len(), 1);
        let got = cluster(&reports, "cluster", "eds");
        assert_eq!(got.upstream_locality_stats.len(), 2);
        assert_eq!(locality_stats(got, "r1").total_issued_requests, 2);
        assert_eq!(locality_stats(got, "r2").total_issued_requests, 1);
        assert_eq!(got.total_dropped_requests, 2);
    }

    #[test]
    fn prunes_entries_without_recorders() {
        let (mut reporter, store, _) = new_reporter();
        let stats = store.locality_stats("cluster", "eds", &locality("r1"), no_propagation());
        let drops = store.cluster_level_stats("cluster", "eds");
        stats.start_call().finish(CallOutcome::Succeeded);
        drops.record_uncategorized_drop();
        drop(stats);
        drop(drops);
        assert_eq!(num_entries(&reporter), 1);

        // The final counts are reported once, and the entry is pruned.
        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = cluster(&reports, "cluster", "eds");
        assert_eq!(locality_stats(got, "r1").total_successful_requests, 1);
        assert_eq!(got.total_dropped_requests, 1);
        assert_eq!(num_entries(&reporter), 0);
        assert!(reporter.snapshot(&ClusterSelection::All).is_empty());
    }

    #[test]
    fn does_not_prune_entries_with_calls_in_progress() {
        let (mut reporter, store, _) = new_reporter();
        let stats = store.locality_stats("cluster", "eds", &locality("r1"), no_propagation());
        let tracker = stats.start_call();
        drop(stats);

        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = locality_stats(cluster(&reports, "cluster", "eds"), "r1");
        assert_eq!(got.total_requests_in_progress, 1);
        assert_eq!(num_entries(&reporter), 1);

        tracker.finish(CallOutcome::Succeeded);
        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = locality_stats(cluster(&reports, "cluster", "eds"), "r1");
        assert_eq!(got.total_successful_requests, 1);
        assert_eq!(got.total_requests_in_progress, 0);
        assert_eq!(num_entries(&reporter), 0);
    }

    #[test]
    fn creates_fresh_counters_after_pruning() {
        let (mut reporter, store, _) = new_reporter();
        let stats = store.locality_stats("cluster", "eds", &locality("r1"), no_propagation());
        stats.start_call().finish(CallOutcome::Succeeded);
        drop(stats);
        reporter.snapshot(&ClusterSelection::All);
        assert_eq!(num_entries(&reporter), 0);

        let stats = store.locality_stats("cluster", "eds", &locality("r1"), no_propagation());
        stats.start_call().finish(CallOutcome::Failed);
        let reports = reporter.snapshot(&ClusterSelection::All);
        let got = locality_stats(cluster(&reports, "cluster", "eds"), "r1");
        assert_eq!(got.total_issued_requests, 1);
        assert_eq!(got.total_error_requests, 1);
        assert_eq!(got.total_successful_requests, 0);
    }

    /// Recorders keep working if the reporter is gone, as when the worker task
    /// ends abnormally: the stores keep the registry alive.
    #[test]
    fn recorders_work_after_reporter_is_gone() {
        let (reporter, store, _) = new_reporter();
        let all = propagation(&["cpu_utilization", "named_metrics.*"]);
        let before = store.locality_stats("cluster", "eds", &locality("r1"), all.clone());
        drop(reporter);

        before.start_call().finish_with_metrics(
            CallOutcome::Succeeded,
            BackendMetrics::new()
                .with_cpu_utilization(0.5)
                .with_named_metrics([("a", 1.0)]),
        );
        let after = store.locality_stats("cluster", "eds", &locality("r1"), all);
        after.start_call().finish(CallOutcome::Failed);
        let drops = store.cluster_level_stats("cluster", "eds");
        drops.record_drop("lb");
        drops.record_uncategorized_drop();
    }

    #[test]
    fn reports_only_selected_clusters() {
        let (mut reporter, store, _) = new_reporter();
        let a1 = store.locality_stats("a", "eds1", &locality("r1"), no_propagation());
        let a2 = store.locality_stats("a", "eds2", &locality("r1"), no_propagation());
        let b = store.locality_stats("b", "eds1", &locality("r1"), no_propagation());
        for stats in [&a1, &a2, &b] {
            stats.start_call().finish(CallOutcome::Succeeded);
        }

        let reports = reporter.snapshot(&only(&["a"]));
        assert_eq!(reports.len(), 2);
        cluster(&reports, "a", "eds1");
        cluster(&reports, "a", "eds2");

        // The loads of "b" were discarded, rather than carried over.
        b.start_call().finish(CallOutcome::Failed);
        let reports = reporter.snapshot(&only(&["b"]));
        assert_eq!(reports.len(), 1);
        let got = locality_stats(cluster(&reports, "b", "eds1"), "r1");
        assert_eq!(got.total_issued_requests, 1);
        assert_eq!(got.total_successful_requests, 0);
        assert_eq!(got.total_error_requests, 1);

        // Entries of unselected clusters are pruned too.
        drop(b);
        reporter.snapshot(&only(&["a"]));
        assert_eq!(num_entries(&reporter), 2);
    }

    #[test]
    fn omits_empty_stats() {
        let (mut reporter, store, _) = new_reporter();
        let idle = store.locality_stats("idle", "eds", &locality("r1"), no_propagation());
        let _idle_drops = store.cluster_level_stats("idle", "eds");
        let busy = store.locality_stats("busy", "eds", &locality("busy"), no_propagation());
        let busy_idle = store.locality_stats("busy", "eds", &locality("idle"), no_propagation());
        let _tracker = busy.start_call();

        let reports = reporter.snapshot(&ClusterSelection::All);
        assert_eq!(reports.len(), 1);
        let got = cluster(&reports, "busy", "eds");
        assert_eq!(got.upstream_locality_stats.len(), 1);
        assert_eq!(locality_stats(got, "busy").total_requests_in_progress, 1);
        // Entries with recorders are kept, even with nothing to report.
        assert_eq!(num_entries(&reporter), 2);
        drop((idle, busy_idle));
    }

    #[test]
    fn measures_report_intervals() {
        let (mut reporter, store, clock) = new_reporter();
        clock.advance(Duration::from_secs(1));
        let a = store.locality_stats("a", "eds", &locality("r1"), no_propagation());
        let b = store.locality_stats("b", "eds", &locality("r1"), no_propagation());
        let record = |stats: &ClusterLocalityStats| {
            stats.start_call().finish(CallOutcome::Succeeded);
        };

        // The first interval starts when the entry is created.
        clock.advance(Duration::from_secs(2));
        record(&a);
        record(&b);
        let reports = reporter.snapshot(&ClusterSelection::All);
        assert_eq!(
            cluster(&reports, "a", "eds").load_report_interval,
            Duration::from_secs(2)
        );

        // Later ones start at the previous report, even if the cluster was
        // left out of it.
        clock.advance(Duration::from_secs(3));
        record(&a);
        record(&b);
        let reports = reporter.snapshot(&only(&["a"]));
        assert_eq!(
            cluster(&reports, "a", "eds").load_report_interval,
            Duration::from_secs(3)
        );
        clock.advance(Duration::from_secs(4));
        record(&b);
        let reports = reporter.snapshot(&ClusterSelection::All);
        assert_eq!(
            cluster(&reports, "b", "eds").load_report_interval,
            Duration::from_secs(4)
        );

        // An entry pruned by a report still gets its interval in it. "a" had
        // nothing to report in the previous report, which still reset it.
        clock.advance(Duration::from_secs(5));
        record(&a);
        drop(a);
        let reports = reporter.snapshot(&ClusterSelection::All);
        assert_eq!(
            cluster(&reports, "a", "eds").load_report_interval,
            Duration::from_secs(5)
        );
        assert_eq!(num_entries(&reporter), 1);
        drop(b);
    }

    /// Records calls and drops from many threads, while creating and dropping
    /// recorders, concurrently with reports. Checks that every count is
    /// reported exactly once.
    #[test]
    fn concurrent_recording_and_reporting() {
        const THREADS: u64 = 8;
        const ITERATIONS: u64 = 2000;
        let (mut reporter, store, _) = new_reporter();
        let mut issued = 0;
        let mut succeeded = 0;
        let mut dropped = 0;
        let mut add = |reports: Vec<ClusterStats>| {
            for stats in reports {
                dropped += stats.total_dropped_requests;
                for l in stats.upstream_locality_stats {
                    issued += l.total_issued_requests;
                    succeeded += l.total_successful_requests;
                }
            }
        };

        thread::scope(|scope| {
            let workers: Vec<_> = (0..THREADS)
                .map(|t| {
                    let store = store.clone();
                    scope.spawn(move || {
                        for i in 0..ITERATIONS {
                            // A few keys, shared across threads.
                            let region = format!("r{}", (t + i) % 3);
                            let stats = store.locality_stats(
                                "cluster",
                                "eds",
                                &locality(&region),
                                no_propagation(),
                            );
                            stats.start_call().finish(CallOutcome::Succeeded);
                            store
                                .cluster_level_stats("cluster", "eds")
                                .record_drop("lb");
                        }
                    })
                })
                .collect();
            while !workers.iter().all(|w| w.is_finished()) {
                add(reporter.snapshot(&ClusterSelection::All));
            }
        });
        add(reporter.snapshot(&ClusterSelection::All));

        assert_eq!(issued, THREADS * ITERATIONS);
        assert_eq!(succeeded, THREADS * ITERATIONS);
        assert_eq!(dropped, THREADS * ITERATIONS);
        assert_eq!(num_entries(&reporter), 0);
    }
}

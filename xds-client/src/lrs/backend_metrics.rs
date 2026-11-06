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

//! ORCA backend metrics propagated to LRS load reports, as specified by
//! [gRFC A85](https://github.com/grpc/proposal/blob/master/A85-lrs-custom-metrics-changes.md).

use std::collections::HashSet;
use std::iter;

/// Which ORCA backend metrics to propagate to LRS load reports, as configured
/// by a cluster's `lrs_report_endpoint_metrics` (gRFC A85).
///
/// The default propagates nothing, as when the field is unset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackendMetricPropagation {
    cpu_utilization: bool,
    mem_utilization: bool,
    application_utilization: bool,
    all_named_metrics: bool,
    /// Keys of the named metrics to propagate. Not used if
    /// `all_named_metrics` is set.
    named_metric_keys: HashSet<String>,
}

impl BackendMetricPropagation {
    /// Prefix of the specs of named metrics, and of their names in load
    /// reports.
    pub(super) const NAMED_METRICS_PREFIX: &'static str = "named_metrics.";

    /// Parses the metric specs of a cluster's `lrs_report_endpoint_metrics`:
    /// `cpu_utilization`, `mem_utilization`, `application_utilization`,
    /// `named_metrics.*` and `named_metrics.<key>`. Other specs are ignored.
    pub fn from_metric_specs<S: AsRef<str>>(specs: impl IntoIterator<Item = S>) -> Self {
        let mut propagation = Self::default();
        for spec in specs {
            let spec = spec.as_ref();
            match spec {
                "cpu_utilization" => propagation.cpu_utilization = true,
                "mem_utilization" => propagation.mem_utilization = true,
                "application_utilization" => propagation.application_utilization = true,
                _ => match spec.strip_prefix(Self::NAMED_METRICS_PREFIX) {
                    Some("*") => propagation.all_named_metrics = true,
                    Some(key) => {
                        propagation.named_metric_keys.insert(key.to_owned());
                    }
                    None => {}
                },
            }
        }
        propagation
    }

    /// Whether CPU utilization is propagated.
    pub fn propagates_cpu_utilization(&self) -> bool {
        self.cpu_utilization
    }

    /// Whether memory utilization is propagated.
    pub fn propagates_mem_utilization(&self) -> bool {
        self.mem_utilization
    }

    /// Whether application utilization is propagated.
    pub fn propagates_application_utilization(&self) -> bool {
        self.application_utilization
    }

    /// Whether all named metrics are propagated.
    pub fn propagates_all_named_metrics(&self) -> bool {
        self.all_named_metrics
    }

    /// Whether the named metric with `key` is propagated.
    pub fn propagates_named_metric(&self, key: &str) -> bool {
        self.all_named_metrics || self.named_metric_keys.contains(key)
    }

    /// Whether any metric is propagated.
    pub(super) fn propagates_any(&self) -> bool {
        self.propagates_utilizations() || self.propagates_named_metrics()
    }

    /// Whether any of the CPU, memory and application utilizations is
    /// propagated.
    pub(super) fn propagates_utilizations(&self) -> bool {
        self.cpu_utilization || self.mem_utilization || self.application_utilization
    }

    /// Whether any named metric is propagated.
    pub(super) fn propagates_named_metrics(&self) -> bool {
        self.all_named_metrics || !self.named_metric_keys.is_empty()
    }
}

/// ORCA backend metrics returned by a call, to record in LRS load reports.
///
/// `N` is any iterable of (name, value) pairs for the named metrics, such as
/// `&HashMap<String, f64>` from a decoded ORCA load report, or an array of
/// `(&str, f64)`. It is iterated at most once, and nothing is copied out of it
/// except the names of propagated metrics that the recorder hasn't seen
/// recently.
///
/// ```
/// use std::collections::HashMap;
/// use xds_client::lrs::BackendMetrics;
///
/// let named_metrics = HashMap::from([("queue_depth".to_owned(), 3.0)]);
/// let metrics = BackendMetrics::new()
///     .with_cpu_utilization(0.5)
///     .with_named_metrics(&named_metrics);
/// assert_eq!(metrics.cpu_utilization, 0.5);
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BackendMetrics<N = iter::Empty<(&'static str, f64)>> {
    /// CPU utilization, as a fraction of the available CPU.
    pub cpu_utilization: f64,
    /// Memory utilization, as a fraction of the available memory.
    pub mem_utilization: f64,
    /// Application-specific utilization, as a fraction of the available
    /// resources.
    pub application_utilization: f64,
    /// Application-specific metrics, as (name, value) pairs.
    pub named_metrics: N,
}

impl BackendMetrics {
    /// Creates metrics with all values zero, and no named metrics.
    pub fn new() -> Self {
        Self {
            cpu_utilization: 0.0,
            mem_utilization: 0.0,
            application_utilization: 0.0,
            named_metrics: iter::empty(),
        }
    }
}

impl Default for BackendMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl<N> BackendMetrics<N> {
    /// Sets the CPU utilization.
    pub fn with_cpu_utilization(mut self, value: f64) -> Self {
        self.cpu_utilization = value;
        self
    }

    /// Sets the memory utilization.
    pub fn with_mem_utilization(mut self, value: f64) -> Self {
        self.mem_utilization = value;
        self
    }

    /// Sets the application utilization.
    pub fn with_application_utilization(mut self, value: f64) -> Self {
        self.application_utilization = value;
        self
    }

    /// Sets the named metrics.
    pub fn with_named_metrics<M>(self, named_metrics: M) -> BackendMetrics<M> {
        BackendMetrics {
            cpu_utilization: self.cpu_utilization,
            mem_utilization: self.mem_utilization,
            application_utilization: self.application_utilization,
            named_metrics,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_propagates_nothing() {
        for propagation in [
            BackendMetricPropagation::default(),
            BackendMetricPropagation::from_metric_specs::<&str>([]),
        ] {
            assert!(!propagation.propagates_any());
            assert!(!propagation.propagates_cpu_utilization());
            assert!(!propagation.propagates_mem_utilization());
            assert!(!propagation.propagates_application_utilization());
            assert!(!propagation.propagates_named_metrics());
            assert!(!propagation.propagates_named_metric("foo"));
        }
    }

    #[test]
    fn parses_utilization_specs() {
        let cpu = BackendMetricPropagation::from_metric_specs(["cpu_utilization"]);
        assert!(cpu.propagates_cpu_utilization());
        assert!(!cpu.propagates_mem_utilization());
        assert!(!cpu.propagates_application_utilization());
        assert!(!cpu.propagates_named_metrics());
        assert!(cpu.propagates_any());

        let mem = BackendMetricPropagation::from_metric_specs(["mem_utilization"]);
        assert!(!mem.propagates_cpu_utilization());
        assert!(mem.propagates_mem_utilization());
        assert!(!mem.propagates_application_utilization());

        let app = BackendMetricPropagation::from_metric_specs(["application_utilization"]);
        assert!(!app.propagates_cpu_utilization());
        assert!(!app.propagates_mem_utilization());
        assert!(app.propagates_application_utilization());
    }

    #[test]
    fn parses_named_metric_specs() {
        let all = BackendMetricPropagation::from_metric_specs(["named_metrics.*"]);
        assert!(all.propagates_all_named_metrics());
        assert!(all.propagates_named_metrics());
        assert!(all.propagates_named_metric("foo"));
        assert!(all.propagates_named_metric("bar"));
        assert!(!all.propagates_cpu_utilization());

        let foo = BackendMetricPropagation::from_metric_specs(["named_metrics.foo"]);
        assert!(!foo.propagates_all_named_metrics());
        assert!(foo.propagates_named_metrics());
        assert!(foo.propagates_any());
        assert!(foo.propagates_named_metric("foo"));
        assert!(!foo.propagates_named_metric("bar"));
    }

    #[test]
    fn ignores_unknown_specs() {
        let propagation = BackendMetricPropagation::from_metric_specs([
            "qps",
            "named_metrics",
            "foo.bar",
            "CPU_UTILIZATION",
        ]);
        assert_eq!(propagation, BackendMetricPropagation::default());
    }

    #[test]
    fn parses_mixed_and_duplicate_specs() {
        let propagation = BackendMetricPropagation::from_metric_specs(vec![
            "cpu_utilization".to_owned(),
            "named_metrics.a".to_owned(),
            "cpu_utilization".to_owned(),
            "named_metrics.b".to_owned(),
            "named_metrics.a".to_owned(),
        ]);
        assert!(propagation.propagates_cpu_utilization());
        assert!(!propagation.propagates_mem_utilization());
        assert!(propagation.propagates_named_metric("a"));
        assert!(propagation.propagates_named_metric("b"));
        assert!(!propagation.propagates_named_metric("c"));
        assert_eq!(
            propagation,
            BackendMetricPropagation::from_metric_specs([
                "named_metrics.b",
                "cpu_utilization",
                "named_metrics.a",
            ])
        );
    }

    #[test]
    fn builds_backend_metrics() {
        let metrics = BackendMetrics::new()
            .with_cpu_utilization(0.1)
            .with_mem_utilization(0.2)
            .with_application_utilization(0.3)
            .with_named_metrics([("a", 1.0)]);
        assert_eq!(metrics.cpu_utilization, 0.1);
        assert_eq!(metrics.mem_utilization, 0.2);
        assert_eq!(metrics.application_utilization, 0.3);
        assert_eq!(metrics.named_metrics, [("a", 1.0)]);
        assert_eq!(BackendMetrics::default().named_metrics.count(), 0);
    }
}

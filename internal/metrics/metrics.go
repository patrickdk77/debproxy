// Package metrics registers Prometheus metrics for debproxy.
// All vars are registered with the default prometheus registry.
// The /metrics HTTP endpoint is served on a separate port configured
// via MetricsAddr in the config file; set it to "" to disable.
package metrics

import (
	"runtime/debug"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTPRequestsTotal counts completed HTTP requests.
	// selector_type is "live", "current", or "snapshot".
	HTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "debproxy_http_requests_total",
		Help: "Total HTTP requests served, by selector type and status code.",
	}, []string{"selector_type", "status"})

	// HTTPRequestDuration records request latency in seconds.
	HTTPRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "debproxy_http_request_duration_seconds",
		Help:    "HTTP request latency in seconds, by selector type.",
		Buckets: prometheus.DefBuckets,
	}, []string{"selector_type"})

	// PoolHitsTotal counts .deb/.dsc requests served directly from the cache
	// without fetching from upstream.
	PoolHitsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "debproxy_pool_hits_total",
		Help: "Pool files served from cache (no upstream fetch required).",
	}, []string{"os", "codename", "upstream"})

	// PullThroughsTotal counts pull-through operations (live only).
	// result is "success" or "error".
	PullThroughsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "debproxy_pull_throughs_total",
		Help: "Pull-through fetches from upstream triggered by a client request.",
	}, []string{"os", "codename", "upstream", "result"})

	// SourcePullThroughsTotal counts source-file pull-through operations.
	SourcePullThroughsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "debproxy_source_pull_throughs_total",
		Help: "Source-file pull-through fetches from upstream triggered by a client request.",
	}, []string{"os", "codename", "result"})

	// SnapshotPublishesTotal counts snapshot publish operations.
	SnapshotPublishesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "debproxy_snapshot_publishes_total",
		Help: "Snapshot publish operations, by OS.",
	}, []string{"os"})

	// AutoUpdateFilesTotal counts binary (.deb) files downloaded by the
	// auto_update background syncer, labeled by os, codename, and upstream.
	AutoUpdateFilesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "debproxy_auto_update_files_total",
		Help: "Binary files downloaded by the auto_update background syncer.",
	}, []string{"os", "codename", "upstream"})

	// AutoUpdateSourceFilesTotal counts source files downloaded by the
	// auto_update background syncer, labeled by os, codename, and upstream.
	AutoUpdateSourceFilesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "debproxy_auto_update_source_files_total",
		Help: "Source files downloaded by the auto_update background syncer.",
	}, []string{"os", "codename", "upstream"})

	// GCFilesDeletedTotal counts files removed by the pool/src GC.
	GCFilesDeletedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "debproxy_gc_files_deleted_total",
		Help: "Total orphaned pool/src files deleted by GC runs.",
	})

	// SnapshotsPrunedTotal counts snapshot directories pruned by cleanup.
	SnapshotsPrunedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "debproxy_snapshots_pruned_total",
		Help: "Total snapshot directories pruned by cleanup runs.",
	})

	// GCAbortedTotal counts pool/src GC passes that refused to delete because
	// the orphan ratio looked implausibly high (see maxOrphanRatio in
	// internal/syncer/cleanup.go) -- a signal the reference set itself (the
	// metadata index and/or published snapshots) is broken, not that the
	// pool/src tree is suddenly mostly garbage. Should normally stay at 0;
	// any increment needs investigating before the next cleanup run.
	GCAbortedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "debproxy_gc_aborted_total",
		Help: "GC passes aborted because the orphan ratio looked implausibly high, labeled by kind (pool/src).",
	}, []string{"kind"})

	// MetadataEntriesPrunedTotal counts metadata index entries removed because
	// their pool/src file no longer exists in storage -- the reverse of
	// GCFilesDeletedTotal (which removes files with no metadata entry).
	MetadataEntriesPrunedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "debproxy_metadata_entries_pruned_total",
		Help: "Total metadata index entries removed because their pool/src file no longer exists.",
	})

	// BuildInfo exposes the running binary's VCS revision as a gauge fixed at 1,
	// labeled with revision info. Unlike the *Vec metrics above, it is set once
	// here so it is always present in /metrics from process start, letting
	// Grafana/Prometheus queries key off it (e.g. template variables) and
	// correlate other series with the deployed version.
	BuildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "debproxy_build_info",
		Help: "Build information about the running debproxy binary. Always 1.",
	}, []string{"revision", "modified"})

	// APIRequestsTotal counts completed /api/v1 requests, by resource,
	// action, and status code (as a string, matching HTTPRequestsTotal's own
	// convention).
	APIRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "debproxy_api_requests_total",
		Help: "Total /api/v1 requests served, by resource, action, and status code.",
	}, []string{"resource", "action", "status"})

	// APIAuthFailuresTotal counts /api/v1 authentication/authorization
	// failures, by reason ("invalid_credentials" or "not_permitted").
	APIAuthFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "debproxy_api_auth_failures_total",
		Help: "Total /api/v1 authentication/authorization failures, by reason.",
	}, []string{"reason"})

	// OperationDuration records how long each admin operation (snapshot,
	// cleanup, update, rebuild, prime) took, whether triggered via /api or a
	// periodic scheduler.
	OperationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "debproxy_operation_duration_seconds",
		Help:    "Admin operation latency in seconds, by operation.",
		Buckets: prometheus.ExponentialBuckets(1, 2, 12), // 1s .. ~34min
	}, []string{"operation"})

	// OperationFailuresTotal counts admin operations that ended in failure.
	OperationFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "debproxy_operation_failures_total",
		Help: "Total admin operations that ended in failure, by operation.",
	}, []string{"operation"})

	// APIJobQueueDepth is the current number of queued-or-running async
	// admin-operation jobs on this replica -- lets a bulk `prime` submission
	// watch its own drain progress instead of polling every individual
	// job_id.
	APIJobQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "debproxy_api_job_queue_depth",
		Help: "Current number of queued or running async /api/v1 admin-operation jobs on this replica.",
	})

	// FileCacheRequestsTotal counts internal/storage/filecache lookups, by
	// result ("hit" or "miss"). No-op (never incremented) when the cache is
	// disabled (storage.file_cache.size unset or "0").
	FileCacheRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "debproxy_file_cache_requests_total",
		Help: "Total storage file-cache lookups, by result (hit or miss).",
	}, []string{"result"})

	// FileCacheBytes is the file cache's current total size in bytes.
	FileCacheBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "debproxy_file_cache_bytes",
		Help: "Current total size of the storage file cache, in bytes.",
	})

	// FileCacheEvictionsTotal counts entries evicted from the file cache to
	// stay within its configured size budget (does not include entries
	// invalidated because their underlying path was written or deleted).
	FileCacheEvictionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "debproxy_file_cache_evictions_total",
		Help: "Total entries evicted from the storage file cache to stay within its size budget.",
	})
)

func init() {
	revision, modified := "unknown", "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.modified":
				modified = s.Value
			}
		}
	}
	BuildInfo.WithLabelValues(revision, modified).Set(1)
}

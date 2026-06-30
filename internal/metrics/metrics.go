// Package metrics registers Prometheus metrics for debproxy.
// All vars are registered with the default prometheus registry.
// The /metrics HTTP endpoint is served on a separate port configured
// via MetricsAddr in the config file; set it to "" to disable.
package metrics

import (
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
)

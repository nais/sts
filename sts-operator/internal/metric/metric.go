package metric

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	OAuthClientsTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "oauth_client_total",
		})
	OAuthClientsProcessedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "oauth_client_processed_count",
			Help: "Number of OAuth clients processed",
		},
	)
	OAuthClientsFinalizedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "oauth_client_finalized_count",
			Help: "Number of OAuth clients finalized",
		},
	)
	OAuthClientsProcessingFailedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "oauth_client_processing_failed_count",
			Help: "Number of OAuth clients that failed to process",
		},
	)
)

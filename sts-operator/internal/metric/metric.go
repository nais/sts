package metric

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	STSClientsTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "sts_client_total",
		})
	STSClientsProcessedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "sts_client_processed_count",
			Help: "Number of STS clients processed",
		},
	)
	STSClientsFinalizedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "sts_client_finalized_count",
			Help: "Number of STS clients finalized",
		},
	)
	STSClientsProcessingFailedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "sts_client_processing_failed_count",
			Help: "Number of STS clients that failed to process",
		},
	)

	ctx = context.Background()
)

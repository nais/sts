package metric

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestOAuthClientMetricNames(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(
		OAuthClientsTotal,
		OAuthClientsProcessedCount,
		OAuthClientsFinalizedCount,
		OAuthClientsProcessingFailedCount,
	)

	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"oauth_client_total":                   true,
		"oauth_client_processed_count":         true,
		"oauth_client_finalized_count":         true,
		"oauth_client_processing_failed_count": true,
	}
	for _, family := range families {
		name := family.GetName()
		if !want[name] {
			t.Errorf("unexpected metric %q", name)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("missing metric %q", name)
	}
}

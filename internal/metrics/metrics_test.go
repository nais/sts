package metrics

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMetrics(t *testing.T) {
	provider, err := NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})

	metrics := provider.Metrics()
	metrics.ObserveTokenStep(t.Context(), "get_client", time.Now(), nil)
	metrics.ObserveTokenStep(t.Context(), "authorize_target", time.Now(), errors.New("denied"))

	families, err := provider.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "sts_token_step_duration_seconds" {
			continue
		}
		if got := len(family.Metric); got != 2 {
			t.Errorf("token step duration series count = %d, want 2", got)
		}
		return
	}
	t.Error("token step duration metric was not gathered")
}

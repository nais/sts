package metrics

import (
	"context"
	"errors"
	"testing"
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
	finish := metrics.StartTokenGrant(t.Context(), "client_credentials")
	finish(nil)
	finish = metrics.StartTokenStep(t.Context(), "get_client")
	finish(nil)
	finish = metrics.StartTokenStep(t.Context(), "authorize_target")
	finish(errors.New("denied"))

	families, err := provider.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{
		"sts_token_grant_duration_seconds": 1,
		"sts_token_step_duration_seconds":  2,
	}
	for _, family := range families {
		expected, ok := want[family.GetName()]
		if !ok {
			continue
		}
		if got := len(family.Metric); got != expected {
			t.Errorf("%s series count = %d, want %d", family.GetName(), got, expected)
		}
		delete(want, family.GetName())
	}
	for name := range want {
		t.Errorf("metric %s was not gathered", name)
	}
}

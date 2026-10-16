package api

import "testing"

func TestWorkloadClientID(t *testing.T) {
	workload := Workload{
		Environment: "dev",
		Issuer:      "https://issuer.example",
		Namespace:   "team",
		Name:        "app",
	}
	if got, want := workload.ClientID(), "dev:team:app"; got != want {
		t.Fatalf("got client ID %q, want %q", got, want)
	}
}

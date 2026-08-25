package oauth

import (
	"os"
	"testing"
)

func TestLoadRegistrationStore(t *testing.T) {
	path := t.TempDir() + "/registrations.yaml"
	data := `clients:
  client-a:
    workloadIssuer: https://issuer.example
    workloadSubject: subject-a
    allowedAudiences: [https://api.example]
subjectTokenIssuers:
  - https://subject-issuer.example
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	registrations, err := LoadRegistrationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if registrations.clients["client-a"].GetID() != "client-a" {
		t.Fatalf("client ID = %q", registrations.clients["client-a"].GetID())
	}
	if _, ok := registrations.subjectTokenIssuers["https://subject-issuer.example"]; !ok {
		t.Fatal("subject token issuer not loaded")
	}
}

func TestLoadRegistrationStoreRejectsUnknownFields(t *testing.T) {
	path := t.TempDir() + "/registrations.yaml"
	if err := os.WriteFile(path, []byte("unknown: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistrationStore(path); err == nil {
		t.Fatal("LoadRegistrationStore returned nil error")
	}
}

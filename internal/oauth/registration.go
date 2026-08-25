package oauth

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
)

type RegistrationStore struct {
	clients             map[string]*Client
	subjectTokenIssuers map[string]struct{}
}

type registrationConfig struct {
	Clients             map[string]*Client `yaml:"clients"`
	SubjectTokenIssuers []string           `yaml:"subjectTokenIssuers"`
}

func LoadRegistrationStore(path string) (*RegistrationStore, error) {
	file, err := os.Open(path) // #nosec G304 -- operators configure this local startup file path.
	if err != nil {
		return nil, fmt.Errorf("open registrations file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var cfg registrationConfig
	decoder := yaml.NewDecoder(file, yaml.DisallowUnknownField())
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode registrations file: %w", err)
	}

	registrations := &RegistrationStore{
		clients:             cfg.Clients,
		subjectTokenIssuers: make(map[string]struct{}, len(cfg.SubjectTokenIssuers)),
	}
	for id, client := range registrations.clients {
		if client == nil {
			return nil, fmt.Errorf("client %q has no configuration", id)
		}
		client.id = id
	}
	for _, issuer := range cfg.SubjectTokenIssuers {
		registrations.subjectTokenIssuers[issuer] = struct{}{}
	}
	return registrations, nil
}

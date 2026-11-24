package registration

import (
	"testing"

	"github.com/nais/sts/api"
	"github.com/stretchr/testify/require"
)

func TestSoftwareStatementValidate(t *testing.T) {
	valid := func() SoftwareStatement {
		return SoftwareStatement{
			Client: api.Client{Namespace: "team-a", Name: "workload-1"},
			AuthorizationPolicy: api.AuthorizationPolicy{
				Clients: []api.AuthorizedClient{{
					Namespace: "team-b", Name: "workload-2",
					Roles: []string{"reader", "writer"},
				}},
				AllowedNamespaces:    []string{"team-c", "team-d"},
				AllowedImpersonators: []api.Impersonator{{Issuer: "https://identity.example", Subject: "alice"}},
			},
		}
	}

	tests := map[string]struct {
		mutate  func(*SoftwareStatement)
		wantErr string
	}{
		"valid": {},
		"invalid namespace": {
			mutate:  func(s *SoftwareStatement) { s.Client.Namespace = "team_a" },
			wantErr: "client: namespace",
		},
		"invalid consumer": {
			mutate:  func(s *SoftwareStatement) { s.AuthorizationPolicy.Clients[0].Namespace = "Team-b" },
			wantErr: "authorized client 0",
		},
		"missing impersonator issuer": {
			mutate:  func(s *SoftwareStatement) { s.AuthorizationPolicy.AllowedImpersonators[0].Issuer = "" },
			wantErr: "allowed impersonator 0",
		},
		"missing impersonator subject": {
			mutate:  func(s *SoftwareStatement) { s.AuthorizationPolicy.AllowedImpersonators[0].Subject = "" },
			wantErr: "allowed impersonator 0",
		},
		"invalid allowed namespace": {
			mutate:  func(s *SoftwareStatement) { s.AuthorizationPolicy.AllowedNamespaces[1] = "*" },
			wantErr: "allowed namespace 1",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			statement := valid()
			if test.mutate != nil {
				test.mutate(&statement)
			}
			err := statement.validate()
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

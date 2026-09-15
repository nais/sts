package registration

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSoftwareStatementValidate(t *testing.T) {
	valid := func() SoftwareStatement {
		return SoftwareStatement{
			ClientId: "client-1",
			Workload: Workload{
				Environment: "prod",
				Issuer:      "https://issuer.example",
				Namespace:   "team-a",
				Name:        "workload-1",
			},
			AuthorizationPolicies: []AuthorizationPolicy{{
				Consumer: "client-2",
				Roles:    []string{"reader", "writer"},
			}},
		}
	}

	tests := map[string]struct {
		mutate  func(*SoftwareStatement)
		wantErr string
	}{
		"valid": {},
		"uppercase client ID": {
			mutate:  func(s *SoftwareStatement) { s.ClientId = "Client-1" },
			wantErr: "client_id",
		},
		"invalid environment": {
			mutate:  func(s *SoftwareStatement) { s.Workload.Environment = "Prod" },
			wantErr: "workload environment",
		},
		"invalid namespace": {
			mutate:  func(s *SoftwareStatement) { s.Workload.Namespace = "team_a" },
			wantErr: "workload namespace",
		},
		"invalid workload": {
			mutate:  func(s *SoftwareStatement) { s.Workload.Name = "workload.name" },
			wantErr: "workload name",
		},
		"insecure issuer": {
			mutate:  func(s *SoftwareStatement) { s.Workload.Issuer = "http://issuer.example" },
			wantErr: "workload issuer",
		},
		"invalid consumer": {
			mutate:  func(s *SoftwareStatement) { s.AuthorizationPolicies[0].Consumer = "Client-2" },
			wantErr: "consumer",
		},
		"duplicate policy": {
			mutate: func(s *SoftwareStatement) {
				duplicate := s.AuthorizationPolicies[0]
				duplicate.Roles = []string{"other"}
				s.AuthorizationPolicies = append(s.AuthorizationPolicies, duplicate)
			},
			wantErr: "duplicated",
		},
		"empty roles": {
			mutate:  func(s *SoftwareStatement) { s.AuthorizationPolicies[0].Roles = nil },
			wantErr: "roles must not be empty",
		},
		"invalid role": {
			mutate:  func(s *SoftwareStatement) { s.AuthorizationPolicies[0].Roles = []string{"team:reader"} },
			wantErr: "role 0 is invalid",
		},
		"role too long": {
			mutate: func(s *SoftwareStatement) {
				s.AuthorizationPolicies[0].Roles = []string{strings.Repeat("a", maxRoleLength+1)}
			},
			wantErr: "role 0 is too long",
		},
		"duplicate role": {
			mutate:  func(s *SoftwareStatement) { s.AuthorizationPolicies[0].Roles = []string{"reader", "reader"} },
			wantErr: "role \"reader\" is duplicated",
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

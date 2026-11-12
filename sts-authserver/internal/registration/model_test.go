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
			AuthorizationPolicies: []api.AuthorizationPolicy{{
				Consumer: api.Client{Namespace: "team-b", Name: "workload-2"},
				Roles:    []string{"reader", "writer"},
			}},
			ConsumerNamespaces: []string{"team-c", "team-d"},
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
		"invalid workload": {
			mutate:  func(s *SoftwareStatement) { s.Client.Name = "workload.name" },
			wantErr: "client: name",
		},
		"invalid consumer": {
			mutate:  func(s *SoftwareStatement) { s.AuthorizationPolicies[0].Consumer.Namespace = "Team-b" },
			wantErr: "consumer",
		},
		"nil roles": {
			mutate: func(s *SoftwareStatement) { s.AuthorizationPolicies[0].Roles = nil },
		},
		"empty roles": {
			mutate: func(s *SoftwareStatement) { s.AuthorizationPolicies[0].Roles = []string{} },
		},
		"invalid consumer namespace": {
			mutate:  func(s *SoftwareStatement) { s.ConsumerNamespaces[1] = "*" },
			wantErr: "consumer namespace 1",
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

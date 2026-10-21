package oauth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNameValidate(t *testing.T) {
	for _, name := range []Name{"client", "client-1"} {
		require.NoError(t, name.Validate())
	}
	for _, name := range []Name{"", "1client", "Client", "client:", "client.name"} {
		require.Error(t, name.Validate())
	}
}

func TestClientIDValidate(t *testing.T) {
	for _, clientID := range []ClientID{"env1:namespace1:workload1", NewClientID("env", "namespace", "name")} {
		require.NoError(t, clientID.Validate())
	}
	for _, clientID := range []ClientID{"", "client", "env:namespace", "env:namespace:name:extra", "1client", "Client", "client:", "client::target", "client.name"} {
		require.Error(t, clientID.Validate())
	}
}

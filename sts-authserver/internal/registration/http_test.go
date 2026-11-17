package registration

import (
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeClientRegistrationRejectsInvalidBodies(t *testing.T) {
	for name, body := range map[string]string{
		"wrong type":                  `{"software_statement":1}`,
		"truncated":                   `{"software_statement":`,
		"second JSON value":           `{"software_statement":"statement"} {}`,
		"trailing malformed data":     `{"software_statement":"statement"} trailing`,
		"null":                        `null`,
		"missing software statement":  `{}`,
		"blank software statement":    `{"software_statement":"  "}`,
		"software statement too long": `{"software_statement":"` + strings.Repeat("a", maxSoftwareStatementLength+1) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(nethttp.MethodPost, "/v1/registration/client", strings.NewReader(body))
			_, err := decodeClientRegistration(httptest.NewRecorder(), request)
			require.Error(t, err)
		})
	}
}

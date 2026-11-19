package impersonation

import (
	"fmt"
	nethttp "net/http"

	"github.com/nais/sts/internal/http"
	"github.com/nais/sts/internal/jwt"
)

const TokenPath = "/impersonation/token"

func (i *Api) TokenEndpoint() nethttp.HandlerFunc {
	return http.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) error {
		token, ok := http.BearerToken(r)
		if !ok {
			return fmt.Errorf("missing bearer token")
		}

		claims, err := i.ClientAuthVerifier.Verify(r.Context(), token)
		if err != nil {
			return fmt.Errorf("verify bearer token: %w", err)
		}
		authenticatedUser := AuthenticatedUser{Claims: claims}

		req, err := http.ReadJSON[Request](w, r)
		if err != nil {
			return err
		}


		resp, err := i.handle(r.Context(),  req, authenticatedUser)
		if err != nil {
			return err
		}

		http.WriteJSON(w, r, resp)
		return nil
	})
}

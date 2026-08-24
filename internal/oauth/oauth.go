package oauth

import (
	"net/http"

	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

type authServer struct {
	op.UnimplementedServer
}

type localStorage struct{}

type stsProvider struct {
	op.Provider
}

func (s stsProvider) AuthorizationEndpoint() *op.Endpoint {
	return nil
}

func (s stsProvider) IntrospectionEndpoint() *op.Endpoint {
	return nil
}

func (s stsProvider) UserinfoEndpoint() *op.Endpoint {
	return nil
}

func (s stsProvider) RevocationEndpoint() *op.Endpoint {
	return nil
}

func (s stsProvider) EndSessionEndpoint() *op.Endpoint {
	return nil
}

func (s stsProvider) DeviceAuthorizationEndpoint() *op.Endpoint {
	return nil
}

func (s stsProvider) CheckSessionIframe() *op.Endpoint {
	return nil
}

func (s stsProvider) AuthMethodPostSupported() bool {
	return false
}

func (s stsProvider) CodeMethodS256Supported() bool {
	return false
}

func (s stsProvider) AuthMethodPrivateKeyJWTSupported() bool {
	return false
}

func (s stsProvider) GrantTypeRefreshTokenSupported() bool {
	return false
}

func (s stsProvider) GrantTypeJWTAuthorizationSupported() bool {
	return false
}

func (s stsProvider) GrantTypeDeviceCodeSupported() bool {
	return false
}

func (s stsProvider) IntrospectionAuthMethodPrivateKeyJWTSupported() bool {
	return false
}

func (s stsProvider) IntrospectionEndpointSigningAlgorithmsSupported() []string {
	return nil
}

func (s stsProvider) RevocationAuthMethodPrivateKeyJWTSupported() bool {
	return false
}

func (s stsProvider) RevocationEndpointSigningAlgorithmsSupported() []string {
	return nil
}

func (s stsProvider) RequestObjectSupported() bool {
	return false
}

func (s stsProvider) RequestObjectSigningAlgorithmsSupported() []string {
	return nil
}

func (s stsProvider) SupportedUILocales() []language.Tag {
	return nil
}

func (s stsProvider) BackChannelLogoutSupported() bool {
	return false
}

func (s stsProvider) BackChannelLogoutSessionSupported() bool {
	return false
}

var _ op.Server = (*authServer)(nil)

//var _ op.Storage = (*localStorage)(nil)

var _ op.Configuration = (*stsProvider)(nil)

func NewServer(issuer string, endpoints *op.Endpoints) (http.Handler, error) {
	userStore := storage.NewUserStore(issuer)
	provider, err := op.NewProvider(
		&op.Config{},
		storage.NewStorage(userStore),
		op.StaticIssuer(issuer),
		op.WithAllowInsecure(),
	)
	if err != nil {
		return nil, err
	}

	server := op.NewLegacyServer(provider, *endpoints)
	return op.RegisterServer(server, *endpoints), nil
}

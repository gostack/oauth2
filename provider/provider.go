package provider

import (
	"net/http"

	"github.com/gostack/oauth2/common"
)

type Client struct {
	ID, secret string
}

type AuthorizationGrant interface {
	Perform(*http.Request, Client) *common.TokenResponse
}

// TokenEndpointHandler implements the http handler for the OAuth2 token
// endpoint.
type TokenEndpointHandler struct {
	grants map[string]AuthorizationGrant
}

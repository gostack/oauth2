package oauth2

import (
	"io"
	"net/http"
)

type Backend interface {
	// AuthorizationPersist persists the provided Authorization in the backend
	AuthorizationPersist(a *Authorization) error

	// AuthorizationAuthenticate takes an access token and returns the authorization
	// it represents, if exists.
	AuthorizationAuthenticate(accessToken string) (*Authorization, error)

	// ClientLookup returns the Client that is identified by the provided id.
	ClientLookup(clientID string) (*Client, error)

	// ClientPerist persists the provided client in the backend
	ClientPersist(c *Client) error

	// RenderAuthorizationPage should write to the io.Writer the HTML for the
	// authorization page.
	RenderAuthorizationPage(c *Client, u *User, scope string, redirectURI string, w io.Writer) error

	// UserAuthenticate should authenticate a user using the provided username
	// and password and return a User object or an error.
	UserAuthenticate(username, password string) (*User, error)

	// UserLoggedIn should take an http request and extract the current logged
	// user from it.
	UserLoggedIn(req *http.Request) (*User, error)
}

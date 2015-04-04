package oauth2

import (
	"errors"
	"net/http"
)

// ErrNotFound should be returned by any Get* methods defined in PersistenceBackend
// when the object could not be found.
var ErrNotFound = errors.New("object not found")

// PersistenceBackend defines the interface necessary for persistence, which needs to
// be implemented by users of this library.
//
// If an object can't be found by any of the Get* methods, it should return ErrNotFound.
type PersistenceBackend interface {
	//*
	// Authorization persistence
	//*
	GetAuthorizationByCode(code string) (*Authorization, error)
	GetAuthorizationByAccessToken(accessToken string) (*Authorization, error)
	GetAuthorizationByRefreshToken(refreshToken string) (*Authorization, error)
	SaveAuthorization(a *Authorization) error

	//*
	// Client persistence
	//*
	GetClientByID(ID string) (*Client, error)
	SaveClient(c *Client) error

	//*
	// Scope persistence
	//*
	GetScopesByID(scopeIDs ...string) ([]*Scope, error)

	//*
	// User persistence
	//*
	GetUserByCredentials(username, password string) (*User, error)
}

type AuthorizationPageData struct {
	Client *Client
	User   *User
	Scopes []*Scope
}

type ErrorPageData struct {
	Error Error
}

type HTTPBackend interface {
	// RenderAuthorizationPage should write to the io.Writer the HTML for the
	// authorization page.
	RenderAuthorizationPage(w http.ResponseWriter, req *http.Request, data *AuthorizationPageData) error

	// RenderErrorPage should write to the io.Writer the HTML the error page.
	RenderErrorPage(w http.ResponseWriter, req *http.Request, err *ErrorPageData) error

	// AuthenticateRequest should take an http.Request and either return
	// the current logged in user or generate a response that will allow the
	// user to login, such as a redirect. If the later happens, both User and
	// error should be nil.
	AuthenticateRequest(c *Client, w http.ResponseWriter, req *http.Request) (*User, error)
}

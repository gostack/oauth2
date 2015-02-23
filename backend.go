package oauth2

import (
	"errors"
	"io"
	"net/http"
)

var (
	ErrNotFound = errors.New("object not found")
)

// PersistenceBackend defines the interface necessary for persistence, which needs to
// be implemented by users of this library.
// If an object can't be found by any of the Get* methods, it should return ErrNotFound.
type PersistenceBackend interface {
	//*
	// Authorization persistence
	//*
	SaveAuthorization(a *Authorization) error
	GetAuthorizationByCode(code string) (*Authorization, error)
	GetAuthorizationByAccessToken(code string) (*Authorization, error)

	//*
	// Client persistence
	//*
	SaveClient(c *Client) error
	GetClientByID(ID string) (*Client, error)

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

type HTTPBackend interface {
	// RenderAuthorizationPage should write to the io.Writer the HTML for the
	// authorization page.
	RenderAuthorizationPage(w io.Writer, data *AuthorizationPageData) error

	// AuthenticateRequest should take an http.Request and either return
	// the current logged in user or generate a response that will allow the
	// user to login, such as a redirect. If the later happens, both User and
	// error should be nil.
	AuthenticateRequest(w http.ResponseWriter, req *http.Request) (*User, error)
}

package oauth2

import (
	"html/template"
	"io"
	"net/http"
)

var (
	tplAuthorization = template.Must(template.New("authorization").Parse(`
<!DOCTYPE html>
<html>
	<head>
		<title>Doximity</title>
	</head>

	<body>
		<form method="POST">
			<button type="submit" name="action" value="authorize">Authorize</button>
			<button type="submit" name="action" value="deny">Deny</button>
		</form>
	</body>
</html>
`))
)

// TestBackend is a simple backend implementation that keeps all data
// in memory and it's meant to be used for test or demo purposes.
// It is not a safe implementation, so it shouldn't be used in production.
type TestBackend struct {
	// clients holds the references to the existing clients,
	// indexed by their client IDs.
	clients map[string]*Client

	// users holds the references to existing users in the system,
	// indexed by their login
	users map[string]*User

	// authorizations holds the existing authorizations indexed by
	// access token
	authorizations map[string]*Authorization
}

func NewTestBackend() *TestBackend {
	return &TestBackend{
		clients:        make(map[string]*Client),
		users:          make(map[string]*User),
		authorizations: make(map[string]*Authorization),
	}
}

// AuthorizationPersist stores the authorization in the backend
func (b *TestBackend) AuthorizationPersist(a *Authorization) error {
	b.authorizations[a.AccessToken] = a
	return nil
}

// AuthorizationAuthenticate takes an access token and returns the authorization
// it represents, if exists.
func (b *TestBackend) AuthorizationAuthenticate(accessToken string) (*Authorization, error) {
	a, exst := b.authorizations[accessToken]
	if !exst {
		return nil, ErrAccessDenied
	}

	return a, nil
}

// ClientPersist persists the client
func (b *TestBackend) ClientPersist(c *Client) error {
	b.clients[c.ID] = c
	return nil
}

// ClientLookup fetches the Client instance using it's client id
func (b *TestBackend) ClientLookup(clientID string) (*Client, error) {
	c, exst := b.clients[clientID]
	if !exst {
		return nil, ErrInvalidClient
	}

	return c, nil
}

// RenderAuthorizationPage writes the HTML for the user authorization page
func (b *TestBackend) RenderAuthorizationPage(w io.Writer) error {
	return tplAuthorization.Execute(w, nil)
}

// UserAuthenticate lookup the user that matches the username and password
func (b *TestBackend) UserAuthenticate(username, password string) (*User, error) {
	u, exst := b.users[username]
	if !exst || password != "validpassword" {
		return nil, ErrAccessDenied
	}

	return u, nil
}

// UserLoggedIn takes an http request and extract the current logged
// user from it.
func (b *TestBackend) UserLoggedIn(req *http.Request) (*User, error) {
	return nil, nil
}

// UserPersist persists the user in the backend, it's not part of the Backend interface
// but we need a way to add users to the Backend.
func (b *TestBackend) UserPersist(u *User) error {
	b.users[u.Login] = u
	return nil
}

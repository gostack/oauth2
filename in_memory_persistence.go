package oauth2

// InMemoryPersistence is a simple backend implementation that keeps all data
// in memory and it's meant to be used for test or demo purposes.
// It is not a safe implementation, so it shouldn't be used in production.
type InMemoryPersistence struct {
	validPassword string

	// clients holds the references to the existing clients,
	// indexed by their client IDs.
	clients map[string]*Client

	// users holds the references to existing users in the system,
	// indexed by their login
	users map[string]*User

	// authorizations holds the existing authorizations indexed by
	// access token
	authorizations []*Authorization

	// scopes holds the existing scopes indexed by id
	scopes map[string]*Scope
}

func NewInMemoryPersistence(validPassword string) *InMemoryPersistence {
	return &InMemoryPersistence{
		validPassword:  validPassword,
		clients:        make(map[string]*Client),
		users:          make(map[string]*User),
		authorizations: make([]*Authorization, 0),
		scopes:         make(map[string]*Scope),
	}
}

// SaveAuthorization stores the authorization in the backend
func (b *InMemoryPersistence) SaveAuthorization(a *Authorization) error {
	if id, ok := a.InternalID.(int); ok {
		b.authorizations[id] = a
	} else {
		a.InternalID = len(b.authorizations)
		b.authorizations = append(b.authorizations, a)
	}

	return nil
}

// GetAuthorizationByCode takes a code and look it up
func (b *InMemoryPersistence) GetAuthorizationByCode(code string) (*Authorization, error) {
	for _, a := range b.authorizations {
		if a.Code == code {
			return a, nil
		}
	}

	return nil, ErrNotFound
}

// GetAuthorizationByAccessToken takes an access token and returns the authorization
// it represents, if exists.
func (b *InMemoryPersistence) GetAuthorizationByAccessToken(accessToken string) (*Authorization, error) {
	for _, a := range b.authorizations {
		if a.AccessToken == accessToken {
			return a, nil
		}
	}

	return nil, ErrNotFound
}

// GetAuthorizationByRefreshToken takes an access token and returns the authorization
// it represents, if exists.
func (b *InMemoryPersistence) GetAuthorizationByRefreshToken(refreshToken string) (*Authorization, error) {
	for _, a := range b.authorizations {
		if a.RefreshToken == refreshToken {
			return a, nil
		}
	}

	return nil, ErrNotFound
}

// SaveClient persists the client
func (b *InMemoryPersistence) SaveClient(c *Client) error {
	b.clients[c.ID] = c
	return nil
}

// GetClientByID fetches the Client instance using it's client id
func (b *InMemoryPersistence) GetClientByID(ID string) (*Client, error) {
	c, exst := b.clients[ID]
	if !exst {
		return nil, ErrNotFound
	}

	return c, nil
}

// GetScopesByID takes scope IDs and fetches the Scope from backend
func (b *InMemoryPersistence) GetScopesByID(IDs ...string) ([]*Scope, error) {
	s := make([]*Scope, 0)
	for _, id := range IDs {
		scope, exst := b.scopes[id]
		if !exst {
			return nil, ErrNotFound
		}

		s = append(s, scope)
	}

	return s, nil
}

// SaveScope persists the scope in the backend, it's not part of the Backend interface
// but we need a way to add scopes to the Backend.
func (b *InMemoryPersistence) SaveScope(s *Scope) error {
	b.scopes[s.ID] = s
	return nil
}

// GetUserByCredentials lookup the user that matches the username and password
func (b *InMemoryPersistence) GetUserByCredentials(username, password string) (*User, error) {
	u, exst := b.users[username]
	if !exst || password != "validpassword" {
		return nil, ErrAccessDenied
	}

	return u, nil
}

// SaveUser persists the user in the backend, it's not part of the Backend interface
// but we need a way to add users to the Backend.
func (b *InMemoryPersistence) SaveUser(u *User) error {
	b.users[u.Login] = u
	return nil
}

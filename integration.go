package oauth2

type Backend interface {
	AuthenticateUser(username, password string) (*User, error)
	LookupClient(id string) (*Client, error)
	Authorize(c *Client, u *User, scope string) (*Authorization, error)
}

type User struct {
	ID int64
}

type Client struct {
	ID, Secret string
	Internal   bool
}

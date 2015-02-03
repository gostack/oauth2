package provider

var storage Storage

type Storage interface {
	LookupClient(ID string) (*Client, error)
	AuthenticateUser(username, password string) bool
}

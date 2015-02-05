package provider

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gostack/oauth2/client"
	"github.com/gostack/oauth2/common"
)

type testBackend struct{}

func (i testBackend) AuthenticateUser(username, password string) (*User, error) {
	if username == "username" && password == "password" {
		return &User{ID: 1}, nil
	} else {
		return nil, errors.New("invalid user")
	}
}

func (i testBackend) LookupClient(id string) (*Client, error) {
	if id == "e6e41132d34a952627375a94f08823fb219a828d" {
		return &Client{
			ID:       "e6e41132d34a952627375a94f08823fb219a828d",
			Secret:   "3fa181c93f330cd832c290ba310486a73c32dbe22178c7b3faa96a5236a1d7ab649058c33e060de3f3ebee63e7e976c77693e433addbc0e81bf17b679b350d9f",
			Internal: true,
		}, nil
	}

	return nil, errors.New("invalid client")
}

func (i testBackend) Authorize(c *Client, u *User, scope string) (*Authorization, error) {
	return &Authorization{
		AccessToken:  "fe23f7f48d1856785f4eeda57e52fffada592df7dc24e580401e2d6007cf23d557b5fb36588539a2f477f657e127c94644796e1ad9afb785fa69df0a1b6e473d",
		TokenType:    "bearer",
		ExpiresIn:    3600,
		RefreshToken: "0ca5e99b50b8cd9393265a3ce64338635cf1182984236d9832e77a1431efb814b7c79d93710ce1f95992f608ecbd2ba20104644664ef41ab6293ed0a5417666c",
		Scope:        scope,
	}, nil
}

func TestPasswordGrantType(t *testing.T) {
	p := New(testBackend{})
	srv := httptest.NewServer(p.HTTPHandler())
	defer srv.Close()

	c := client.Client{
		AuthBaseURL: srv.URL,
		ID:          "e6e41132d34a952627375a94f08823fb219a828d",
		Secret:      "3fa181c93f330cd832c290ba310486a73c32dbe22178c7b3faa96a5236a1d7ab649058c33e060de3f3ebee63e7e976c77693e433addbc0e81bf17b679b350d9f",
	}

	tr, err := c.ResourceOwnerCredentials("username", "password", "scope")
	if err != nil {
		t.Fatal(err)
	}

	expected := common.Authorization{
		AccessToken:  "fe23f7f48d1856785f4eeda57e52fffada592df7dc24e580401e2d6007cf23d557b5fb36588539a2f477f657e127c94644796e1ad9afb785fa69df0a1b6e473d",
		TokenType:    "bearer",
		ExpiresIn:    3600,
		RefreshToken: "0ca5e99b50b8cd9393265a3ce64338635cf1182984236d9832e77a1431efb814b7c79d93710ce1f95992f608ecbd2ba20104644664ef41ab6293ed0a5417666c",
		Scope:        "scope",
	}
	if *tr != expected {
		t.Errorf("Unexpected token response: %#v", tr)
	}
}

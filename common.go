package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

type User struct {
	Login string
}

type Client struct {
	ID, Secret   string
	Internal     bool
	Confidential bool
}

func NewClient() (*Client, error) {
	c := Client{}

	if b, err := secureRandomBytes(32); err != nil {
		return nil, err
	} else {
		c.ID = hex.EncodeToString(b)
	}

	if b, err := secureRandomBytes(64); err != nil {
		return nil, err
	} else {
		c.Secret = hex.EncodeToString(b)
	}

	return &c, nil
}

type Authorization struct {
	Client *Client `json:"-"`
	User   *User   `json:"-"`

	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

func NewAuthorization(c *Client, u *User, scope string) (*Authorization, error) {
	a := Authorization{
		Client:    c,
		User:      u,
		ExpiresIn: 3600,
		Scope:     scope,
	}

	if b, err := secureRandomBytes(64); err != nil {
		return nil, err
	} else {
		a.AccessToken = base64.URLEncoding.EncodeToString(b)
	}

	if c.Confidential {
		if b, err := secureRandomBytes(128); err != nil {
			return nil, err
		} else {
			a.RefreshToken = base64.URLEncoding.EncodeToString(b)
		}
	}

	return &a, nil
}

func secureRandomBytes(bytes uint) ([]byte, error) {
	r := make([]byte, bytes)
	_, err := rand.Read(r)
	return r, err
}

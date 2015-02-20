package oauth2

import (
	"crypto/rand"
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
	var err error

	a := Authorization{
		Client:    c,
		User:      u,
		ExpiresIn: 3600,
		Scope:     scope,
	}

	a.AccessToken, err = secureRandomHex(64)
	if err != nil {
		return nil, err
	}

	if c.Confidential {
		a.RefreshToken, err = secureRandomHex(128)
		if err != nil {
			return nil, err
		}
	}

	return &a, nil
}

func secureRandomHex(bytes uint) (string, error) {
	r := make([]byte, bytes)
	if _, err := rand.Read(r); err != nil {
		return "", err
	}

	return hex.EncodeToString(r), nil
}

package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"time"
)

type User struct {
	Login string
}

type Client struct {
	ID, Secret   string
	Name         string
	RedirectURI  string
	Internal     bool
	Confidential bool
}

func NewClient(name, redirectURI string, confidential, internal bool) (*Client, error) {
	c := Client{
		Name:         name,
		RedirectURI:  redirectURI,
		Confidential: confidential,
		Internal:     internal,
	}

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

type Scope struct {
	ID       string
	Desc     string
	UserOnly bool
}

type Authorization struct {
	Client *Client `json:"-"`
	User   *User   `json:"-"`

	Code      string    `json:"-"`
	CreatedAt time.Time `json:"-"`

	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

func NewAuthorization(c *Client, u *User, scope string, refresh bool, code bool) (*Authorization, error) {
	a := Authorization{
		Client:    c,
		User:      u,
		CreatedAt: time.Now().UTC(),
		ExpiresIn: int64((24 * time.Hour * 60).Seconds()),
		Scope:     scope,
	}

	if code {
		if b, err := secureRandomBytes(16); err != nil {
			return nil, err
		} else {
			a.Code = base64.URLEncoding.EncodeToString(b)
		}
	}

	if b, err := secureRandomBytes(64); err != nil {
		return nil, err
	} else {
		a.AccessToken = base64.URLEncoding.EncodeToString(b)
	}

	if refresh {
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

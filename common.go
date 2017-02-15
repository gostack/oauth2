/*
Copyright 2015 Rodrigo Rafael Monti Kochenburger

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

type User interface {
	GetUsername() string
	CheckPassword(password string) bool
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
	User   User    `json:"-"`

	Code         string    `json:"-"`
	CreatedAt    time.Time `json:"-"`
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Scope        string    `json:"scope"`
}

func NewAuthorization(c *Client, u User, scope string, refresh bool, code bool) (*Authorization, error) {
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
			a.Code = hex.EncodeToString(b)
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

func (a *Authorization) Refresh(scope string) error {
	if a.RefreshToken == "" {
		return errors.New("can't refresh a token that has no refresh token")
	}

	existingScopes := strings.Split(a.Scope, " ")
	newScopes := strings.Split(scope, " ")
	finalScopes := make([]string, 0)

	for _, ns := range newScopes {
		for _, es := range existingScopes {
			if ns == es {
				finalScopes = append(finalScopes, ns)
			}
		}
	}

	a.CreatedAt = time.Now().UTC()
	a.ExpiresIn = int64((24 * time.Hour * 60).Seconds())
	a.Scope = strings.Join(finalScopes, " ")

	if b, err := secureRandomBytes(64); err != nil {
		return err
	} else {
		a.AccessToken = base64.URLEncoding.EncodeToString(b)
	}

	if b, err := secureRandomBytes(128); err != nil {
		return err
	} else {
		a.RefreshToken = base64.URLEncoding.EncodeToString(b)
	}

	return nil
}

func secureRandomBytes(bytes uint) ([]byte, error) {
	r := make([]byte, bytes)
	_, err := rand.Read(r)
	return r, err
}

// secureCompare will compare two slice of bytes in constant time, ensuring no timing information
// is leaked in order to prevent timing attacks.
func secureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

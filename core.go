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
	"errors"
	"net/http"
)

// AbstractUser is an abstract type representing the current user in the system.
type AbstractUser interface{}

// Client represents a known client application using this OAuth2 server to authenticate.
//
// Related RFC topics:
// https://tools.ietf.org/html/rfc6749#section-1.1
// https://tools.ietf.org/html/rfc6749#section-2
type Client struct {
	ID           string
	Secret       string
	Name         string
	RedirectURI  string
	Confidential bool
	Internal     bool
}

// Init
// TODO(divoxx): Remove this
func (c *Client) Init() error {
	return c.generateCredentials()
}

// generateCredentials securely generate and initialize the Client's ID and Secret.
func (c *Client) generateCredentials() error {
	var err error

	c.ID, err = generateToken(32)
	if err != nil {
		return err
	}

	c.Secret, err = generateToken(32)
	if err != nil {
		return err
	}

	return nil
}

// UserAuthorization represents an explicit authorization given by the user to a specific client application.
//
// Related RFC topics:
// https://tools.ietf.org/html/rfc6749#section-4.1
// https://tools.ietf.org/html/rfc6749#section-4.2
type UserAuthorization struct {
	Client       Client
	Scope        []string
	RefreshToken []byte
}

// AccessToken represents an OAuth2 Access Token issued for an application.
//
// Related RFC topics:
// https://tools.ietf.org/html/rfc6749#section-1.1
// https://tools.ietf.org/html/rfc6749#section-1.4
type AccessToken struct {
	Client        Client
	Authorization UserAuthorization

	Token        string
	ExpiresIn    int64
	RefreshToken string
	Scope        string
}

// generateToken generates a random sequence of N bytes and returns it encoded as base64
func generateToken(nBytes int) (string, error) {
	r := make([]byte, nBytes)

	n, err := rand.Read(r)
	if err != nil {
		return "", err
	}
	if nBytes != n {
		return "", errors.New("unexpected length for generated string")
	}

	return base64.RawURLEncoding.EncodeToString(r), nil
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

type Authenticator interface {
	Authenticate(req *http.Request) AbstractUser
}

type Authorizer interface {
	LookupAuthorization(u AbstractUser, c Client, s []string) (*UserAuthorization, error)
	LookupAuthorizationByRefreshToken(t string) (*UserAuthorization, error)
	StoreAccessToken(at AccessToken) error
}

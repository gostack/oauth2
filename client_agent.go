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
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/divoxx/stackerr"
)

// Client is the main entrypoint for this package and it exposes the
// actions the client can perform for authentication purpose.
type ClientAgent struct {
	// ID and Secret are used for identification and authentication of the client
	ID, Secret string

	// AuthBaseURL is the base location for the OAuth2 endpoints
	AuthBaseURL string

	// httpClient is the http client to be used for API calls
	httpClient http.Client
}

// AuthorizationURL implements the password grant type.
func (c ClientAgent) AuthorizationURL(state, scope, redirectURI string) (string, error) {
	u, err := url.ParseRequestURI(c.AuthBaseURL + "/authorize")
	if err != nil {
		return "", err
	}

	u.RawQuery = url.Values{
		"client_id":     []string{c.ID},
		"response_type": []string{"code"},
		"state":         []string{state},
		"scope":         []string{scope},
		"redirect_uri":  []string{redirectURI},
	}.Encode()

	return u.String(), nil
}

// AuthorizationCode implements the password grant type.
func (c ClientAgent) AuthorizationCode(code, redirectURI string) (*Authorization, error) {
	return c.doTokenRequest(url.Values{
		"grant_type":   []string{"authorization_code"},
		"code":         []string{code},
		"redirect_uri": []string{redirectURI},
	})
}

// ResourceOwnerCredentials implements the password grant type.
func (c ClientAgent) ResourceOwnerCredentials(username, password, scope string) (*Authorization, error) {
	return c.doTokenRequest(url.Values{
		"grant_type": []string{"password"},
		"username":   []string{username},
		"password":   []string{password},
		"scope":      []string{scope},
	})
}

// ClientCredentials implements the client credentials grant type.
func (c ClientAgent) ClientCredentials(scope string) (*Authorization, error) {
	return c.doTokenRequest(url.Values{
		"grant_type": []string{"client_credentials"},
		"scope":      []string{scope},
	})
}

// RefreshToken implements the refresh token flow
func (c ClientAgent) RefreshToken(refreshToken, scope string) (*Authorization, error) {
	return c.doTokenRequest(url.Values{
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{refreshToken},
		"scope":         []string{scope},
	})
}

// doTokenRequest performs a request against token endpoint and returns a Authorization.
func (c ClientAgent) doTokenRequest(params url.Values) (*Authorization, error) {
	body := []byte(params.Encode())

	req, err := http.NewRequest("POST", c.AuthBaseURL+"/token", bytes.NewReader(body))
	if err != nil {
		return nil, stackerr.Wrap(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; encoding=utf-8")
	req.SetBasicAuth(c.ID, c.Secret)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, stackerr.Wrap(err)
	}

	dec := json.NewDecoder(res.Body)

	switch res.StatusCode {
	case 200, 201, 202:
		auth := Authorization{}
		return &auth, dec.Decode(&auth)
	case 400, 401, 403, 422:
		knownErr := Error{}
		if err := dec.Decode(&knownErr); err != nil {
			return nil, stackerr.Wrap(err)
		}

		knownErr.Code = res.StatusCode
		return nil, &knownErr
	default:
		return nil, errors.New("don't know how to handle response")
	}
}

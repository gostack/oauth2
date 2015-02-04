package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/divoxx/stackerr"
	"github.com/gostack/oauth2/common"
)

// Client is the main entrypoint for this package and it exposes the
// actions the client can perform for authentication purpose.
type Client struct {
	// ID and Secret are used for identification and authentication of the client
	ID, Secret string

	// AuthBaseURL is the base location for the OAuth2 endpoints
	AuthBaseURL string

	// httpClient is the http client to be used for API calls
	httpClient http.Client
}

// ResourceOwnerCredentials implements the password grant type.
func (c Client) ResourceOwnerCredentials(username, password, scope string) (*common.Authorization, error) {
	return c.doTokenRequest(url.Values{
		"grant_type": []string{"password"},
		"username":   []string{username},
		"password":   []string{password},
		"scope":      []string{scope},
	})
}

// doTokenRequest performs a request against token endpoint and returns a Authorization.
func (c Client) doTokenRequest(params url.Values) (*common.Authorization, error) {
	var auth common.Authorization

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

	if err := json.NewDecoder(res.Body).Decode(&auth); err != nil {
		return nil, stackerr.Wrap(err)
	}

	return &auth, nil
}

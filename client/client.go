package oauth2c

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/divoxx/stackerr"
)

// Client is the main entrypoint for this package and it exposes the
// actions the client can perform for authentication purpose.
type Client struct {
	// AuthBaseURL is the base location for the OAuth2 endpoints
	AuthBaseURL string

	// ID and Secret are used for identification and authentication of the client
	ID, Secret string

	// httpClient is the http client to be used for API calls
	httpClient http.Client
}

// TokenResponse represents the response from the token endpoint, containing the
// access token and other information, such as the refresh token and token type.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// ResourceOwnerCredentials implements the password grant type.
func (c Client) ResourceOwnerCredentials(username, password, scope string) (*TokenResponse, error) {
	return c.doTokenRequest(url.Values{
		"grant_type": []string{"password"},
		"username":   []string{username},
		"password":   []string{password},
		"scope":      []string{scope},
	})
}

// doTokenRequest performs a request against token endpoint and returns a TokenResponse.
func (c Client) doTokenRequest(params url.Values) (*TokenResponse, error) {
	var tr TokenResponse

	body := []byte(params.Encode())

	req, err := http.NewRequest("POST", c.AuthBaseURL+"/token", bytes.NewReader(body))
	if err != nil {
		return nil, stackerr.Wrap(err)
	}

	req.SetBasicAuth(c.ID, c.Secret)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, stackerr.Wrap(err)
	}

	if err := json.NewDecoder(res.Body).Decode(&tr); err != nil {
		return nil, stackerr.Wrap(err)
	}

	return &tr, nil
}

/*
Copyright 2015 Rodrigo Rafael Monti Kochenburger

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oauth2_test

import (
	"html/template"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/gostack/jwt"
	"github.com/gostack/oauth2"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Llongfile)
}

var (
	tplAuthorization = template.Must(template.New("authorization").Parse(`
<!DOCTYPE html>
<html>
	<head>
		<title>Doximity</title>
	</head>

	<body>
		{{ .Client.Name }}

		<form method="POST">
			<button type="submit" name="action" value="authorize">Authorize</button>
			<button type="submit" name="action" value="deny">Deny</button>
		</form>
	</body>
</html>
`))

	tplError = template.Must(template.New("authorization").Parse(`
<!DOCTYPE html>
<html>
	<head>
		<title>Doximity</title>
	</head>

	<body>
		{{ .Error.Desc }}
	</body>
</html>
`))
)

var tokenExpiresIn = time.Duration(30)

type User struct {
	Username string
	Password string
}

func (u User) GetUsername() string {
	return u.Username
}

func (u User) CheckPassword(password string) bool {
	return u.Password == password
}

type testHTTPBackend struct {
	AutoLogin *User
}

func (b *testHTTPBackend) AuthenticateRequest(c *oauth2.Client, w http.ResponseWriter, req *http.Request) (oauth2.User, error) {
	return b.AutoLogin, nil
}

func (b *testHTTPBackend) RenderAuthorizationPage(w http.ResponseWriter, req *http.Request, data *oauth2.AuthorizationPageData) error {
	return tplAuthorization.Execute(w, data)
}

func (b *testHTTPBackend) RenderErrorPage(w http.ResponseWriter, req *http.Request, data *oauth2.ErrorPageData) error {
	return tplError.Execute(w, data)
}

func setupProvider() (oauth2.PersistenceBackend, *oauth2.ClientAgent, *httptest.Server) {
	inMemory := oauth2.NewInMemoryPersistence("valid_password")

	// Setup some data
	client, err := oauth2.NewClient("Test Client", "http://example.com/callback", true, true)
	if err != nil {
		panic(err)
	}
	if err := inMemory.SaveClient(client); err != nil {
		panic(err)
	}

	user := User{Username: "username", Password: "validpassword"}
	if err := inMemory.SaveUser(&user); err != nil {
		panic(err)
	}

	scopes := []oauth2.Scope{
		{"basic_profile", "Basic profile information", true},
		{"email", "Your email", true},
		{"search", "Search profiles", false},
	}
	for _, s := range scopes {
		if err := inMemory.SaveScope(&s); err != nil {
			panic(err)
		}
	}

	provider := oauth2.NewProvider(inMemory, &testHTTPBackend{&user})
	provider.Register(&oauth2.AuthorizationCodeGrantType{
		ExpiresIn: tokenExpiresIn,
	})
	provider.Register(&oauth2.ResourceOwnerCredentialsGrantType{
		ExpiresIn: tokenExpiresIn,
	})
	provider.Register(&oauth2.ClientCredentialsGrantType{
		ExpiresIn: tokenExpiresIn,
	})
	provider.Register(&oauth2.RefreshTokenGrantType{
		ExpiresIn: tokenExpiresIn,
	})
	provider.Register(&oauth2.AssertionJWTGrantType{
		Audience:  "http://authz.jwt.test",
		Algorithm: jwt.HS256,
		ExpiresIn: tokenExpiresIn,
	})

	srv := httptest.NewServer(provider.HTTPHandler())

	clientAgent := oauth2.ClientAgent{
		AuthBaseURL: srv.URL,
		ID:          client.ID,
		Secret:      client.Secret,
	}

	return inMemory, &clientAgent, srv
}

func TestAuthorizationCodeGrantType(t *testing.T) {
	p, clt, srv := setupProvider()
	defer srv.Close()

	authURL, _ := clt.AuthorizationURL("state", "basic_profile email", "http://example.com/callback")

	resp, err := http.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Error("Expected authorize HTML page to be rendered properly")
	}

	// When the user click authorize, it basically just re-submit the same page with
	// POST data specifying which button was clicked. Here we simulate this.
	resp, err = http.PostForm(authURL, url.Values{"action": []string{"authorize"}})
	if err != nil {
		t.Fatal(err)
	}

	code := resp.Request.URL.Query().Get("code")
	if code == "" {
		t.Errorf("Expected a code on the redirect back to the client callback")
	}

	auth, err := clt.AuthorizationCode(code, "http://example.com/callback")
	if err != nil {
		t.Fatal(err)
	}

	persistedAuth, err := p.GetAuthorizationByAccessToken(auth.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	if persistedAuth.Client.ID != clt.ID || persistedAuth.User.GetUsername() != "username" {
		t.Errorf("Authorization does not match client or user")
	}

	if persistedAuth.Scope != "basic_profile email" {
		t.Errorf("Authorization scope does not match what was requested")
	}
	if persistedAuth.ExpiresIn != int64(tokenExpiresIn.Seconds()) {
		t.Errorf("Authorization expiration time does not match what was configured")
	}

	_, err = clt.AuthorizationCode(code, "http://example.com/callback")
	if !reflect.DeepEqual(err, &oauth2.ErrInvalidGrant) {
		t.Error("Expected replay of authorization code to fail")
	}

	// Let's refresh the token now
	refreshedAuth, err := clt.RefreshToken(auth.RefreshToken, "basic_profile search")
	if err != nil {
		t.Fatal(err)
	}

	refreshedPersistedAuth, err := p.GetAuthorizationByAccessToken(refreshedAuth.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	if refreshedPersistedAuth.Client.ID != clt.ID || refreshedPersistedAuth.User.GetUsername() != "username" {
		t.Errorf("Authorization does not match client or user")
	}

	if refreshedPersistedAuth.Scope != "basic_profile" {
		t.Errorf("Authorization scope does not match what's expected")
	}

	persistedAuth, err = p.GetAuthorizationByAccessToken(auth.AccessToken)
	if err != oauth2.ErrNotFound {
		t.Error("expected old access token to not be valid anymore")
	}
}

func TestAuthorizationCodeGrantTypeDeny(t *testing.T) {
	_, clt, srv := setupProvider()
	defer srv.Close()

	authURL, _ := clt.AuthorizationURL("state", "basic_profile email", "http://example.com/callback")

	resp, err := http.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Error("Expected authorize HTML page to be rendered properly")
	}

	// When the user click authorize, it basically just re-submit the same page with
	// POST data specifying which button was clicked. Here we simulate this.
	resp, err = http.PostForm(authURL, url.Values{"action": []string{"deny"}})
	if err != nil {
		t.Fatal(err)
	}

	urlErr := resp.Request.URL.Query().Get("error")
	if urlErr != "access_denied" {
		t.Errorf("Expected error to be access_denied")
	}
}

func TestPasswordGrantType(t *testing.T) {
	p, clt, srv := setupProvider()
	defer srv.Close()

	a, err := clt.ResourceOwnerCredentials("username", "validpassword", "basic_profile email")
	if err != nil {
		t.Fatal(err)
	}

	a2, err := p.GetAuthorizationByAccessToken(a.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	if a2.Client.ID != clt.ID || a2.User.GetUsername() != "username" {
		t.Errorf("Authorization does not match client or user")
	}

	if a2.Scope != "basic_profile email" {
		t.Errorf("Authorization scope does not match what was requested")
	}
}

func TestAssertionGrantType(t *testing.T) {
	p, clt, srv := setupProvider()
	defer srv.Close()

	tk := jwt.NewToken()
	tk.JWTID = "id"
	tk.Issuer = "http://client.jwt.test"
	tk.Subject = "username"
	tk.Audience = "http://authz.jwt.test"
	tk.Expires = time.Now().Add(time.Minute * 1)

	signedTk, err := tk.Sign(clt.Secret)
	if err != nil {
		t.Fatal(err)
	}

	a, err := clt.Assertion(oauth2.AssertionJWT, signedTk, "basic_profile email")
	if err != nil {
		t.Fatal(err)
	}

	a2, err := p.GetAuthorizationByAccessToken(a.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	if a2.Client.ID != clt.ID || a2.User.GetUsername() != "username" {
		t.Errorf("Authorization does not match client or user")
	}
	if a2.Scope != "basic_profile email" {
		t.Errorf("Authorization scope does not match what was requested")
	}
	if a2.ExpiresIn != int64(tokenExpiresIn.Seconds()) {
		t.Errorf("Authorization expiration time does not match what was configured")
	}
}

func TestClientCredentials(t *testing.T) {
	p, clt, srv := setupProvider()
	defer srv.Close()

	a, err := clt.ClientCredentials("search")
	if err != nil {
		t.Fatal(err)
	}

	a2, err := p.GetAuthorizationByAccessToken(a.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	if a2.Client.ID != clt.ID {
		t.Errorf("Authorization does not match client")
	}
	if a2.User != nil {
		t.Errorf("Client credentials access token should not have an user associated to it")
	}
	if a2.Scope != "search" {
		t.Errorf("Authorization scope does not match what was requested")
	}
	if a2.ExpiresIn != int64(tokenExpiresIn.Seconds()) {
		t.Errorf("Authorization expiration time does not match what was configured")
	}
}

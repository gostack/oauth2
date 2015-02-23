package oauth2_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gostack/oauth2"
)

var (
	bkd = oauth2.NewTestBackend()
	prv = oauth2.NewProvider(bkd)

	clt *oauth2.Client
)

func init() {
	var err error

	clt, err = oauth2.NewClient("Test Client", "http://example.com/callback", true, true)
	if err != nil {
		panic(err)
	}

	bkd.ClientPersist(clt)

	bkd.UserPersist(&oauth2.User{
		Login: "username",
	})

	bkd.ScopePersist(&oauth2.Scope{"basic_profile", "Basic profile information"})
	bkd.ScopePersist(&oauth2.Scope{"email", "Your email"})
}

func TestAuthorizationCodeGrantType(t *testing.T) {
	srv := httptest.NewServer(prv.HTTPHandler())
	defer srv.Close()

	clt := oauth2.ClientAgent{
		AuthBaseURL: srv.URL,
		ID:          clt.ID,
		Secret:      clt.Secret,
	}

	authURL, _ := clt.AuthorizationURL("state", "basic_profile email", "http://example.com/callback")

	bkd.RequestLogin = "username"

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
}

func TestPasswordGrantType(t *testing.T) {
	srv := httptest.NewServer(prv.HTTPHandler())
	defer srv.Close()

	clt := oauth2.ClientAgent{
		AuthBaseURL: srv.URL,
		ID:          clt.ID,
		Secret:      clt.Secret,
	}

	a, err := clt.ResourceOwnerCredentials("username", "validpassword", "basic_profile email")
	if err != nil {
		t.Fatal(err)
	}

	a2, err := bkd.AuthorizationAuthenticate(a.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	if a2.Client.ID != clt.ID || a2.User.Login != "username" {
		t.Errorf("Authorization does not match client or user")
	}
}

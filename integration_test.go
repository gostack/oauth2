package oauth2_test

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
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

	url, _ := clt.AuthorizationURL("state", "basic_profile email", "http://example.com/callback")
	log.Println(url)

	bkd.RequestLogin = "username"

	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}

	b, _ := ioutil.ReadAll(resp.Body)
	log.Println(string(b))
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

package oauth2_test

import (
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

	clt, err = oauth2.NewClient()
	if err != nil {
		panic(err)
	}

	clt.Internal = true
	bkd.ClientPersist(clt)

	bkd.UserPersist(&oauth2.User{
		Login: "username",
	})
}

func TestPasswordGrantType(t *testing.T) {
	srv := httptest.NewServer(prv.HTTPHandler())
	defer srv.Close()

	clt := oauth2.ClientAgent{
		AuthBaseURL: srv.URL,
		ID:          clt.ID,
		Secret:      clt.Secret,
	}

	a, err := clt.ResourceOwnerCredentials("username", "validpassword", "scope")
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

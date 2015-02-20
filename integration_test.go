package oauth2_test

import (
	"net/http/httptest"
	"testing"

	"github.com/gostack/oauth2"
)

var (
	bkd = oauth2.NewTestBackend()
	prv = oauth2.NewProvider(bkd)
)

func init() {
	bkd.ClientPersist(&oauth2.Client{
		ID:           "e6e41132d34a952627375a94f08823fb219a828d",
		Secret:       "3fa181c93f330cd832c290ba310486a73c32dbe22178c7b3faa96a5236a1d7ab649058c33e060de3f3ebee63e7e976c77693e433addbc0e81bf17b679b350d9f",
		Internal:     true,
		Confidential: true,
	})

	bkd.UserPersist(&oauth2.User{
		Login: "username",
	})
}

func TestPasswordGrantType(t *testing.T) {
	srv := httptest.NewServer(prv.HTTPHandler())
	defer srv.Close()

	clt := oauth2.ClientAgent{
		AuthBaseURL: srv.URL,
		ID:          "e6e41132d34a952627375a94f08823fb219a828d",
		Secret:      "3fa181c93f330cd832c290ba310486a73c32dbe22178c7b3faa96a5236a1d7ab649058c33e060de3f3ebee63e7e976c77693e433addbc0e81bf17b679b350d9f",
	}

	a, err := clt.ResourceOwnerCredentials("username", "validpassword", "scope")
	if err != nil {
		t.Fatal(err)
	}

	a2, err := bkd.AuthorizationAuthenticate(a.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	if a2.Client.ID != "e6e41132d34a952627375a94f08823fb219a828d" || a2.User.Login != "username" {
		t.Errorf("Authorization does not match client or user")
	}
}

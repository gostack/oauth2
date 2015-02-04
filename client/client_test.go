package client

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gostack/oauth2/common"
)

func TestResourceOwnerCredentials(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, req *http.Request) {
		json := `{"access_token":"2YotnFZFEjr1zCsicMWpAA","token_type":"example","expires_in":3600,"refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA","scope":"scope"}`
		w.Write([]byte(json))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := Client{
		AuthBaseURL: srv.URL,
		ID:          "e6e41132d34a952627375a94f08823fb219a828d",
		Secret:      "3fa181c93f330cd832c290ba310486a73c32dbe22178c7b3faa96a5236a1d7ab649058c33e060de3f3ebee63e7e976c77693e433addbc0e81bf17b679b350d9f",
	}

	resp, err := client.ResourceOwnerCredentials("username", "password", "scope")
	if err != nil {
		t.Fatal(err)
	}

	expected := &common.Authorization{
		AccessToken:  "2YotnFZFEjr1zCsicMWpAA",
		TokenType:    "example",
		ExpiresIn:    3600,
		RefreshToken: "tGzv3JOkF0XG5Qx2TlKWIA",
		Scope:        "scope",
	}

	if !reflect.DeepEqual(resp, expected) {
		t.Errorf(`
Expected token response to be: %#v
                   But it was: %#v`,
			expected,
			resp,
		)
	}
}

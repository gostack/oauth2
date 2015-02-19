package oauth2

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// stubProvider is a stub implementation of an OAuth2 provider to be used when
// unit testing the client.
type stubProvider struct {
	mux *http.ServeMux
}

// newStubProvider creates a new stubProvider configured with the proper routes
func newStubProvider() *stubProvider {
	p := stubProvider{mux: http.NewServeMux()}
	p.mux.HandleFunc("/token", p.tokenHandler)
	return &p
}

// Start creates a new server goroutine running this instance of the stub provider
func (p *stubProvider) Start() *httptest.Server {
	return httptest.NewServer(p.mux)
}

// tokenHandler implements the stub http handler for the token endpoint
func (p *stubProvider) tokenHandler(w http.ResponseWriter, req *http.Request) {
	json := `{"access_token":"2YotnFZFEjr1zCsicMWpAA","token_type":"example","expires_in":3600,"refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA","scope":"scope"}`
	w.Write([]byte(json))
}

func TestResourceOwnerCredentials(t *testing.T) {
	srv := newStubProvider().Start()
	defer srv.Close()

	ca := ClientAgent{
		AuthBaseURL: srv.URL,
		ID:          "e6e41132d34a952627375a94f08823fb219a828d",
		Secret:      "3fa181c93f330cd832c290ba310486a73c32dbe22178c7b3faa96a5236a1d7ab649058c33e060de3f3ebee63e7e976c77693e433addbc0e81bf17b679b350d9f",
	}

	resp, err := ca.ResourceOwnerCredentials("username", "password", "scope")
	if err != nil {
		t.Fatal(err)
	}

	expected := &Authorization{
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

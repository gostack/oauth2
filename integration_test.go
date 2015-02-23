package oauth2_test

import (
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/gostack/oauth2"
)

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
)

type testHTTPBackend struct {
	AutoLogin *oauth2.User
}

func (b *testHTTPBackend) AuthenticateRequest(w http.ResponseWriter, req *http.Request) (*oauth2.User, error) {
	return b.AutoLogin, nil
}

func (b *testHTTPBackend) RenderAuthorizationPage(w io.Writer, data *oauth2.AuthorizationPageData) error {
	return tplAuthorization.Execute(w, data)
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

	user := oauth2.User{Login: "username"}
	if err := inMemory.SaveUser(&user); err != nil {
		panic(err)
	}

	scopes := []oauth2.Scope{
		{"basic_profile", "Basic profile information"},
		{"email", "Your email"},
	}
	for _, s := range scopes {
		if err := inMemory.SaveScope(&s); err != nil {
			panic(err)
		}
	}

	provider := oauth2.NewProvider(inMemory, &testHTTPBackend{&user})
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

	a, err := clt.AuthorizationCode(code, "http://example.com/callback")
	if err != nil {
		t.Fatal(err)
	}

	a2, err := p.GetAuthorizationByAccessToken(a.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	if a2.Client.ID != clt.ID || a2.User.Login != "username" {
		t.Errorf("Authorization does not match client or user")
	}

	a, err = clt.AuthorizationCode(code, "http://example.com/callback")
	if !reflect.DeepEqual(err, &oauth2.ErrInvalidGrant) {
		t.Error("Expected replay of authorization code to fail")
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

	if a2.Client.ID != clt.ID || a2.User.Login != "username" {
		t.Errorf("Authorization does not match client or user")
	}
}

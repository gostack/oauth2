package oauth2

import (
	"testing"
)

func TestClientCredentials(t *testing.T) {
	c := Client{Name: "Test Client", RedirectURI: "https://example.test/oauth2/callback"}

	if err := c.generateCredentials(); err != nil {
		t.Error(err)
	}

	if c.ID == "" {
		t.Fatal("ID not properly initialized")
	}

	if c.Secret == "" {
		t.Fatal("Secret not properly initialized")
	}
}

func TestSecureCompare(t *testing.T) {
	table := []struct {
		A, B   string
		Result bool
	}{
		{"CZEXIa-mVtAvzrJV8-q-MGiynZf476lMo9Ba1Be4L3Y", "CZEXIa-mVtAvzrJV8-q-MGiynZf476lMo9Ba1Be4L3Y", true},
		{"J1ye8B7nGPfImUiXS2xK9EQZT-3NuAG-Kt7qg51sAhU", "J1ye8B7nGPfImUiXS2xK9EQZT-3NuAG-Kt7qg51sAhU", true},
		{"CZEXIa-mVtAvzrJV8-q-MGiynZf476lMo9Ba1Be4L3Y", "J1ye8B7nGPfImUiXS2xK9EQZT-3NuAG-Kt7qg51sAhU", false},
	}

	for i, e := range table {
		var r string
		if e.Result {
			r = "match"
		} else {
			r = "not match"
		}

		if secureCompare([]byte(e.A), []byte(e.B)) != e.Result {
			t.Errorf("expected entry #%d with %s and %s to %s", i, e.A, e.B, r)
		}
	}
}

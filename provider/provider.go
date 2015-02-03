package provider

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/gostack/oauth2/common"
)

type provider struct {
	// Mux that will be used as main handler for mounting the library
	mux *http.ServeMux
}

func NewProvider(inter Interface) *provider {
	p := provider{mux: http.NewServeMux()}
	p.mux.Handle("/token", internalHandler{tokenEndpoint})
	return &p
}

type Client struct {
	ID, Secret string
	Internal   bool
}

type AuthorizationGrantType interface {
	Perform(c *Client, v url.Values) *common.TokenResponse
}

type Error struct {
	Code string `json:"error"`
	Desc string `json:"error_description,omitempty"`
	URI  string `json:"error_uri,omitempty"`
}

var (
	ErrInvalidRequest     = Error{Code: "invalid_request", Desc: "The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed."}
	ErrInvalidClient      = Error{Code: "invalid_client", Desc: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)."}
	ErrUnauthorizedClient = Error{Code: "unauthorized_client", Desc: "The authenticated client is not authorized to use this authorization grant type."}
)

type internalHandler struct {
	handler func(req *http.Request) (interface{}, error)
}

func (h internalHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	enc := json.NewEncoder(w)

	var data interface{}

	if v, err := handler(req); err != nil {
		data = err
	} else {
		data = v
	}

	if err := enc.Encode(data); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func tokenEndpoint(req *http.Request) (interface{}, error) {
	if id, secret, ok := req.BasicAuth(); ok {
		c := Stora.LookupClient(id)
		if c.Secret != secret {
			return ErrInvalidClient
		}
	} else {
		return ErrInvalidRequest
	}

	if err := req.ParseForm(); err != nil {
		return ErrInvalidRequest
	}

	gt := req.PostFormValue("grant_type")
	if gt == "" {
		return ErrInvalidRequest
	}

	switch gt {
	case "password":
		if !c.Internal {
			return ErrUnauthorizedClient
		}

		var (
			username = req.PostFormValue("username")
			password = req.PostFormValue("password")
			scope    = req.PostFormValue("scope")
		)

		if username == "" || password == "" {
			return ErrInvalidRequest
		}

	}
}

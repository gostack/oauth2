package provider

import (
	"encoding/json"
	"net/http"
)

var (
	Provider = http.NewServeMux()
)

func init() {
	Provider.Handle("/token", internalHandler{tokenEndpoint})
}

type Error struct {
	Code int    `json:"-"`
	ID   string `json:"error"`
	Desc string `json:"error_description,omitempty"`
	URI  string `json:"error_uri,omitempty"`
}

func (e Error) Error() string {
	return e.Desc
}

var (
	ErrInvalidRequest       = Error{ID: "invalid_request", Code: http.StatusBadRequest, Desc: "The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed."}
	ErrInvalidClient        = Error{ID: "invalid_client", Code: http.StatusUnauthorized, Desc: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)."}
	ErrUnauthorizedClient   = Error{ID: "unauthorized_client", Code: http.StatusUnauthorized, Desc: "The authenticated client is not authorized to use this authorization grant type."}
	ErrAccessDenied         = Error{ID: "access_denied", Code: http.StatusUnauthorized, Desc: "The resource owner or authorization server denied the request."}
	ErrServerError          = Error{ID: "server_error", Code: http.StatusInternalServerError, Desc: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request."}
	ErrUnsupportedGrantType = Error{ID: "unsupported_grant_type", Code: http.StatusBadRequest, Desc: "The authorization grant type is not supported by the authorization server."}
)

type internalHandler struct {
	endpoint func(req *http.Request) (interface{}, error)
}

func (h internalHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	enc := json.NewEncoder(w)

	var data interface{}

	if v, err := h.endpoint(req); err != nil {
		data = err
		if err, k := err.(Error); k {
			w.WriteHeader(err.Code)
		}
	} else {
		data = v
	}

	if err := enc.Encode(data); err != nil {
		return
	}
}

func tokenEndpoint(req *http.Request) (interface{}, error) {
	var (
		err error
		c   *Client
		u   *User
	)

	id, secret, ok := req.BasicAuth()
	if !ok {
		return nil, ErrInvalidRequest
	}

	c, err = integration.LookupClient(id)
	if err != nil {
		return nil, ErrServerError
	}

	if c.Secret != secret {
		return nil, ErrInvalidClient
	}

	gt := req.PostFormValue("grant_type")
	if gt == "" {
		return nil, ErrInvalidRequest
	}

	switch gt {
	case "password":
		if !c.Internal {
			return nil, ErrUnauthorizedClient
		}

		var (
			username = req.PostFormValue("username")
			password = req.PostFormValue("password")
			scope    = req.PostFormValue("scope")
		)

		if username == "" || password == "" {
			return nil, ErrInvalidRequest
		}

		u, err = integration.AuthenticateUser(username, password)
		if err != nil {
			return nil, ErrAccessDenied
		}

		auth, err := integration.Authorize(c, u, scope)
		if err != nil {
			return nil, ErrServerError
		}

		return auth, nil
	}

	return nil, ErrUnsupportedGrantType
}

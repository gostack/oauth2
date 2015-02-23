package oauth2

import (
	"net/http"
)

type Error struct {
	Code int    `json:"-"`
	ID   string `json:"error"`
	Desc string `json:"error_description,omitempty"`
}

func (e Error) Error() string {
	return e.Desc
}

var (
	ErrInvalidRequest = Error{
		ID:   "invalid_request",
		Code: http.StatusBadRequest,
		Desc: "The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed.",
	}

	ErrInvalidClient = Error{
		ID:   "invalid_client",
		Code: http.StatusUnauthorized,
		Desc: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
	}

	ErrInvalidGrant = Error{
		ID:   "invalid_grant",
		Code: http.StatusBadRequest,
		Desc: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
	}

	ErrInvalidScope = Error{
		ID:   "invalid_scope",
		Code: http.StatusBadRequest,
		Desc: "The requested scope is invalid, unknown, or malformed.",
	}

	ErrUnauthorizedClient = Error{
		ID:   "unauthorized_client",
		Code: http.StatusUnauthorized,
		Desc: "The authenticated client is not authorized to use this authorization grant type.",
	}

	ErrAccessDenied = Error{
		ID:   "access_denied",
		Code: http.StatusUnauthorized,
		Desc: "The resource owner or authorization server denied the request.",
	}

	ErrServerError = Error{
		ID:   "server_error",
		Code: http.StatusInternalServerError,
		Desc: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
	}

	ErrUnsupportedGrantType = Error{
		ID:   "unsupported_grant_type",
		Code: http.StatusBadRequest,
		Desc: "The authorization grant type is not supported by the authorization server.",
	}
)

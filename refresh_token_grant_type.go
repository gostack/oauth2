/*
Copyright 2015 Rodrigo Rafael Monti Kochenburger

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oauth2

import (
	"log"
	"net/http"
	"net/url"
)

type RefreshTokenGrantType struct {
	persistence PersistenceBackend
}

func (gt RefreshTokenGrantType) RegistrationInfo() (string, string) {
	return "", "refresh_token"
}

func (gt *RefreshTokenGrantType) SetPersistenceBackend(p PersistenceBackend) {
	gt.persistence = p
}

func (gt RefreshTokenGrantType) AuthzHandler(c *Client, u User, scope string, req *http.Request) (url.Values, error) {
	return nil, nil
}

func (gt RefreshTokenGrantType) TokenHandler(c *Client, ew *EncoderResponseWriter, req *http.Request) {
	var (
		refreshToken = req.PostFormValue("refresh_token")
		scope        = req.PostFormValue("scope")
	)

	if refreshToken == "" || scope == "" {
		log.Println("missing required parameters")
		ew.Encode(ErrInvalidRequest)
		return
	}

	auth, err := gt.persistence.GetAuthorizationByRefreshToken(refreshToken)
	if err != nil {
		log.Println("invalid refresh token:", refreshToken)
		ew.Encode(ErrInvalidGrant)
		return
	}

	if err := auth.Refresh(scope); err != nil {
		log.Println("failed to refresh token")
		ew.Encode(ErrServerError)
		return
	}

	if err := gt.persistence.SaveAuthorization(auth); err != nil {
		log.Println("failed to persist authorization")
		ew.Encode(ErrServerError)
		return
	}

	ew.Encode(auth)
}

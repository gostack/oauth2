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
	"time"
)

type AuthorizationCodeGrantType struct {
	persistence PersistenceBackend
	ExpiresIn   time.Duration
}

func (gt AuthorizationCodeGrantType) RegistrationInfo() (string, string) {
	return "code", "authorization_code"
}

func (gt *AuthorizationCodeGrantType) SetPersistenceBackend(p PersistenceBackend) {
	gt.persistence = p
}

func (gt AuthorizationCodeGrantType) AuthzHandler(c *Client, u User, scope string, req *http.Request) (url.Values, error) {
	auth, err := NewAuthorization(c, u, scope, gt.ExpiresIn, true, true)
	if err != nil {
		log.Println(err)
		return nil, ErrServerError
	}

	if err := gt.persistence.SaveAuthorization(auth); err != nil {
		log.Println(err)
		return nil, ErrServerError
	}

	return url.Values{"code": []string{auth.Code}}, nil
}

func (gt AuthorizationCodeGrantType) TokenHandler(c *Client, ew *EncoderResponseWriter, req *http.Request) {
	var (
		code        = req.PostFormValue("code")
		redirectURI = req.PostFormValue("redirect_uri")
	)

	if code == "" || redirectURI == "" {
		log.Println("missing required parameters")
		ew.Encode(ErrInvalidRequest)
		return
	}

	if redirectURI != c.RedirectURI {
		log.Println("redirect_uri does not match authorization")
		ew.Encode(ErrInvalidGrant)
		return
	}

	auth, err := gt.persistence.GetAuthorizationByCode(c, code)
	if err != nil {
		log.Println("couldn't find authorization for code:", err)
		ew.Encode(ErrInvalidGrant)
		return
	}

	if time.Now().Unix() > auth.CreatedAt.Add(5*time.Minute).Unix() {
		log.Println("code has expired")
		ew.Encode(ErrInvalidGrant)
		return
	}

	auth.Code = ""
	if err := gt.persistence.SaveAuthorization(auth); err != nil {
		log.Println("could not save authorization:", err)
		ew.Encode(ErrServerError)
		return
	}

	ew.Encode(auth)
}

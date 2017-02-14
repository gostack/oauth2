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
	"github.com/gostack/jwt"
	"log"
	"net/http"
)

type AssertionJWTGrantType struct {
	Audience    string
	Algorithm   jwt.Algorithm
	persistence PersistenceBackend
}

func (gt AssertionJWTGrantType) RegistrationInfo() (string, string) {
	return "", "urn:ietf:params:oauth:grant-type:jwt-bearer"
}

func (gt *AssertionJWTGrantType) SetPersistenceBackend(p PersistenceBackend) {
	gt.persistence = p
}

func (gt AssertionJWTGrantType) TokenHandler(c *Client, ew *EncoderResponseWriter, req *http.Request) {
	var (
		assertion = req.PostFormValue("assertion")
		scope     = req.PostFormValue("scope")
	)

	if assertion == "" || scope == "" {
		log.Println("missing required parameters")
		ew.Encode(ErrInvalidRequest)
		return
	}

	jwtTk, err := jwt.DecodeToken(assertion, gt.Algorithm, c.Secret)
	if err != nil {
		log.Println("JWT token is not valid:", err)
		ew.Encode(ErrInvalidGrant)
		return
	}

	err = jwtTk.Verify("", "", gt.Audience)
	if err != nil {
		log.Println("JWT token failed to verify:", err)
		ew.Encode(ErrInvalidGrant)
		return
	}

	u, err := gt.persistence.GetUserByLogin(jwtTk.Subject)
	if err != nil {
		log.Println("JWT subject is not a valid user")
		ew.Encode(ErrInvalidGrant)
		return
	}

	auth, err := NewAuthorization(c, u, scope, false, false)
	if err != nil {
		log.Println(err)
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

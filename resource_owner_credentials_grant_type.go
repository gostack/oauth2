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

type ResourceOwnerCredentialsGrantType struct {
	persistence PersistenceBackend
}

func (gt ResourceOwnerCredentialsGrantType) RegistrationInfo() (string, string) {
	return "", "password"
}

func (gt *ResourceOwnerCredentialsGrantType) SetPersistenceBackend(p PersistenceBackend) {
	gt.persistence = p
}

func (gt ResourceOwnerCredentialsGrantType) AuthzHandler(c *Client, u *User, scope string, req *http.Request) (url.Values, error) {
	return nil, nil
}

func (gt ResourceOwnerCredentialsGrantType) TokenHandler(c *Client, ew *EncoderResponseWriter, req *http.Request) {
	if !c.Internal {
		log.Println("client not internal")
		ew.Encode(ErrUnauthorizedClient)
		return
	}

	var (
		username = req.PostFormValue("username")
		password = req.PostFormValue("password")
		scope    = req.PostFormValue("scope")
	)

	if username == "" || password == "" {
		log.Println("username or password is empty")
		ew.Encode(ErrInvalidRequest)
		return
	}

	u, err := gt.persistence.GetUserByUsername(username)
	if err != nil {
		log.Println("invalid credentials")
		ew.Encode(ErrAccessDenied)
		return
	}
	if !secureCompare([]byte(username), []byte(u.Username)) {
		log.Println("invalid password")
		ew.Encode(ErrAccessDenied)
		return
	}

	auth, err := NewAuthorization(c, u, scope, true, false)
	if err != nil {
		log.Println(err)
		ew.Encode(ErrServerError)
		return
	}

	if err := gt.persistence.SaveAuthorization(auth); err != nil {
		log.Println(err)
		ew.Encode(ErrServerError)
		return
	}

	ew.Encode(auth)
}

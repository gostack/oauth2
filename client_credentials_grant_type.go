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
	"strings"
)

type ClientCredentialsGrantType struct {
	persistence PersistenceBackend
}

func (gt ClientCredentialsGrantType) RegistrationInfo() (string, string) {
	return "", "client_credentials"
}

func (gt *ClientCredentialsGrantType) SetPersistenceBackend(p PersistenceBackend) {
	gt.persistence = p
}

func (gt ClientCredentialsGrantType) TokenHandler(c *Client, ew *EncoderResponseWriter, req *http.Request) {
	if !(c.Confidential && c.Internal) {
		log.Println("client is not confidential and internal")
		ew.Encode(ErrUnauthorizedClient)
		return
	}

	var (
		scope = req.PostFormValue("scope")
	)

	if scope != "" {
		scopesSl, err := gt.persistence.GetScopesByID(strings.Split(scope, " ")...)
		if err != nil {
			log.Println("couldn't fetch scopes by id:", err)
			ew.Encode(ErrServerError)
			return
		}

		for _, s := range scopesSl {
			if s.UserOnly == true {
				log.Println("attempt to request user only scope on client credentials grant type")
				ew.Encode(ErrInvalidScope)
				return
			}
		}
	}

	auth, err := NewAuthorization(c, nil, scope, false, false)
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

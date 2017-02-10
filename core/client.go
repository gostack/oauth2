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

package core

import (
	"crypto/rand"
	"encoding/hex"
)

type Client struct {
	ID, Secret   string
	Name         string
	RedirectURI  string
	Internal     bool
	Confidential bool
}

func NewClient(name, redirectURI string, confidential, internal bool) (*Client, error) {
	c := Client{
		Name:         name,
		RedirectURI:  redirectURI,
		Confidential: confidential,
		Internal:     internal,
	}

	if b, err := secureRandomBytes(32); err != nil {
		return nil, err
	} else {
		c.ID = hex.EncodeToString(b)
	}

	if b, err := secureRandomBytes(64); err != nil {
		return nil, err
	} else {
		c.Secret = hex.EncodeToString(b)
	}

	return &c, nil
}

func secureRandomBytes(bytes uint) ([]byte, error) {
	r := make([]byte, bytes)
	_, err := rand.Read(r)
	return r, err
}

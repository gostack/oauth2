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

package strategy

import (
	"errors"
)

var (
	ErrBadRegistration = errors.New("strategy failed to register, make sure RegistrationInfo() is properly implemented")
)

type Set struct {
	// Holds a mapping from grant_type -> response_type, allows us to lookup the
	// AuthorizationRequest for a grant if it requires one.
	assoc map[string]string

	authorizers map[string]Interface
	granters    map[string]Interface
}

func NewSet() *Set {
	return &Set{
		assoc:       make(map[string]string),
		authorizers: make(map[string]Interface),
		granters:    make(map[string]Interface),
	}
}

func (s *Set) Add(strategy Interface) error {
	responseType, grantType := strategy.RegistrationInfo()

	if responseType == "" && grantType == "" {
		return ErrBadRegistration
	}

	if responseType != "" {
		s.authorizers[responseType] = strategy
	}

	if grantType != "" {
		s.granters[grantType] = strategy
	}

	if responseType != "" && grantType != "" {
		s.assoc[grantType] = responseType
	}

	return nil
}

func (s Set) ResponseType(responseType string) Interface {
	if s, ok := s.authorizers[responseType]; ok {
		return s
	}
	return nil
}

func (s Set) GrantType(grantType string) Interface {
	if s, ok := s.granters[grantType]; ok {
		return s
	}
	return nil
}

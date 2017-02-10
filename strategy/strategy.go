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
	"github.com/gostack/oauth2/core"
)

type Interface interface {
	RegistrationInfo() (response_type, grant_type string)
	Authorize(*AuthorizationRequest) (*Authorization, error)
	Grant(*GrantRequest) (*Grant, error)
}

// AuthorizationRequest represents the request for an user authorization from an application.
type AuthorizationRequest struct {
	Client *core.Client
	Scope  []string
}

// Authorization represents a grant from a user authorizing a application on his behalf.
type Authorization struct {
	ID    string
	Scope []string
}

// GrantRequest represents the request for an access grant for an application.
type GrantRequest struct {
	AuthorizationRequest *AuthorizationRequest

	Client *core.Client
	Scope  []string
}

// Grant represents the actual grant of access for the provided client.
type Grant struct{}

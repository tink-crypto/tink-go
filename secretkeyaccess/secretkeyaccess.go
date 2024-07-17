// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package secretkeyaccess provides a function to validate secret key access tokens.
//
// This package is intended for use in APIs that return secret key material to
// avoid taking a direct dependency on the insecuresecretkeyaccess package.
// Consumers of secret key material should use the insecuresecretkeyaccess
// package directly.
//
// For example, an API that returns secret key material could be defined as:
//
//	func MyFunction(token any) (secretKey []byte, err error) {
//		if err := secretkeyaccess.Validate(token); err != nil {
//			return nil, err
//		}
//		// ...
//	}
//
// The API is used as follows:
//
//	secretKey, err := MyFunction(insecuresecretkeyaccess.Token{})
//	// ...
//
// Internally at Google, this package is used in conjunction with the build
// system to restrict access to functions that return secret key material.
package secretkeyaccess

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/insecuresecretkeyaccess"
)

// Validate validates a secret key access token.
//
// This function should be used by APIs that return secret key material to
// validate that the caller has a valid token.
//
// Internally at Google, this function is used in conjunction with the build
// system to restrict access to functions that return secret key material.
func Validate(token any) error {
	if _, ok := token.(insecuresecretkeyaccess.Token); !ok {
		return fmt.Errorf("secret key access token is not of type insecuresecretkeyaccess.Token, got %T", token)
	}
	return nil
}

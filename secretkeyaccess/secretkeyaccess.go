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

// Package secretkeyaccess provides utilities for APIs that return secret key
// material and need to validate secret key access tokens.
//
// This package is intended for use in APIs that return secret key bytes to
// avoid taking a direct dependency on the insecuresecretkeyaccess package.
// Consumers of secret key bytes should use the insecuresecretkeyaccess
// package directly.
//
// TODO: b/354103265 - Move this to an example test.
//
// For example, an API that returns secret key bytes could simply do:
//
//	func MyFunction() (secretKey Bytes, err error) {
//		// ...
//	}
//
// Then to access the wrapped bytes, the caller would do:
//
//	secretKey, err := MyFunction()
//	if err != nil {
//		return err
//	}
//	secretKeyMaterial, err := secretKey.Data(insecuresecretkeyaccess.Token{})
//	if err != nil {
//		return err
//	}
//	// ...
//
// This package and build restrictions on insecuresecretkeyaccess may be used
// together to restrict access to secret key bytes.
package secretkeyaccess

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/insecuresecretkeyaccess"
)

// Validate validates a secret key access token.
//
// This function should be used by APIs that return secret key bytes to
// validate that the caller has a valid token.
//
// This function and build restrictions on insecuresecretkeyaccess may be used
// together to restrict access to secret key bytes.
func Validate(token any) error {
	if _, ok := token.(insecuresecretkeyaccess.Token); !ok {
		return fmt.Errorf("secret key access token is not of type insecuresecretkeyaccess.Token, got %T", token)
	}
	return nil
}

// Bytes is a wrapper around []byte that requires a secret key access token to
// access a copy of the data.
//
// This type ensures immutability of the wrapped bytes.
//
// This type and build restrictions on insecuresecretkeyaccess may be used
// together to restrict access to secret key bytes.
type Bytes struct {
	data []byte
}

// NewBytes creates a new Bytes with size bytes of cryptographically strong
// random data.
func NewBytes(size uint32) (*Bytes, error) {
	b := &Bytes{data: make([]byte, size)}
	if _, err := rand.Read(b.data); err != nil {
		return nil, err
	}
	return b, nil
}

// NewBytesFromData creates a new Bytes populated with data.
//
// This function make a copy of the data. Returns an error if token is not an
// [insecuresecretkeyaccess.Token].
func NewBytesFromData(data []byte, token any) (*Bytes, error) {
	if err := Validate(token); err != nil {
		return nil, err
	}
	return &Bytes{data: bytes.Clone(data)}, nil
}

// Data returns a copy of the wrapped bytes.
//
// Returns an error if token is not an [insecuresecretkeyaccess.Token].
func (b *Bytes) Data(token any) ([]byte, error) {
	if err := Validate(token); err != nil {
		return nil, err
	}
	return bytes.Clone(b.data), nil
}

// Len returns the size of the wrapped bytes.
func (b *Bytes) Len() int { return len(b.data) }

// Equals returns true if the two Bytes objects are equal.
//
// The comparison is done in constant time. The time taken is a function of the
// length of the wrapped bytes and is independent of the contents. If the two
// wrapped slices are of different lengths, the function returns immediately.
func (b *Bytes) Equals(other *Bytes) bool {
	return subtle.ConstantTimeCompare(b.data, other.data) == 1
}

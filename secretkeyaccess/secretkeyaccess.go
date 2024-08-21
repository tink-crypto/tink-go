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
// This package and build restrictions on insecuresecretkeyaccess may be used
// together to restrict access to secret key bytes.
package secretkeyaccess

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"

	"github.com/tink-crypto/tink-go/v2/insecuresecretkeyaccess"
)

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

// NewBytesFromRand returns a Bytes value wrapping size bytes of
// cryptographically strong random data.
func NewBytesFromRand(size uint32) (*Bytes, error) {
	b := &Bytes{data: make([]byte, size)}
	if _, err := rand.Read(b.data); err != nil {
		return nil, err
	}
	return b, nil
}

// NewBytesFromData creates a new Bytes populated with data.
//
// This function makes a copy of the data. It requires an
// [insecuresecretkeyaccess.Token] value.
func NewBytesFromData(data []byte, token insecuresecretkeyaccess.Token) *Bytes {
	return &Bytes{data: bytes.Clone(data)}
}

// Data returns a copy of the wrapped bytes.
//
// It requires an [insecuresecretkeyaccess.Token] value to access the data.
func (b *Bytes) Data(token insecuresecretkeyaccess.Token) []byte {
	return bytes.Clone(b.data)
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

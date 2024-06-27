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

// Package key defines interfaces for Key and Parameters types.
package key

// Parameters represents key parameters.
type Parameters interface {
	// HasIDRequirement tells whether the key has an ID requirement, that is, if a
	// key generated with these parameters must have a given ID.
	//
	// In Tink, certain keys change their behavior depending on the key ID (e.g.,
	// an AEAD object may add a prefix containing the big endian encoding of the
	// key id to the ciphertext). In this case, such a key should require a unique
	// id in key.ID() and return true.
	HasIDRequirement() bool
	// Equals compares this parameters object with other.
	Equals(other Parameters) bool
}

// Key represents a Tink key.
//
// A Tink key is a cryptographic function, that is, it contains all the
// information necessary to perform cryptographic operations. Keys are meant to
// be grouped in keysets, from which primitives can be obtained.
type Key interface {
	// Parameters returns the parameters of this key.
	Parameters() Parameters
	// IDRequirement returns required to indicate if this key requires an
	// identifier. If it does, id will contain that identifier.
	IDRequirement() (id uint32, required bool)
	// Equals compares this key object with other.
	Equals(other Key) bool
}

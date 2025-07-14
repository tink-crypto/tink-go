// Copyright 2021 Google LLC
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

package hpke

// kem is a package-internal interface for the Hybrid Public Key Encryption
// (HPKE) key encapsulation mechanism (KEM).
//
// The HPKE RFC is available at
// https://www.rfc-editor.org/rfc/rfc9180.html.
type kem interface {
	// encapsulate generates and encapsulates a shared secret using
	// recipientPubKey. It returns the raw shared secret and encapsulated key.
	// The HPKE RFC refers to this function as Encap(). It is used by the sender.
	encapsulate(recipientPubKey []byte) ([]byte, []byte, error)

	// decapsulate extracts the shared secret from encapsulatedKey using
	// recipientPrivKey. It returns the raw shared secret. The HPKE RFC refers
	// to this function as Decap(). It is used by the recipient.
	decapsulate(encapsulatedKey, recipientPrivKey []byte) ([]byte, error)

	// id returns the HPKE KEM algorithm identifier for the underlying KEM
	// implementation.
	//
	// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1
	id() KEMID

	// encapsulatedKeyLength returns the length of the encapsulated key,
	// corresponding to Nenc in the following table.
	//
	// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1
	encapsulatedKeyLength() int
}

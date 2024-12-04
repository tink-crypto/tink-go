// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aesctrhmac

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
	subtlemac "github.com/tink-crypto/tink-go/v2/mac/subtle"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type fullAEAD struct {
	aead    *subtle.EncryptThenAuthenticate
	prefix  []byte
	variant Variant
}

var _ tink.AEAD = (*fullAEAD)(nil)

func newAEAD(key *Key) (tink.AEAD, error) {
	aesCTR, err := subtle.NewAESCTR(key.AESKeyBytes().Data(insecuresecretdataaccess.Token{}), key.parameters.IVSizeInBytes())
	if err != nil {
		return nil, err
	}
	hmac, err := subtlemac.NewHMAC(key.parameters.HashType().String(), key.HMACKeyBytes().Data(insecuresecretdataaccess.Token{}), uint32(key.parameters.TagSizeInBytes()))
	if err != nil {
		return nil, err
	}
	eta, err := subtle.NewEncryptThenAuthenticate(aesCTR, hmac, key.parameters.TagSizeInBytes())
	if err != nil {
		return nil, err
	}
	return &fullAEAD{
		aead:    eta,
		prefix:  key.OutputPrefix(),
		variant: key.parameters.Variant(),
	}, nil
}

func (a *fullAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	ciphertext, err := a.aead.Encrypt(plaintext, associatedData)
	if err != nil {
		return nil, err
	}
	return slices.Concat(a.prefix, ciphertext), nil
}

func (a *fullAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	if len(ciphertext) < len(a.prefix) {
		return nil, fmt.Errorf("ciphertext with size %d is too short", len(ciphertext))
	}
	prefix := ciphertext[:len(a.prefix)]
	ciphertextNoPrefix := ciphertext[len(a.prefix):]
	if !bytes.Equal(prefix, a.prefix) {
		return nil, fmt.Errorf("ciphertext prefix does not match: got %x, want %x", prefix, a.prefix)
	}
	return a.aead.Decrypt(ciphertextNoPrefix, associatedData)
}

// primitiveConstructor creates a [tink.AEAD] from a [key.Key].
//
// The key must be of type [aesctrhmac.Key].
func primitiveConstructor(k key.Key) (any, error) {
	that, ok := k.(*Key)
	if !ok {
		return nil, fmt.Errorf("invalid key type: got %T, want *aesctrhmac.Key", k)
	}
	return newAEAD(that)
}

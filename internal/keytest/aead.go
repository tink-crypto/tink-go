// Copyright 2026 Google LLC
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

package keytest

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type aead struct {
	prefix    []byte
	dummyAEAD *testutil.DummyAEAD
}

var _ tink.AEAD = (*aead)(nil)

// newAEAD creates a new [tink.AEAD] from a [keytest.Key].
func newAEAD(k *Key) (tink.AEAD, error) {
	keyBytes := k.KeyBytes().Data(insecuresecretdataaccess.Token{})
	base64Key := hex.EncodeToString(keyBytes)
	return &aead{
		prefix:    k.OutputPrefix(),
		dummyAEAD: &testutil.DummyAEAD{Name: base64Key},
	}, nil
}

func (a *aead) Encrypt(plaintext []byte, associatedData []byte) ([]byte, error) {
	ciphertext, err := a.dummyAEAD.Encrypt(plaintext, associatedData)
	if err != nil {
		return nil, err
	}
	return slices.Concat(a.prefix, ciphertext), nil
}

func (a *aead) Decrypt(ciphertext []byte, associatedData []byte) ([]byte, error) {
	if len(ciphertext) < len(a.prefix) {
		return nil, fmt.Errorf("ciphertext is too short")
	}
	if !bytes.Equal(ciphertext[:len(a.prefix)], a.prefix) {
		return nil, fmt.Errorf("ciphertext prefix does not match expected prefix")
	}
	ciphertext = ciphertext[len(a.prefix):]
	return a.dummyAEAD.Decrypt(ciphertext, associatedData)
}

// primitiveConstructor creates a [tink.AEAD] from a [key.Key].
//
// The key must be of type [keytest.Key].
func primitiveConstructor(k key.Key) (any, error) {
	that, ok := k.(*Key)
	if !ok {
		return nil, fmt.Errorf("key is of type %T; needed *keytest.Key", k)
	}
	return newAEAD(that)
}

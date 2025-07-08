// Copyright 2025 Google LLC
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

package hmacprf_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/prf/hmacprf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

var key128Bits = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
}
var key256Bits = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
}

func TestNewKey(t *testing.T) {
	for _, keyBytes := range [][]byte{key128Bits, key256Bits} {
		for _, hashType := range []hmacprf.HashType{hmacprf.SHA256, hmacprf.SHA512, hmacprf.SHA1, hmacprf.SHA384} {
			t.Run(fmt.Sprintf("HMAC keySize=%d hashType=%v", len(keyBytes), hashType), func(t *testing.T) {
				params, err := hmacprf.NewParameters(len(keyBytes), hashType)
				if err != nil {
					t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
				}
				keyBytes := secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{})
				key, err := hmacprf.NewKey(keyBytes, params)
				if err != nil {
					t.Errorf("hmacprf.NewKey() err = %v, want nil", err)
				}
				if !key.KeyBytes().Equal(keyBytes) {
					t.Errorf("KeyBytes() = %v, want %v", key.KeyBytes(), keyBytes)
				}
				if !key.Parameters().Equal(params) {
					t.Errorf("Parameters() = %v, want %v", key.Parameters(), params)
				}
				id, required := key.IDRequirement()
				if id != 0 {
					t.Errorf("IDRequirement() = %v, want 0", id)
				}
				if required {
					t.Errorf("IDRequirement() = %v, want false", required)
				}
				if key.OutputPrefix() != nil {
					t.Errorf("OutputPrefix() = %v, want nil", key.OutputPrefix())
				}

				key2, err := hmacprf.NewKey(keyBytes, params)
				if err != nil {
					t.Errorf("hmacprf.NewKey() err = %v, want nil", err)
				}
				if !key.Equal(key2) {
					t.Errorf("Equal() = false, want true")
				}
				if !key2.Equal(key) {
					t.Errorf("Equal() = false, want true")
				}
			})
		}
	}
}

func TestNewKeyFails(t *testing.T) {
	params, err := hmacprf.NewParameters(32, hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}
	keyBytes := secretdata.NewBytesFromData(key128Bits, insecuresecretdataaccess.Token{})
	if _, err := hmacprf.NewKey(keyBytes, params); err == nil {
		t.Errorf("hmacprf.NewKey() err = nil, want error")
	}
}

func TestNotEqualIfDifferentKeyBytes(t *testing.T) {
	params, err := hmacprf.NewParameters(32, hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}
	keyBytes1 := secretdata.NewBytesFromData(key256Bits, insecuresecretdataaccess.Token{})
	key1, err := hmacprf.NewKey(keyBytes1, params)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() err = %v, want nil", err)
	}

	otherKey := bytes.Clone(key256Bits)
	otherKey[0] ^= 0xff

	keyBytes2 := secretdata.NewBytesFromData(otherKey, insecuresecretdataaccess.Token{})
	key2, err := hmacprf.NewKey(keyBytes2, params)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() err = %v, want nil", err)
	}
	if key1.Equal(key2) {
		t.Errorf("Equal() = true, want false")
	}
}

func TestNotEqualIfDifferentKeySizes(t *testing.T) {
	params, err := hmacprf.NewParameters(32, hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}
	keyBytes1 := secretdata.NewBytesFromData(key256Bits, insecuresecretdataaccess.Token{})
	key1, err := hmacprf.NewKey(keyBytes1, params)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() err = %v, want nil", err)
	}

	params2, err := hmacprf.NewParameters(16, hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}
	keyBytes2 := secretdata.NewBytesFromData(key128Bits, insecuresecretdataaccess.Token{})
	key2, err := hmacprf.NewKey(keyBytes2, params2)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() err = %v, want nil", err)
	}
	if key1.Equal(key2) {
		t.Errorf("Equal() = true, want false")
	}
}

func TestNotEqualIfDifferentParams(t *testing.T) {
	params, err := hmacprf.NewParameters(32, hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}
	keyBytes1 := secretdata.NewBytesFromData(key256Bits, insecuresecretdataaccess.Token{})
	key1, err := hmacprf.NewKey(keyBytes1, params)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() err = %v, want nil", err)
	}

	params2, err := hmacprf.NewParameters(32, hmacprf.SHA512)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}
	keyBytes2 := secretdata.NewBytesFromData(key256Bits, insecuresecretdataaccess.Token{})
	key2, err := hmacprf.NewKey(keyBytes2, params2)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() err = %v, want nil", err)
	}
	if key1.Equal(key2) {
		t.Errorf("Equal() = true, want false")
	}
}

func TestKeyCreator(t *testing.T) {
	params, err := hmacprf.NewParameters(32, hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}

	key, err := keygenregistry.CreateKey(params, 0x1234)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey(%v, 0x1234) err = %v, want nil", &params, err)
	}
	aescmacKey, ok := key.(*hmacprf.Key)
	if !ok {
		t.Fatalf("keygenregistry.CreateKey(%v, 0x1234) returned key of type %T, want %T", params, key, (*hmacprf.Key)(nil))
	}
	idRequirement, hasIDRequirement := aescmacKey.IDRequirement()
	if hasIDRequirement || idRequirement != 0 {
		t.Errorf("aescmacKey.IDRequirement() (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 0, false)
	}
	if diff := cmp.Diff(aescmacKey.Parameters(), params); diff != "" {
		t.Errorf("aescmacKey.Parameters() diff (-want +got):\n%s", diff)
	}
}

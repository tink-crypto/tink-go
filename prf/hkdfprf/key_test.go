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

package hkdfprf_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
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
		for _, hashType := range []hkdfprf.HashType{hkdfprf.SHA256, hkdfprf.SHA512, hkdfprf.SHA1, hkdfprf.SHA384} {
			for _, salt := range [][]byte{nil, []byte("another salt")} {
				t.Run(fmt.Sprintf("HKDF keySize=%d hashType=%v, salt=%v", len(keyBytes), hashType, salt), func(t *testing.T) {
					params, err := hkdfprf.NewParameters(len(keyBytes), hashType, salt)
					if err != nil {
						t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
					}
					keyBytes := secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{})
					key, err := hkdfprf.NewKey(keyBytes, params)
					if err != nil {
						t.Errorf("hkdfprf.NewKey() err = %v, want nil", err)
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

					key2, err := hkdfprf.NewKey(keyBytes, params)
					if err != nil {
						t.Errorf("hkdfprf.NewKey() err = %v, want nil", err)
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
}

func TestNewKeyFails(t *testing.T) {
	params, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, nil)
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	keyBytes := secretdata.NewBytesFromData(key128Bits, insecuresecretdataaccess.Token{})
	if _, err := hkdfprf.NewKey(keyBytes, params); err == nil {
		t.Errorf("hkdfprf.NewKey() err = nil, want error")
	}
}

func TestNotEqualIfDifferentKeyBytes(t *testing.T) {
	params, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, nil)
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	keyBytes1 := secretdata.NewBytesFromData(key256Bits, insecuresecretdataaccess.Token{})
	key1, err := hkdfprf.NewKey(keyBytes1, params)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() err = %v, want nil", err)
	}

	otherKey := bytes.Clone(key256Bits)
	otherKey[0] ^= 0xff

	keyBytes2 := secretdata.NewBytesFromData(otherKey, insecuresecretdataaccess.Token{})
	key2, err := hkdfprf.NewKey(keyBytes2, params)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() err = %v, want nil", err)
	}
	if key1.Equal(key2) {
		t.Errorf("Equal() = true, want false")
	}
}

func TestNotEqualIfDifferentKeySizes(t *testing.T) {
	params, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, nil)
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	keyBytes1 := secretdata.NewBytesFromData(key256Bits, insecuresecretdataaccess.Token{})
	key1, err := hkdfprf.NewKey(keyBytes1, params)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() err = %v, want nil", err)
	}

	params2, err := hkdfprf.NewParameters(16, hkdfprf.SHA256, nil)
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	keyBytes2 := secretdata.NewBytesFromData(key128Bits, insecuresecretdataaccess.Token{})
	key2, err := hkdfprf.NewKey(keyBytes2, params2)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() err = %v, want nil", err)
	}
	if key1.Equal(key2) {
		t.Errorf("Equal() = true, want false")
	}
}

func TestNotEqualIfDifferentParams(t *testing.T) {
	params, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, nil)
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	keyBytes1 := secretdata.NewBytesFromData(key256Bits, insecuresecretdataaccess.Token{})
	key1, err := hkdfprf.NewKey(keyBytes1, params)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() err = %v, want nil", err)
	}

	params2, err := hkdfprf.NewParameters(32, hkdfprf.SHA512, nil)
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	keyBytes2 := secretdata.NewBytesFromData(key256Bits, insecuresecretdataaccess.Token{})
	key2, err := hkdfprf.NewKey(keyBytes2, params2)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() err = %v, want nil", err)
	}
	if key1.Equal(key2) {
		t.Errorf("Equal() = true, want false")
	}
}

func TestKeyCreator(t *testing.T) {
	params, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte("some salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}

	key, err := keygenregistry.CreateKey(params, 0x1234)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey(%v, 0x1234) err = %v, want nil", &params, err)
	}
	aescmacKey, ok := key.(*hkdfprf.Key)
	if !ok {
		t.Fatalf("keygenregistry.CreateKey(%v, 0x1234) returned key of type %T, want %T", params, key, (*hkdfprf.Key)(nil))
	}
	idRequirement, hasIDRequirement := aescmacKey.IDRequirement()
	if hasIDRequirement || idRequirement != 0 {
		t.Errorf("aescmacKey.IDRequirement() (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 0, false)
	}
	if diff := cmp.Diff(aescmacKey.Parameters(), params); diff != "" {
		t.Errorf("aescmacKey.Parameters() diff (-want +got):\n%s", diff)
	}
}

func TestKeyCreator_FailsWithInvalidParameters(t *testing.T) {

	for _, tc := range []struct {
		name          string
		params        *hkdfprf.Parameters
		idRequirement uint32
	}{
		{
			name:          "invalid key size",
			params:        mustCreateParameters(t, 16, hkdfprf.SHA256, []byte("some salt")), // Key size must be 32 bytes.
			idRequirement: 0x1234,
		},
		{
			name:          "invalid hash",
			params:        mustCreateParameters(t, 32, hkdfprf.SHA1, []byte("some salt")),
			idRequirement: 0x1234,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := keygenregistry.CreateKey(tc.params, tc.idRequirement); err == nil {
				t.Errorf("keygenregistry.CreateKey(%v, %v) err = nil, want error", tc.params, tc.idRequirement)
			}
		})
	}
}

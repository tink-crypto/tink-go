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

package aescmacprf_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/prf/aescmacprf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
)

var key128Bits = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
}
var key256Bits = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
}

func TestNewKey(t *testing.T) {
	for _, keySize := range []int{16, 32} {
		t.Run(fmt.Sprintf("keySize=%d", keySize), func(t *testing.T) {
			keyBytes := secretdata.NewBytesFromData(key256Bits[:keySize], testonlyinsecuresecretdataaccess.Token())
			key, err := aescmacprf.NewKey(keyBytes)
			if err != nil {
				t.Errorf("aescmacprf.NewKey() err = %v, want nil", err)
			}
			if !key.KeyBytes().Equal(keyBytes) {
				t.Errorf("KeyBytes() = %v, want %v", key.KeyBytes(), keyBytes)
			}
			wantParams, err := aescmacprf.NewParameters(keySize)
			if err != nil {
				t.Fatalf("aescmacprf.NewParameters() err = %v, want nil", err)
			}
			if !key.Parameters().Equal(&wantParams) {
				t.Errorf("Parameters() = %v, want %v", key.Parameters(), wantParams)
			}
			id, required := key.IDRequirement()
			if id != 0 {
				t.Errorf("IDRequirement() = %v, want 0", id)
			}
			if required {
				t.Errorf("IDRequirement() = %v, want false", required)
			}
		})
	}
}

func TestNewKeyFails(t *testing.T) {
	keyBytes := secretdata.NewBytesFromData(make([]byte, 33), testonlyinsecuresecretdataaccess.Token())
	if _, err := aescmacprf.NewKey(keyBytes); err == nil {
		t.Errorf("aescmacprf.NewKey() err = nil, want error")
	}
}

func TestEqual(t *testing.T) {
	keyBytes := secretdata.NewBytesFromData(key256Bits, testonlyinsecuresecretdataaccess.Token())
	key1, err := aescmacprf.NewKey(keyBytes)
	if err != nil {
		t.Fatalf("aescmacprf.NewKey() err = %v, want nil", err)
	}
	key2, err := aescmacprf.NewKey(keyBytes)
	if err != nil {
		t.Fatalf("aescmacprf.NewKey() err = %v, want nil", err)
	}
	if !key1.Equal(key2) {
		t.Errorf("Equal() = false, want true")
	}
}

func TestNotEqualIfDifferentKeyBytes(t *testing.T) {
	keyBytes1 := secretdata.NewBytesFromData(key256Bits, testonlyinsecuresecretdataaccess.Token())
	key1, err := aescmacprf.NewKey(keyBytes1)
	if err != nil {
		t.Fatalf("aescmacprf.NewKey() err = %v, want nil", err)
	}

	otherKey := bytes.Clone(key256Bits)
	otherKey[0] ^= 0xff

	keyBytes2 := secretdata.NewBytesFromData(otherKey, testonlyinsecuresecretdataaccess.Token())
	key2, err := aescmacprf.NewKey(keyBytes2)
	if err != nil {
		t.Fatalf("aescmacprf.NewKey() err = %v, want nil", err)
	}
	if key1.Equal(key2) {
		t.Errorf("Equal() = true, want false")
	}
}

func TestNotEqualIfDifferentKeySizes(t *testing.T) {
	keyBytes1 := secretdata.NewBytesFromData(key256Bits, testonlyinsecuresecretdataaccess.Token())
	key1, err := aescmacprf.NewKey(keyBytes1)
	if err != nil {
		t.Fatalf("aescmacprf.NewKey() err = %v, want nil", err)
	}

	keyBytes2 := secretdata.NewBytesFromData(key128Bits, testonlyinsecuresecretdataaccess.Token())
	key2, err := aescmacprf.NewKey(keyBytes2)
	if err != nil {
		t.Fatalf("aescmacprf.NewKey() err = %v, want nil", err)
	}
	if key1.Equal(key2) {
		t.Errorf("Equal() = true, want false")
	}
}

func TestKeyCreator(t *testing.T) {
	params, err := aescmacprf.NewParameters(32)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters() err = %v, want nil", err)
	}

	key, err := keygenregistry.CreateKey(&params, 0x1234)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey(%v, 0x1234) err = %v, want nil", &params, err)
	}
	aescmacKey, ok := key.(*aescmacprf.Key)
	if !ok {
		t.Fatalf("keygenregistry.CreateKey(%v, 0x1234) returned key of type %T, want %T", params, key, (*aescmacprf.Key)(nil))
	}
	idRequirement, hasIDRequirement := aescmacKey.IDRequirement()
	if hasIDRequirement || idRequirement != 0 {
		t.Errorf("aescmacKey.IDRequirement() (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 0, false)
	}
	if diff := cmp.Diff(aescmacKey.Parameters(), &params); diff != "" {
		t.Errorf("aescmacKey.Parameters() diff (-want +got):\n%s", diff)
	}
}

func TestKeyCreator_FailsWithInvalidParameters(t *testing.T) {
	params16Bytes, err := aescmacprf.NewParameters(16)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters() err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name          string
		params        *aescmacprf.Parameters
		idRequirement uint32
	}{
		{
			name:          "invalid key size",
			params:        &params16Bytes, // Key size must be 32 bytes.
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

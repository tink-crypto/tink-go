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

package aessiv_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/daead/aessiv"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

var (
	key256Bits = []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	key384Bits = []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	key512Bits = []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
)

func TestNewKeyFailsIfParametersIsNil(t *testing.T) {
	keyBytes, err := secretdata.NewBytesFromRand(32)
	if err != nil {
		t.Fatalf("secretdata.NewBytesFromRand(32) err = %v, want nil", err)
	}
	if _, err := aessiv.NewKey(keyBytes, 123, nil); err == nil {
		t.Errorf("aessiv.NewKey(keyBytes, 123, nil) err = nil, want error")
	}
}

func TestNewKeyFailsIfKeySizeIsDifferentThanParameters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		keyBytes secretdata.Bytes
		keySize  int
		variant  aessiv.Variant
	}{
		{
			name:     "key size is 48 but parameters is 32",
			keyBytes: secretdata.NewBytesFromData(key384Bits, insecuresecretdataaccess.Token{}),
			keySize:  32,
			variant:  aessiv.VariantTink,
		},
		{
			name:     "key size is 32 but parameters is 48",
			keyBytes: secretdata.NewBytesFromData(key256Bits, insecuresecretdataaccess.Token{}),
			keySize:  48,
			variant:  aessiv.VariantTink,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := aessiv.NewParameters(tc.keySize, tc.variant)
			if err != nil {
				t.Fatalf("aessiv.NewParameters(%v, %v) err = %v, want nil", tc.keySize, tc.variant, err)
			}
			if _, err := aessiv.NewKey(tc.keyBytes, 123, params); err == nil {
				t.Errorf("aessiv.NewKey(%v, 123, %v) err = nil, want error", tc.keyBytes, params)
			}
		})
	}
}

// TestNewKeyFailsIfInvalidParams tests that NewKey fails if the parameters are invalid.
//
// The only way to create invalid parameters is to create a struct literal with default
// values.
func TestNewKeyFailsIfInvalidParams(t *testing.T) {
	keyBytes, err := secretdata.NewBytesFromRand(32)
	if err != nil {
		t.Fatalf("secretdata.NewBytesFromRand(32) err = %v, want nil", err)
	}
	params := &aessiv.Parameters{}
	if _, err := aessiv.NewKey(keyBytes, 123, params); err == nil {
		t.Errorf("aessiv.NewKey(keyBytes, 123, nil) err = nil, want error")
	}
}

func TestNewKeyFailsIfNoPrefixAndIDIsNotZero(t *testing.T) {
	params, err := aessiv.NewParameters(32, aessiv.VariantNoPrefix)
	if err != nil {
		t.Fatalf("aessiv.NewParameters(%v, %v) err = %v, want nil", 32, aessiv.VariantNoPrefix, err)
	}
	keyBytes := secretdata.NewBytesFromData(key384Bits, insecuresecretdataaccess.Token{})
	if _, err := aessiv.NewKey(keyBytes, 123, params); err == nil {
		t.Errorf("aessiv.NewKey(keyBytes, 123, %v) err = nil, want error", params)
	}
}

func TestOutputPrefix(t *testing.T) {
	for _, test := range []struct {
		name    string
		variant aessiv.Variant
		id      uint32
		want    []byte
	}{
		{
			name:    "Tink",
			variant: aessiv.VariantTink,
			id:      uint32(0x01020304),
			want:    []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "Crunchy",
			variant: aessiv.VariantCrunchy,
			id:      uint32(0x01020304),
			want:    []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "No prefix",
			variant: aessiv.VariantNoPrefix,
			id:      0,
			want:    nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := aessiv.NewParameters(32, test.variant)
			if err != nil {
				t.Fatalf("aessiv.NewParameters(32, %v) err = %v, want nil", test.variant, err)
			}
			keyBytes, err := secretdata.NewBytesFromRand(32)
			if err != nil {
				t.Fatalf("secretdata.NewBytes(32fNewBytesFromRand() err = %v, want nil", err)
			}
			key, err := aessiv.NewKey(keyBytes, test.id, params)
			if err != nil {
				t.Fatalf("aessiv.NewKey(keyBytes, %v, %v) err = %v, want nil", test.id, params, err)
			}
			if got := key.OutputPrefix(); !bytes.Equal(got, test.want) {
				t.Errorf("params.OutputPrefix() = %v, want %v", got, test.want)
			}
		})
	}
}

type testKey struct {
	name    string
	keySize int
	id      uint32
	key     []byte
	variant aessiv.Variant
}

func TestNewKeyWorks(t *testing.T) {
	for _, test := range []testKey{

		{
			name:    "256-bit key with Tink prefix",
			keySize: 32,
			id:      1,
			key:     key256Bits,
			variant: aessiv.VariantTink,
		},
		{
			name:    "256-bit key with Crunchy prefix",
			keySize: 32,
			id:      1,
			key:     key256Bits,
			variant: aessiv.VariantCrunchy,
		},
		{
			name:    "256-bit key with NoPrefix prefix",
			keySize: 32,
			id:      0,
			key:     key256Bits,
			variant: aessiv.VariantNoPrefix,
		},
		{
			name:    "384-bit key with Tink prefix",
			keySize: 48,
			id:      1,
			key:     key384Bits,
			variant: aessiv.VariantTink,
		},
		{
			name:    "384-bit key with Crunchy prefix",
			keySize: 48,
			id:      1,
			key:     key384Bits,
			variant: aessiv.VariantCrunchy,
		},
		{
			name:    "384-bit key with NoPrefix prefix",
			keySize: 48,
			id:      0,
			key:     key384Bits,
			variant: aessiv.VariantNoPrefix,
		},
		{
			name:    "512-bit key with Tink prefix",
			keySize: 64,
			id:      1,
			key:     key512Bits,
			variant: aessiv.VariantTink,
		},
		{
			name:    "512-bit key with Crunchy prefix",
			keySize: 64,
			id:      1,
			key:     key512Bits,
			variant: aessiv.VariantCrunchy,
		},
		{
			name:    "512-bit key with NoPrefix prefix",
			keySize: 64,
			id:      0,
			key:     key512Bits,
			variant: aessiv.VariantNoPrefix,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := aessiv.NewParameters(test.keySize, test.variant)
			if err != nil {
				t.Fatalf("aessiv.NewParameters(%v, %v) err = %v, want nil", test.keySize, test.variant, err)
			}
			keyBytes := secretdata.NewBytesFromData(test.key, insecuresecretdataaccess.Token{})

			// Create two keys with the same parameters and key bytes.
			key1, err := aessiv.NewKey(keyBytes, test.id, params)
			if err != nil {
				t.Fatalf("aessiv.NewKey(keyBytes, %v, %v) err = %v, want nil", test.id, params, err)
			}
			if !key1.Parameters().Equal(params) {
				t.Errorf("key1.Parameters() = %v, want %v", key1.Parameters(), params)
			}
			key1Bytes := key1.KeyBytes()
			if !keyBytes.Equal(key1Bytes) {
				t.Errorf("keyBytes.Equal(key1Bytes) = false, want true")
			}
			keyID1, required := key1.IDRequirement()
			if wantRequired := test.variant != aessiv.VariantNoPrefix; required != wantRequired {
				t.Errorf("required = %v, want %v", required, wantRequired)
			}
			wantID := test.id
			if !required {
				wantID = 0
			}
			if keyID1 != wantID {
				t.Errorf("keyID1 = %v, want %v", keyID1, wantID)
			}
			key2, err := aessiv.NewKey(keyBytes, keyID1, params)
			if err != nil {
				t.Fatalf("aessiv.NewKey(keyBytes, %v, %v) err = %v, want nil", keyID1, params, err)
			}
			// Test Equal.
			if !key1.Equal(key2) {
				t.Errorf("key1.Equal(key2) = %v, want true", key1.Equal(key2))
			}
		})
	}
}

func TestKeyEqualReturnsFalseIfDifferent(t *testing.T) {
	for _, test := range []struct {
		name   string
		first  testKey
		second testKey
	}{
		{
			name: "different key size",
			first: testKey{
				keySize: 48,
				variant: aessiv.VariantTink,
				key:     key384Bits,
				id:      0x01,
			},
			second: testKey{
				keySize: 32,
				variant: aessiv.VariantTink,
				key:     key256Bits,
				id:      0x01,
			},
		},
		{
			name: "different prefix variant",
			first: testKey{
				keySize: 48,
				variant: aessiv.VariantTink,
				key:     key384Bits,
				id:      0x01,
			},
			second: testKey{
				keySize: 48,
				variant: aessiv.VariantCrunchy,
				key:     key384Bits,
				id:      0x01,
			},
		},
		{
			name: "different key IDs",
			first: testKey{
				keySize: 48,
				variant: aessiv.VariantTink,
				key:     key384Bits,
				id:      0x01,
			},
			second: testKey{
				keySize: 48,
				variant: aessiv.VariantTink,
				key:     key384Bits,
				id:      0x02,
			},
		},
		{
			name: "different key bytes",
			first: testKey{
				keySize: 48,
				variant: aessiv.VariantCrunchy,
				key:     key384Bits,
				id:      0x01,
			},
			second: testKey{
				keySize: 48,
				variant: aessiv.VariantCrunchy,
				key: func() []byte {
					k := slices.Clone(key384Bits)
					k[0] ^= 1
					return k
				}(),
				id: 0x01,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			firstParams, err := aessiv.NewParameters(test.first.keySize, test.first.variant)
			if err != nil {
				t.Fatalf("aessiv.NewParameters(%v, %v) err = %v, want nil", test.first.keySize, test.first.variant, err)
			}
			firstKeyBytes := secretdata.NewBytesFromData(test.first.key, insecuresecretdataaccess.Token{})
			firstKey, err := aessiv.NewKey(firstKeyBytes, test.first.id, firstParams)
			if err != nil {
				t.Fatalf("aessiv.NewKey(firstKeyBytes, %v, %v) err = %v, want nil", test.first.id, firstParams, err)
			}
			secondParams, err := aessiv.NewParameters(test.second.keySize, test.second.variant)
			if err != nil {
				t.Fatalf("aessiv.NewParameters(%v, %v) err = %v, want nil", test.second.keySize, test.second.variant, err)
			}
			secondKeyBytes := secretdata.NewBytesFromData(test.second.key, insecuresecretdataaccess.Token{})
			secondKey, err := aessiv.NewKey(secondKeyBytes, test.second.id, secondParams)
			if err != nil {
				t.Fatalf("aessiv.NewKey(secondKeyBytes, %v, %v) err = %v, want nil", test.second.id, secondParams, err)
			}
			if firstKey.Equal(secondKey) {
				t.Errorf("firstKey.Equal(secondKey) = true, want false")
			}
		})
	}
}

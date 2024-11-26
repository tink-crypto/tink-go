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

package aesgcmsiv_test

import (
	"bytes"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcmsiv"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

var (
	key128Bits = []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	key256Bits = []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
)

func TestNewParametersInvalidKeySize(t *testing.T) {
	for _, keySize := range []int{1, 15, 17, 31, 33} {
		if _, err := aesgcmsiv.NewParameters(keySize, aesgcmsiv.VariantTink); err == nil {
			t.Errorf("aesgcmsiv.NewParameters(%v, %v) err = nil, want error", keySize, aesgcmsiv.VariantTink)
		}
	}
}

func TestNewParametersInvalidVariant(t *testing.T) {
	if _, err := aesgcmsiv.NewParameters(16, aesgcmsiv.VariantUnknown); err == nil {
		t.Errorf("aesgcmsiv.NewParameters(%v, %v) err = nil, want error", 16, aesgcmsiv.VariantUnknown)
	}
}

func TestNewKeyFailsIfParametersIsNil(t *testing.T) {
	keyBytes, err := secretdata.NewBytesFromRand(32)
	if err != nil {
		t.Fatalf("secretdata.NewBytesFromRand(32) err = %v, want nil", err)
	}
	if _, err := aesgcmsiv.NewKey(keyBytes, 123, nil); err == nil {
		t.Errorf("aesgcmsiv.NewKey(keyBytes, 123, nil) err = nil, want error")
	}
}

func TestNewKeyFailsIfKeySizeIsDifferentThanParameters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		keyBytes secretdata.Bytes
		keySize  int
		variant  aesgcmsiv.Variant
	}{
		{
			name:     "key size is 16 but parameters is 32",
			keyBytes: secretdata.NewBytesFromData(key128Bits, insecuresecretdataaccess.Token{}),
			keySize:  32,
			variant:  aesgcmsiv.VariantTink,
		},
		{
			name:     "key size is 32 but parameters is 16",
			keyBytes: secretdata.NewBytesFromData(key256Bits, insecuresecretdataaccess.Token{}),
			keySize:  16,
			variant:  aesgcmsiv.VariantTink,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := aesgcmsiv.NewParameters(tc.keySize, tc.variant)
			if err != nil {
				t.Fatalf("aesgcmsiv.NewParameters(%v, %v) err = %v, want nil", tc.keySize, tc.variant, err)
			}
			if _, err := aesgcmsiv.NewKey(tc.keyBytes, 123, params); err == nil {
				t.Errorf("aesgcmsiv.NewKey(%v, 123, %v) err = nil, want error", tc.keyBytes, params)
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
	params := &aesgcmsiv.Parameters{}
	if _, err := aesgcmsiv.NewKey(keyBytes, 123, params); err == nil {
		t.Errorf("aesgcmsiv.NewKey(keyBytes, 123, nil) err = nil, want error")
	}
}

func TestNewKeyFailsIfNoPrefixAndIDIsNotZero(t *testing.T) {
	params, err := aesgcmsiv.NewParameters(16, aesgcmsiv.VariantNoPrefix)
	if err != nil {
		t.Fatalf("aesgcmsiv.NewParameters(%v, %v) err = %v, want nil", 16, aesgcmsiv.VariantNoPrefix, err)
	}
	keyBytes := secretdata.NewBytesFromData(key128Bits, insecuresecretdataaccess.Token{})
	if _, err := aesgcmsiv.NewKey(keyBytes, 123, params); err == nil {
		t.Errorf("aesgcmsiv.NewKey(keyBytes, 123, %v) err = nil, want error", params)
	}
}

func TestOutputPrefix(t *testing.T) {
	for _, test := range []struct {
		name    string
		variant aesgcmsiv.Variant
		id      uint32
		want    []byte
	}{
		{
			name:    "Tink",
			variant: aesgcmsiv.VariantTink,
			id:      uint32(0x01020304),
			want:    []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "Crunchy",
			variant: aesgcmsiv.VariantCrunchy,
			id:      uint32(0x01020304),
			want:    []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "No prefix",
			variant: aesgcmsiv.VariantNoPrefix,
			id:      0,
			want:    nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := aesgcmsiv.NewParameters(32, test.variant)
			if err != nil {
				t.Fatalf("aesgcmsiv.NewParameters(32, %v) err = %v, want nil", test.variant, err)
			}
			keyBytes, err := secretdata.NewBytesFromRand(32)
			if err != nil {
				t.Fatalf("secretdata.NewBytes(32fNewBytesFromRand() err = %v, want nil", err)
			}
			key, err := aesgcmsiv.NewKey(keyBytes, test.id, params)
			if err != nil {
				t.Fatalf("aesgcmsiv.NewKey(keyBytes, %v, %v) err = %v, want nil", test.id, params, err)
			}
			if got := key.OutputPrefix(); !bytes.Equal(got, test.want) {
				t.Errorf("params.OutputPrefix() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestNewParametersWorks(t *testing.T) {
	for _, test := range []struct {
		name    string
		keySize int
		variant aesgcmsiv.Variant
	}{
		{
			name:    "128-bit key with Tink prefix",
			keySize: 16,
			variant: aesgcmsiv.VariantTink,
		},
		{
			name:    "128-bit key with Crunchy prefix",
			keySize: 16,
			variant: aesgcmsiv.VariantCrunchy,
		},
		{
			name:    "128-bit key with NoPrefix prefix",
			keySize: 16,
			variant: aesgcmsiv.VariantNoPrefix,
		},
		{
			name:    "256-bit key with Tink prefix",
			keySize: 32,
			variant: aesgcmsiv.VariantTink,
		},
		{
			name:    "256-bit key with Crunchy prefix",
			keySize: 32,
			variant: aesgcmsiv.VariantCrunchy,
		},
		{
			name:    "256-bit key with NoPrefix prefix",
			keySize: 32,
			variant: aesgcmsiv.VariantNoPrefix,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := aesgcmsiv.NewParameters(test.keySize, test.variant)
			if err != nil {
				t.Fatalf("aesgcmsiv.NewParameters(%v, %v) err = %v, want nil", test.keySize, test.variant, err)
			}
			if params.HasIDRequirement() != (test.variant != aesgcmsiv.VariantNoPrefix) {
				t.Errorf("params.HasIDRequirement() = %v, want %v", params.HasIDRequirement(), (test.variant != aesgcmsiv.VariantNoPrefix))
			}
			if params.KeySizeInBytes() != test.keySize {
				t.Errorf("params.KeySizeInBytes()() = %v, want %v", params.KeySizeInBytes(), test.keySize)
			}
			if params.Variant() != test.variant {
				t.Errorf("params.Variant() = %v, want %v", params.Variant(), test.variant)
			}
			otherParams, err := aesgcmsiv.NewParameters(test.keySize, test.variant)
			if err != nil {
				t.Fatalf("aesgcmsiv.NewParameters(%v, %v) err = %v, want nil", test.keySize, test.variant, err)
			}
			if !params.Equals(otherParams) {
				t.Errorf("params.Equals(otherParams) = %v, want true", params.Equals(otherParams))
			}
		})
	}
}

func TestParametersEqualsFalseIfDifferent(t *testing.T) {
	for _, test := range []struct {
		name        string
		key1Size    int
		key1Variant aesgcmsiv.Variant
		key2Size    int
		key2Variant aesgcmsiv.Variant
	}{
		{
			name:        "different key size",
			key1Size:    16,
			key1Variant: aesgcmsiv.VariantTink,
			key2Size:    32,
			key2Variant: aesgcmsiv.VariantTink,
		},
		{
			name:        "different prefix variant",
			key1Size:    16,
			key1Variant: aesgcmsiv.VariantCrunchy,
			key2Size:    16,
			key2Variant: aesgcmsiv.VariantTink,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params1, err := aesgcmsiv.NewParameters(test.key1Size, test.key1Variant)
			if err != nil {
				t.Fatalf("aesgcmsiv.NewParameters(%v, %v) err = %v, want nil", test.key1Size, test.key1Variant, err)
			}
			params2, err := aesgcmsiv.NewParameters(test.key2Size, test.key2Variant)
			if err != nil {
				t.Errorf("aesgcmsiv.NewParameters(%v, %v) err = %v, want nil", test.key2Size, test.key2Variant, err)
			}
			if params1.Equals(params2) {
				t.Errorf("params.Equals(params2) = %v, want false", params1.Equals(params2))
			}
		})
	}
}

type TestKey struct {
	name    string
	keySize int
	id      uint32
	key     []byte
	variant aesgcmsiv.Variant
}

func TestNewKeyWorks(t *testing.T) {
	for _, test := range []TestKey{
		{
			name:    "128-bit key with Tink prefix",
			keySize: 16,
			id:      1,
			key:     key128Bits,
			variant: aesgcmsiv.VariantTink,
		},
		{
			name:    "128-bit key with Crunchy prefix",
			keySize: 16,
			id:      1,
			key:     key128Bits,
			variant: aesgcmsiv.VariantCrunchy,
		},
		{
			name:    "128-bit key with NoPrefix prefix",
			keySize: 16,
			id:      0,
			key:     key128Bits,
			variant: aesgcmsiv.VariantNoPrefix,
		},
		{
			name:    "256-bit key with Tink prefix",
			keySize: 32,
			id:      1,
			key:     key256Bits,
			variant: aesgcmsiv.VariantTink,
		},
		{
			name:    "256-bit key with Crunchy prefix",
			keySize: 32,
			id:      1,
			key:     key256Bits,
			variant: aesgcmsiv.VariantCrunchy,
		},
		{
			name:    "256-bit key with NoPrefix prefix",
			keySize: 32,
			id:      0,
			key:     key256Bits,
			variant: aesgcmsiv.VariantNoPrefix,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := aesgcmsiv.NewParameters(test.keySize, test.variant)
			if err != nil {
				t.Fatalf("aesgcmsiv.NewParameters(%v, %v) err = %v, want nil", test.keySize, test.variant, err)
			}
			keyBytes := secretdata.NewBytesFromData(test.key, insecuresecretdataaccess.Token{})

			// Create two keys with the same parameters and key bytes.
			key1, err := aesgcmsiv.NewKey(keyBytes, test.id, params)
			if err != nil {
				t.Fatalf("aesgcmsiv.NewKey(keyBytes, %v, %v) err = %v, want nil", test.id, params, err)
			}
			if !key1.Parameters().Equals(params) {
				t.Errorf("key1.Parameters() = %v, want %v", key1.Parameters(), params)
			}
			key1Bytes := key1.KeyBytes()
			if !keyBytes.Equals(key1Bytes) {
				t.Errorf("keyBytes.Equals(key1Bytes) = false, want true")
			}
			keyID1, required := key1.IDRequirement()
			if wantRequired := test.variant != aesgcmsiv.VariantNoPrefix; required != wantRequired {
				t.Errorf("required = %v, want %v", required, wantRequired)
			}
			wantID := test.id
			if !required {
				wantID = 0
			}
			if keyID1 != wantID {
				t.Errorf("keyID1 = %v, want %v", keyID1, wantID)
			}
			key2, err := aesgcmsiv.NewKey(keyBytes, keyID1, params)
			if err != nil {
				t.Fatalf("aesgcmsiv.NewKey(keyBytes, %v, %v) err = %v, want nil", keyID1, params, err)
			}
			// Test Equals.
			if !key1.Equals(key2) {
				t.Errorf("key1.Equals(key2) = %v, want true", key1.Equals(key2))
			}
		})
	}
}

func TestKeyEqualsReturnsFalseIfDifferent(t *testing.T) {
	for _, test := range []struct {
		name   string
		first  TestKey
		second TestKey
	}{
		{
			name: "different key size",
			first: TestKey{
				keySize: 16,
				variant: aesgcmsiv.VariantTink,
				key:     key128Bits,
				id:      0x01,
			},
			second: TestKey{
				keySize: 32,
				variant: aesgcmsiv.VariantTink,
				key:     key256Bits,
				id:      0x01,
			},
		},
		{
			name: "different prefix variant",
			first: TestKey{
				keySize: 16,
				variant: aesgcmsiv.VariantTink,
				key:     key128Bits,
				id:      0x01,
			},
			second: TestKey{
				keySize: 16,
				variant: aesgcmsiv.VariantCrunchy,
				key:     key128Bits,
				id:      0x01,
			},
		},
		{
			name: "different key IDs",
			first: TestKey{
				keySize: 16,
				variant: aesgcmsiv.VariantTink,
				key:     key128Bits,
				id:      0x01,
			},
			second: TestKey{
				keySize: 16,
				variant: aesgcmsiv.VariantTink,
				key:     key128Bits,
				id:      0x02,
			},
		},
		{
			name: "different key bytes",
			first: TestKey{
				keySize: 16,
				variant: aesgcmsiv.VariantCrunchy,
				key:     key128Bits,
				id:      0x01,
			},
			second: TestKey{
				keySize: 16,
				variant: aesgcmsiv.VariantCrunchy,
				key: []byte{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09,
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				},
				id: 0x01,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			firstParams, err := aesgcmsiv.NewParameters(test.first.keySize, test.first.variant)
			if err != nil {
				t.Fatalf("aesgcmsiv.NewParameters(%v, %v) err = %v, want nil", test.first.keySize, test.first.variant, err)
			}
			firstKeyBytes := secretdata.NewBytesFromData(test.first.key, insecuresecretdataaccess.Token{})
			firstKey, err := aesgcmsiv.NewKey(firstKeyBytes, test.first.id, firstParams)
			if err != nil {
				t.Fatalf("aesgcmsiv.NewKey(firstKeyBytes, %v, %v) err = %v, want nil", test.first.id, firstParams, err)
			}

			secondParams, err := aesgcmsiv.NewParameters(test.second.keySize, test.second.variant)
			if err != nil {
				t.Fatalf("aesgcmsiv.NewParameters(%v, %v) err = %v, want nil", test.second.keySize, test.second.variant, err)
			}
			secondKeyBytes := secretdata.NewBytesFromData(test.second.key, insecuresecretdataaccess.Token{})
			secondKey, err := aesgcmsiv.NewKey(secondKeyBytes, test.second.id, secondParams)
			if err != nil {
				t.Fatalf("aesgcmsiv.NewKey(secondKeyBytes, %v, %v) err = %v, want nil", test.second.id, secondParams, err)
			}
			if firstKey.Equals(secondKey) {
				t.Errorf("firstKey.Equals(secondKey) = true, want false")
			}
		})
	}
}

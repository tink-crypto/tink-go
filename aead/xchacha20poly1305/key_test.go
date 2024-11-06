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

package xchacha20poly1305_test

import (
	"bytes"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/xchacha20poly1305"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

var (
	rawKey = []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
)

func TestNewParametersInvalidVariant(t *testing.T) {
	if _, err := xchacha20poly1305.NewParameters(xchacha20poly1305.VariantUnknown); err == nil {
		t.Errorf("xchacha20poly1305.NewParameters(xchacha20poly1305.VariantUnknown) err = nil, want error")
	}
}


func TestOutputPrefix(t *testing.T) {
	for _, test := range []struct {
		name    string
		variant xchacha20poly1305.Variant
		id      uint32
		want    []byte
	}{
		{
			name:    "Tink",
			variant: xchacha20poly1305.VariantTink,
			id:      0x01020304,
			want:    []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "Crunchy",
			variant: xchacha20poly1305.VariantCrunchy,
			id:      0x01020304,
			want:    []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "No prefix",
			variant: xchacha20poly1305.VariantNoPrefix,
			id:      0,
			want:    nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := xchacha20poly1305.NewParameters(test.variant)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", test.variant, err)
			}
			keyBytes, err := secretdata.NewBytesFromRand(32)
			if err != nil {
				t.Fatalf("secretdata.NewBytes(32fNewBytesFromRand() err = %v, want nil", err)
			}
			key, err := xchacha20poly1305.NewKey(keyBytes, test.id, params)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewKey(keyBytes, %v, %v) err = %v, want nil", test.id, params, err)
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
		variant xchacha20poly1305.Variant
	}{
		{
			name:    "TINK",
			variant: xchacha20poly1305.VariantTink,
		},
		{
			name:    "CRUNCHY",
			variant: xchacha20poly1305.VariantCrunchy,
		},
		{
			name:    "RAW",
			variant: xchacha20poly1305.VariantNoPrefix,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := xchacha20poly1305.NewParameters(test.variant)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", test.variant, err)
			}
			if params.HasIDRequirement() != (test.variant != xchacha20poly1305.VariantNoPrefix) {
				t.Errorf("params.HasIDRequirement() = %v, want %v", params.HasIDRequirement(), (test.variant != xchacha20poly1305.VariantNoPrefix))
			}
			if params.Variant() != test.variant {
				t.Errorf("params.Variant() = %v, want %v", params.Variant(), test.variant)
			}
			// Test equality.
			otherParams, err := xchacha20poly1305.NewParameters(test.variant)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", test.variant, err)
			}
			if !params.Equals(otherParams) {
				t.Errorf("params.Equals(otherParams) = %v, want true", params.Equals(otherParams))
			}
		})
	}
}

func TestParametersEqualsFalseIfDifferentVariant(t *testing.T) {
	for _, test := range []struct {
		name        string
		key1Variant xchacha20poly1305.Variant
		key2Variant xchacha20poly1305.Variant
	}{
		{
			name:        "CRUNCHY vs TINK",
			key1Variant: xchacha20poly1305.VariantCrunchy,
			key2Variant: xchacha20poly1305.VariantTink,
		},
		{
			name:        "CRUNCHY vs RAW",
			key1Variant: xchacha20poly1305.VariantCrunchy,
			key2Variant: xchacha20poly1305.VariantNoPrefix,
		},
		{
			name:        "TINK vs RAW",
			key1Variant: xchacha20poly1305.VariantTink,
			key2Variant: xchacha20poly1305.VariantNoPrefix,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params1, err := xchacha20poly1305.NewParameters(test.key1Variant)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", test.key1Variant, err)
			}
			params2, err := xchacha20poly1305.NewParameters(test.key2Variant)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", test.key2Variant, err)
			}
			if params1.Equals(params2) {
				t.Errorf("params.Equals(params2) = %v, want false", params1.Equals(params2))
			}
		})
	}
}

type TestKey struct {
	name    string
	id      uint32
	key     []byte
	variant xchacha20poly1305.Variant
}

func TestNewKeyWorks(t *testing.T) {
	for _, tc := range []TestKey{
		{
			name:    "Tink variant",
			id:      0x01,
			key:     rawKey,
			variant: xchacha20poly1305.VariantTink,
		},
		{
			name:    "Crunchy variant",
			id:      0x01,
			key:     rawKey,
			variant: xchacha20poly1305.VariantCrunchy,
		},
		{
			name:    "NoPrefix variant",
			id:      0,
			key:     rawKey,
			variant: xchacha20poly1305.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := xchacha20poly1305.NewParameters(tc.variant)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			keyBytes := secretdata.NewBytesFromData(tc.key, insecuresecretdataaccess.Token{})
			firstKey, err := xchacha20poly1305.NewKey(keyBytes, tc.id, params)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewKey(keyBytes, %v, %v) err = %v, want nil", tc.id, params, err)
			}
			if !firstKey.Parameters().Equals(params) {
				t.Errorf("firstKey.Parameters() = %v, want %v", firstKey.Parameters(), params)
			}
			firstKeyBytes := firstKey.KeyBytes()
			if !keyBytes.Equals(firstKeyBytes) {
				t.Errorf("keyBytes.Equals(firstKeyBytes) = false, want true")
			}
			id, required := firstKey.IDRequirement()
			if required != (tc.variant != xchacha20poly1305.VariantNoPrefix) {
				t.Errorf("firstKey.ID() = %v, want %v", required, (tc.variant == xchacha20poly1305.VariantNoPrefix))
			}
			if id != tc.id {
				t.Errorf("id = %v, want %v", id, tc.id)
			}
			// Test Equals.
			secondKey, err := xchacha20poly1305.NewKey(keyBytes, tc.id, params)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewKey(keyBytes, %v, %v) err = %v, want nil", tc.id, params, err)
			}
			if !firstKey.Equals(secondKey) {
				t.Errorf("firstKey.Equals(secondKey) = %v, want true", firstKey.Equals(secondKey))
			}
		})
	}
}

func TestNewKeyFailsIfNoPrefixAndIDIsNotZero(t *testing.T) {
	params, err := xchacha20poly1305.NewParameters(xchacha20poly1305.VariantNoPrefix)
	if err != nil {
		t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", xchacha20poly1305.VariantNoPrefix, err)
	}
	keyBytes := secretdata.NewBytesFromData(rawKey, insecuresecretdataaccess.Token{})
	if _, err := xchacha20poly1305.NewKey(keyBytes, 123, params); err == nil {
		t.Errorf("xchacha20poly1305.NewKey(keyBytes, 123, %v) err = nil, want error", params)
	}
}

func TestKeyEqualsReturnsFalseIfDifferent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		first  TestKey
		second TestKey
	}{
		{
			name: "different prefix variant",
			first: TestKey{
				variant: xchacha20poly1305.VariantTink,
				key:     rawKey,
				id:      0x01,
			},
			second: TestKey{
				variant: xchacha20poly1305.VariantCrunchy,
				key:     rawKey,
				id:      0x01,
			},
		},
		{
			name: "different key IDs",
			first: TestKey{
				variant: xchacha20poly1305.VariantTink,
				key:     rawKey,
				id:      0x01,
			},
			second: TestKey{
				variant: xchacha20poly1305.VariantTink,
				key:     rawKey,
				id:      0x02,
			},
		},
		{
			name: "different key bytes",
			first: TestKey{
				variant: xchacha20poly1305.VariantCrunchy,
				key:     rawKey,
				id:      0x01,
			},
			second: TestKey{
				variant: xchacha20poly1305.VariantCrunchy,
				key: []byte{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09,
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				},
				id: 0x01,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			firstParams, err := xchacha20poly1305.NewParameters(tc.first.variant)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", tc.first.variant, err)
			}
			firstKeyBytes := secretdata.NewBytesFromData(tc.first.key, insecuresecretdataaccess.Token{})
			firstKey, err := xchacha20poly1305.NewKey(firstKeyBytes, tc.first.id, firstParams)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewKey(firstKeyBytes, %v, %v) err = %v, want nil", tc.first.id, firstParams, err)
			}
			secondParams, err := xchacha20poly1305.NewParameters(tc.second.variant)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", tc.second.variant, err)
			}
			secondKeyBytes := secretdata.NewBytesFromData(tc.second.key, insecuresecretdataaccess.Token{})
			secondKey, err := xchacha20poly1305.NewKey(secondKeyBytes, tc.second.id, secondParams)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewKey(secondKeyBytes, %v, %v) err = %v, want nil", tc.second.id, secondParams, err)
			}
			if firstKey.Equals(secondKey) {
				t.Errorf("firstKey.Equals(secondKey) = true, want false")
			}
		})
	}
}

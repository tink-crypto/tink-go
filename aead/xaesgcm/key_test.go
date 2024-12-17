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

package xaesgcm_test

import (
	"bytes"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/xaesgcm"
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

func TestNewParametersInvalidValues(t *testing.T) {
	// Unknown variant.
	if _, err := xaesgcm.NewParameters(xaesgcm.VariantUnknown, 10); err == nil {
		t.Errorf("xaesgcm.NewParameters(xaesgcm.VariantUnknown, 10) err = nil, want error")
	}
	// Salt size too small.
	if _, err := xaesgcm.NewParameters(xaesgcm.VariantTink, 7); err == nil {
		t.Errorf("xaesgcm.NewParameters(xaesgcm.VariantTink, 7) err = nil, want error")
	}
	// Salt size too large.
	if _, err := xaesgcm.NewParameters(xaesgcm.VariantTink, 13); err == nil {
		t.Errorf("xaesgcm.NewParameters(xaesgcm.VariantTink, 13) err = nil, want error")
	}
}

func TestOutputPrefix(t *testing.T) {
	for _, test := range []struct {
		name    string
		variant xaesgcm.Variant
		id      uint32
		want    []byte
	}{
		{
			name:    "Tink",
			variant: xaesgcm.VariantTink,
			id:      0x01020304,
			want:    []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "No prefix",
			variant: xaesgcm.VariantNoPrefix,
			id:      0,
			want:    nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := xaesgcm.NewParameters(test.variant, 12)
			if err != nil {
				t.Fatalf("xaesgcm.NewParameters(%v, 12) err = %v, want nil", test.variant, err)
			}
			keyBytes, err := secretdata.NewBytesFromRand(32)
			if err != nil {
				t.Fatalf("secretdata.NewBytes(32fNewBytesFromRand() err = %v, want nil", err)
			}
			key, err := xaesgcm.NewKey(keyBytes, test.id, params)
			if err != nil {
				t.Fatalf("xaesgcm.NewKey(keyBytes, %v, %v) err = %v, want nil", test.id, params, err)
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
		variant xaesgcm.Variant
	}{
		{
			name:    "Tink",
			variant: xaesgcm.VariantTink,
		},
		{
			name:    "No Prefix",
			variant: xaesgcm.VariantNoPrefix,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := xaesgcm.NewParameters(test.variant, 12)
			if err != nil {
				t.Fatalf("xaesgcm.NewParameters(%v, 12) err = %v, want nil", test.variant, err)
			}
			if params.HasIDRequirement() != (test.variant != xaesgcm.VariantNoPrefix) {
				t.Errorf("params.HasIDRequirement() = %v, want %v", params.HasIDRequirement(), (test.variant != xaesgcm.VariantNoPrefix))
			}
			if params.Variant() != test.variant {
				t.Errorf("params.Variant() = %v, want %v", params.Variant(), test.variant)
			}
			if params.SaltSizeInBytes() != 12 {
				t.Errorf("params.SaltSizeInBytes() = %v, want 12", params.SaltSizeInBytes())
			}
			// Test equality.
			otherParams, err := xaesgcm.NewParameters(test.variant, 12)
			if err != nil {
				t.Fatalf("xaesgcm.NewParameters(%v, 12) err = %v, want nil", test.variant, err)
			}
			if !params.Equal(otherParams) {
				t.Errorf("params.Equal(otherParams) = %v, want true", params.Equal(otherParams))
			}
		})
	}
}

func TestParametersEqualFalseIfDifferentVariant(t *testing.T) {
	for _, test := range []struct {
		name         string
		key1Variant  xaesgcm.Variant
		key1SaltSize int
		key2Variant  xaesgcm.Variant
		key2SaltSize int
	}{
		{
			name:         "Tink vs No Prefix",
			key1Variant:  xaesgcm.VariantTink,
			key1SaltSize: 12,
			key2Variant:  xaesgcm.VariantNoPrefix,
			key2SaltSize: 12,
		},
		{
			name:         "different salt size",
			key1Variant:  xaesgcm.VariantTink,
			key1SaltSize: 12,
			key2Variant:  xaesgcm.VariantTink,
			key2SaltSize: 10,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params1, err := xaesgcm.NewParameters(test.key1Variant, test.key1SaltSize)
			if err != nil {
				t.Fatalf("xaesgcm.NewParameters(%v, %v) err = %v, want nil", test.key1Variant, test.key1SaltSize, err)
			}
			params2, err := xaesgcm.NewParameters(test.key2Variant, test.key2SaltSize)
			if err != nil {
				t.Fatalf("xaesgcm.NewParameters(%v, %v) err = %v, want nil", test.key2Variant, test.key2SaltSize, err)
			}
			if params1.Equal(params2) {
				t.Errorf("params.Equal(params2) = %v, want false", params1.Equal(params2))
			}
		})
	}
}

type TestKey struct {
	name    string
	id      uint32
	key     []byte
	variant xaesgcm.Variant
}

func TestNewKeyWorks(t *testing.T) {
	for _, tc := range []TestKey{
		{
			name:    "Tink variant",
			id:      0x01,
			key:     rawKey,
			variant: xaesgcm.VariantTink,
		},
		{
			name:    "NoPrefix variant",
			id:      0,
			key:     rawKey,
			variant: xaesgcm.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := xaesgcm.NewParameters(tc.variant, 12)
			if err != nil {
				t.Fatalf("xaesgcm.NewParameters(%v, 12) err = %v, want nil", tc.variant, err)
			}
			keyBytes := secretdata.NewBytesFromData(tc.key, insecuresecretdataaccess.Token{})
			firstKey, err := xaesgcm.NewKey(keyBytes, tc.id, params)
			if err != nil {
				t.Fatalf("xaesgcm.NewKey(keyBytes, %v, %v) err = %v, want nil", tc.id, params, err)
			}
			if !firstKey.Parameters().Equal(params) {
				t.Errorf("firstKey.Parameters() = %v, want %v", firstKey.Parameters(), params)
			}
			firstKeyBytes := firstKey.KeyBytes()
			if !keyBytes.Equal(firstKeyBytes) {
				t.Errorf("keyBytes.Equal(firstKeyBytes) = false, want true")
			}
			id, required := firstKey.IDRequirement()
			if required != (tc.variant != xaesgcm.VariantNoPrefix) {
				t.Errorf("firstKey.ID() = %v, want %v", required, (tc.variant == xaesgcm.VariantNoPrefix))
			}
			if id != tc.id {
				t.Errorf("id = %v, want %v", id, tc.id)
			}
			// Test Equal.
			secondKey, err := xaesgcm.NewKey(keyBytes, tc.id, params)
			if err != nil {
				t.Fatalf("xaesgcm.NewKey(keyBytes, %v, %v) err = %v, want nil", tc.id, params, err)
			}
			if !firstKey.Equal(secondKey) {
				t.Errorf("firstKey.Equal(secondKey) = %v, want true", firstKey.Equal(secondKey))
			}
		})
	}
}

func TestNewKeyFailsIfNoPrefixAndIDIsNotZero(t *testing.T) {
	params, err := xaesgcm.NewParameters(xaesgcm.VariantNoPrefix, 12)
	if err != nil {
		t.Fatalf("xaesgcm.NewParameters(%v, 12) err = %v, want nil", xaesgcm.VariantNoPrefix, err)
	}
	keyBytes := secretdata.NewBytesFromData(rawKey, insecuresecretdataaccess.Token{})
	if _, err := xaesgcm.NewKey(keyBytes, 123, params); err == nil {
		t.Errorf("xaesgcm.NewKey(keyBytes, 123, %v) err = nil, want error", params)
	}
}

func TestKeyEqualReturnsFalseIfDifferent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		first  TestKey
		second TestKey
	}{
		{
			name: "different prefix variant and key ID",
			first: TestKey{
				variant: xaesgcm.VariantTink,
				key:     rawKey,
				id:      0x01,
			},
			second: TestKey{
				variant: xaesgcm.VariantNoPrefix,
				key:     rawKey,
				id:      0x00,
			},
		},
		{
			name: "different key IDs",
			first: TestKey{
				variant: xaesgcm.VariantTink,
				key:     rawKey,
				id:      0x01,
			},
			second: TestKey{
				variant: xaesgcm.VariantTink,
				key:     rawKey,
				id:      0x02,
			},
		},
		{
			name: "different key bytes",
			first: TestKey{
				variant: xaesgcm.VariantTink,
				key:     rawKey,
				id:      0x01,
			},
			second: TestKey{
				variant: xaesgcm.VariantTink,
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
			firstParams, err := xaesgcm.NewParameters(tc.first.variant, 12)
			if err != nil {
				t.Fatalf("xaesgcm.NewParameters(%v, 12) err = %v, want nil", tc.first.variant, err)
			}
			firstKeyBytes := secretdata.NewBytesFromData(tc.first.key, insecuresecretdataaccess.Token{})
			firstKey, err := xaesgcm.NewKey(firstKeyBytes, tc.first.id, firstParams)
			if err != nil {
				t.Fatalf("xaesgcm.NewKey(firstKeyBytes, %v, %v) err = %v, want nil", tc.first.id, firstParams, err)
			}
			secondParams, err := xaesgcm.NewParameters(tc.second.variant, 12)
			if err != nil {
				t.Fatalf("xaesgcm.NewParameters(%v, 12) err = %v, want nil", tc.second.variant, err)
			}
			secondKeyBytes := secretdata.NewBytesFromData(tc.second.key, insecuresecretdataaccess.Token{})
			secondKey, err := xaesgcm.NewKey(secondKeyBytes, tc.second.id, secondParams)
			if err != nil {
				t.Fatalf("xaesgcm.NewKey(secondKeyBytes, %v, %v) err = %v, want nil", tc.second.id, secondParams, err)
			}
			if firstKey.Equal(secondKey) {
				t.Errorf("firstKey.Equal(secondKey) = true, want false")
			}
		})
	}
}

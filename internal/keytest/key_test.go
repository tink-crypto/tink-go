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

package keytest_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/internal/keytest"
	"github.com/tink-crypto/tink-go/v2/key"
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

func TestNewParametersInvalidVariant(t *testing.T) {
	if _, err := keytest.NewParameters(keytest.VariantUnknown); err == nil {
		t.Errorf("keytest.NewParameters(keytest.VariantUnknown) err = nil, want error")
	}
}

func TestNewKeyFailsIfParametersIsNil(t *testing.T) {
	keyBytes, err := secretdata.NewBytesFromRand(16)
	if err != nil {
		t.Fatalf("secretdata.NewBytesFromRand(16) err = %v, want nil", err)
	}
	if _, err := keytest.NewKey(keyBytes, 123, nil); err == nil {
		t.Errorf("keytest.NewKey(keyBytes, 123, nil) err = nil, want error")
	}
}

func TestNewKeyFailsIfKeySizeIsWrong(t *testing.T) {
	params, err := keytest.NewParameters(keytest.VariantTink)
	if err != nil {
		t.Fatalf("keytest.NewParameters(%v) err = %v, want nil", keytest.VariantTink, err)
	}
	for _, tc := range []struct {
		name     string
		keyBytes secretdata.Bytes
	}{
		{
			name:     "empty key",
			keyBytes: secretdata.NewBytesFromData([]byte{}, insecuresecretdataaccess.Token{}),
		},
		{
			name:     "15-byte key",
			keyBytes: secretdata.NewBytesFromData(key128Bits[:15], insecuresecretdataaccess.Token{}),
		},
		{
			name:     "32-byte key",
			keyBytes: secretdata.NewBytesFromData(key256Bits, insecuresecretdataaccess.Token{}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := keytest.NewKey(tc.keyBytes, 123, params); err == nil {
				t.Errorf("keytest.NewKey(keyBytes, 123, %v) err = nil, want error", params)
			}
		})
	}
}

// TestNewKeyFailsIfInvalidParams tests that NewKey fails if the parameters are
// invalid.
//
// The only way to create invalid parameters is to create a struct literal with
// default values.
func TestNewKeyFailsIfInvalidParams(t *testing.T) {
	keyBytes, err := secretdata.NewBytesFromRand(16)
	if err != nil {
		t.Fatalf("secretdata.NewBytesFromRand(16) err = %v, want nil", err)
	}
	params := &keytest.Parameters{}
	for _, id := range []uint32{0, 123} {
		if _, err := keytest.NewKey(keyBytes, id, params); err == nil {
			t.Errorf("keytest.NewKey(keyBytes, %v, &keytest.Parameters{}) err = nil, want error", id)
		}
	}
}

func TestNewKeyFailsIfNoPrefixAndIDIsNotZero(t *testing.T) {
	params, err := keytest.NewParameters(keytest.VariantNoPrefix)
	if err != nil {
		t.Fatalf("keytest.NewParameters(%v) err = %v, want nil", keytest.VariantNoPrefix, err)
	}
	keyBytes := secretdata.NewBytesFromData(key128Bits, insecuresecretdataaccess.Token{})
	if _, err := keytest.NewKey(keyBytes, 123, params); err == nil {
		t.Errorf("keytest.NewKey(keyBytes, 123, %v) err = nil, want error", params)
	}
}

func TestNewKeyFailsIfIDRequirementIsZero(t *testing.T) {
	for _, variant := range []keytest.Variant{keytest.VariantTink, keytest.VariantCrunchy} {
		t.Run(variant.String(), func(t *testing.T) {
			params, err := keytest.NewParameters(variant)
			if err != nil {
				t.Fatalf("keytest.NewParameters(%v) err = %v, want nil", variant, err)
			}
			keyBytes := secretdata.NewBytesFromData(key128Bits, insecuresecretdataaccess.Token{})
			if _, err := keytest.NewKey(keyBytes, 0, params); err == nil {
				t.Errorf("keytest.NewKey(keyBytes, 0, %v) err = nil, want error", params)
			}
		})
	}
}

func TestOutputPrefix(t *testing.T) {
	for _, test := range []struct {
		name    string
		variant keytest.Variant
		id      uint32
		want    []byte
	}{
		{
			name:    "Tink",
			variant: keytest.VariantTink,
			id:      uint32(0x01020304),
			want:    []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "Crunchy",
			variant: keytest.VariantCrunchy,
			id:      uint32(0x01020304),
			want:    []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "No prefix",
			variant: keytest.VariantNoPrefix,
			id:      0,
			want:    nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := keytest.NewParameters(test.variant)
			if err != nil {
				t.Fatalf("keytest.NewParameters(%v) err = %v, want nil", test.variant, err)
			}
			keyBytes, err := secretdata.NewBytesFromRand(16)
			if err != nil {
				t.Fatalf("secretdata.NewBytesFromRand(16) err = %v, want nil", err)
			}
			key, err := keytest.NewKey(keyBytes, test.id, params)
			if err != nil {
				t.Fatalf("keytest.NewKey(keyBytes, %v, %v) err = %v, want nil", test.id, params, err)
			}
			if got := key.OutputPrefix(); !bytes.Equal(got, test.want) {
				t.Errorf("key.OutputPrefix() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestNewParametersWorks(t *testing.T) {
	for _, variant := range []keytest.Variant{
		keytest.VariantTink,
		keytest.VariantCrunchy,
		keytest.VariantNoPrefix,
	} {
		t.Run(variant.String(), func(t *testing.T) {
			params, err := keytest.NewParameters(variant)
			if err != nil {
				t.Fatalf("keytest.NewParameters(%v) err = %v, want nil", variant, err)
			}
			if got, want := params.HasIDRequirement(), variant != keytest.VariantNoPrefix; got != want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, want)
			}
			if got := params.Variant(); got != variant {
				t.Errorf("params.Variant() = %v, want %v", got, variant)
			}
			otherParams, err := keytest.NewParameters(variant)
			if err != nil {
				t.Fatalf("keytest.NewParameters(%v) err = %v, want nil", variant, err)
			}
			if !params.Equal(otherParams) {
				t.Errorf("params.Equal(otherParams) = false, want true")
			}
		})
	}
}

func TestParametersEqualFalseIfDifferent(t *testing.T) {
	for _, test := range []struct {
		name     string
		variant1 keytest.Variant
		variant2 keytest.Variant
	}{
		{
			name:     "Crunchy vs Tink",
			variant1: keytest.VariantCrunchy,
			variant2: keytest.VariantTink,
		},
		{
			name:     "Tink vs NoPrefix",
			variant1: keytest.VariantTink,
			variant2: keytest.VariantNoPrefix,
		},
		{
			name:     "Crunchy vs NoPrefix",
			variant1: keytest.VariantCrunchy,
			variant2: keytest.VariantNoPrefix,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params1, err := keytest.NewParameters(test.variant1)
			if err != nil {
				t.Fatalf("keytest.NewParameters(%v) err = %v, want nil", test.variant1, err)
			}
			params2, err := keytest.NewParameters(test.variant2)
			if err != nil {
				t.Fatalf("keytest.NewParameters(%v) err = %v, want nil", test.variant2, err)
			}
			if params1.Equal(params2) {
				t.Errorf("params1.Equal(params2) = true, want false")
			}
		})
	}
}

type testKey struct {
	name    string
	id      uint32
	key     []byte
	variant keytest.Variant
}

func TestNewKeyWorks(t *testing.T) {
	for _, test := range []testKey{
		{
			name:    "Tink prefix",
			id:      1,
			key:     key128Bits,
			variant: keytest.VariantTink,
		},
		{
			name:    "Crunchy prefix",
			id:      1,
			key:     key128Bits,
			variant: keytest.VariantCrunchy,
		},
		{
			name:    "NoPrefix prefix",
			id:      0,
			key:     key128Bits,
			variant: keytest.VariantNoPrefix,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := keytest.NewParameters(test.variant)
			if err != nil {
				t.Fatalf("keytest.NewParameters(%v) err = %v, want nil", test.variant, err)
			}
			keyBytes := secretdata.NewBytesFromData(test.key, insecuresecretdataaccess.Token{})

			// Create two keys with the same parameters and key bytes.
			key1, err := keytest.NewKey(keyBytes, test.id, params)
			if err != nil {
				t.Fatalf("keytest.NewKey(keyBytes, %v, %v) err = %v, want nil", test.id, params, err)
			}
			if !key1.Parameters().Equal(params) {
				t.Errorf("key1.Parameters() = %v, want %v", key1.Parameters(), params)
			}
			if !keyBytes.Equal(key1.KeyBytes()) {
				t.Errorf("keyBytes.Equal(key1.KeyBytes()) = false, want true")
			}
			keyID1, required := key1.IDRequirement()
			if wantRequired := test.variant != keytest.VariantNoPrefix; required != wantRequired {
				t.Errorf("required = %v, want %v", required, wantRequired)
			}
			if keyID1 != test.id {
				t.Errorf("keyID1 = %v, want %v", keyID1, test.id)
			}
			key2, err := keytest.NewKey(keyBytes, keyID1, params)
			if err != nil {
				t.Fatalf("keytest.NewKey(keyBytes, %v, %v) err = %v, want nil", keyID1, params, err)
			}
			if !key1.Equal(key2) {
				t.Errorf("key1.Equal(key2) = false, want true")
			}
		})
	}
}

type stubKey struct{}

var _ key.Key = (*stubKey)(nil)

func (k *stubKey) Parameters() key.Parameters    { return nil }
func (k *stubKey) Equal(other key.Key) bool      { return true }
func (k *stubKey) IDRequirement() (uint32, bool) { return 123, true }

func TestKeyEqual_FalseIfDifferentType(t *testing.T) {
	params, err := keytest.NewParameters(keytest.VariantTink)
	if err != nil {
		t.Fatalf("keytest.NewParameters() err = %v, want nil", err)
	}
	keyBytes := secretdata.NewBytesFromData(key128Bits, insecuresecretdataaccess.Token{})
	key, err := keytest.NewKey(keyBytes, 1234, params)
	if err != nil {
		t.Fatalf("keytest.NewKey() err = %v, want nil", err)
	}
	if key.Equal(&stubKey{}) {
		t.Errorf("key.Equal(&stubKey{}) = true, want false")
	}
}

func TestKeyEqualReturnsFalseIfDifferent(t *testing.T) {
	for _, test := range []struct {
		name   string
		first  testKey
		second testKey
	}{
		{
			name: "different prefix variant",
			first: testKey{
				variant: keytest.VariantTink,
				key:     key128Bits,
				id:      0x01,
			},
			second: testKey{
				variant: keytest.VariantCrunchy,
				key:     key128Bits,
				id:      0x01,
			},
		},
		{
			name: "different key IDs",
			first: testKey{
				variant: keytest.VariantTink,
				key:     key128Bits,
				id:      0x01,
			},
			second: testKey{
				variant: keytest.VariantTink,
				key:     key128Bits,
				id:      0x02,
			},
		},
		{
			name: "different key bytes",
			first: testKey{
				variant: keytest.VariantCrunchy,
				key:     key128Bits,
				id:      0x01,
			},
			second: testKey{
				variant: keytest.VariantCrunchy,
				key: []byte{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09,
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				},
				id: 0x01,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			firstParams, err := keytest.NewParameters(test.first.variant)
			if err != nil {
				t.Fatalf("keytest.NewParameters(%v) err = %v, want nil", test.first.variant, err)
			}
			firstKeyBytes := secretdata.NewBytesFromData(test.first.key, insecuresecretdataaccess.Token{})
			firstKey, err := keytest.NewKey(firstKeyBytes, test.first.id, firstParams)
			if err != nil {
				t.Fatalf("keytest.NewKey(firstKeyBytes, %v, %v) err = %v, want nil", test.first.id, firstParams, err)
			}

			secondParams, err := keytest.NewParameters(test.second.variant)
			if err != nil {
				t.Fatalf("keytest.NewParameters(%v) err = %v, want nil", test.second.variant, err)
			}
			secondKeyBytes := secretdata.NewBytesFromData(test.second.key, insecuresecretdataaccess.Token{})
			secondKey, err := keytest.NewKey(secondKeyBytes, test.second.id, secondParams)
			if err != nil {
				t.Fatalf("keytest.NewKey(secondKeyBytes, %v, %v) err = %v, want nil", test.second.id, secondParams, err)
			}
			if firstKey.Equal(secondKey) {
				t.Errorf("firstKey.Equal(secondKey) = true, want false")
			}
		})
	}
}

func TestKeyCreator(t *testing.T) {
	params, err := keytest.NewParameters(keytest.VariantTink)
	if err != nil {
		t.Fatalf("keytest.NewParameters() err = %v, want nil", err)
	}

	key, err := keygenregistry.CreateKey(params, 123)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey(%v, 123) err = %v, want nil", params, err)
	}
	testOnlyKey, ok := key.(*keytest.Key)
	if !ok {
		t.Fatalf("keygenregistry.CreateKey(%v, 123) returned key of type %T, want %T", params, key, (*keytest.Key)(nil))
	}

	idRequirement, hasIDRequirement := testOnlyKey.IDRequirement()
	if !hasIDRequirement || idRequirement != 123 {
		t.Errorf("testOnlyKey.IDRequirement() = (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 123, true)
	}
	if got, want := testOnlyKey.KeyBytes().Len(), 16; got != want {
		t.Errorf("testOnlyKey.KeyBytes().Len() = %d, want %d", got, want)
	}
	if diff := cmp.Diff(params, testOnlyKey.Parameters()); diff != "" {
		t.Errorf("testOnlyKey.Parameters() diff (-want +got):\n%s", diff)
	}
}

func TestKeyCreator_FailsIfInvalidParameters(t *testing.T) {
	noPrefixParams, err := keytest.NewParameters(keytest.VariantNoPrefix)
	if err != nil {
		t.Fatalf("keytest.NewParameters(%v) err = %v, want nil", keytest.VariantNoPrefix, err)
	}
	for _, tc := range []struct {
		name          string
		params        *keytest.Parameters
		idRequirement uint32
	}{
		{
			name:          "NoPrefix with non-zero ID requirement",
			params:        noPrefixParams,
			idRequirement: 123,
		},
		{
			name:          "unknown variant",
			params:        &keytest.Parameters{},
			idRequirement: 123,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := keygenregistry.CreateKey(tc.params, tc.idRequirement); err == nil {
				t.Errorf("keygenregistry.CreateKey(%v, %v) err = nil, want error", tc.params, tc.idRequirement)
			}
		})
	}
}

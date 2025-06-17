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

package chacha20poly1305_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/aead/chacha20poly1305"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/key"
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
	if _, err := chacha20poly1305.NewParameters(chacha20poly1305.VariantUnknown); err == nil {
		t.Errorf("chacha20poly1305.NewParameters(chacha20poly1305.VariantUnknown) err = nil, want error")
	}
}

func TestOutputPrefix(t *testing.T) {
	for _, test := range []struct {
		name    string
		variant chacha20poly1305.Variant
		id      uint32
		want    []byte
	}{
		{
			name:    "Tink",
			variant: chacha20poly1305.VariantTink,
			id:      0x01020304,
			want:    []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "Crunchy",
			variant: chacha20poly1305.VariantCrunchy,
			id:      0x01020304,
			want:    []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "No prefix",
			variant: chacha20poly1305.VariantNoPrefix,
			id:      0,
			want:    nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := chacha20poly1305.NewParameters(test.variant)
			if err != nil {
				t.Fatalf("chacha20poly1305.NewParameters(%v) err = %v, want nil", test.variant, err)
			}
			keyBytes, err := secretdata.NewBytesFromRand(32)
			if err != nil {
				t.Fatalf("secretdata.NewBytes(32fNewBytesFromRand() err = %v, want nil", err)
			}
			key, err := chacha20poly1305.NewKey(keyBytes, test.id, params)
			if err != nil {
				t.Fatalf("chacha20poly1305.NewKey(keyBytes, %v, %v) err = %v, want nil", test.id, params, err)
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
		variant chacha20poly1305.Variant
	}{
		{
			name:    "TINK",
			variant: chacha20poly1305.VariantTink,
		},
		{
			name:    "CRUNCHY",
			variant: chacha20poly1305.VariantCrunchy,
		},
		{
			name:    "RAW",
			variant: chacha20poly1305.VariantNoPrefix,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := chacha20poly1305.NewParameters(test.variant)
			if err != nil {
				t.Fatalf("chacha20poly1305.NewParameters(%v) err = %v, want nil", test.variant, err)
			}
			if params.HasIDRequirement() != (test.variant != chacha20poly1305.VariantNoPrefix) {
				t.Errorf("params.HasIDRequirement() = %v, want %v", params.HasIDRequirement(), (test.variant != chacha20poly1305.VariantNoPrefix))
			}
			if params.Variant() != test.variant {
				t.Errorf("params.Variant() = %v, want %v", params.Variant(), test.variant)
			}
			// Test equality.
			otherParams, err := chacha20poly1305.NewParameters(test.variant)
			if err != nil {
				t.Fatalf("chacha20poly1305.NewParameters(%v) err = %v, want nil", test.variant, err)
			}
			if !params.Equal(otherParams) {
				t.Errorf("params.Equal(otherParams) = %v, want true", params.Equal(otherParams))
			}
		})
	}
}

func TestParametersEqualFalseIfDifferentVariant(t *testing.T) {
	for _, test := range []struct {
		name        string
		key1Variant chacha20poly1305.Variant
		key2Variant chacha20poly1305.Variant
	}{
		{
			name:        "CRUNCHY vs TINK",
			key1Variant: chacha20poly1305.VariantCrunchy,
			key2Variant: chacha20poly1305.VariantTink,
		},
		{
			name:        "CRUNCHY vs RAW",
			key1Variant: chacha20poly1305.VariantCrunchy,
			key2Variant: chacha20poly1305.VariantNoPrefix,
		},
		{
			name:        "TINK vs RAW",
			key1Variant: chacha20poly1305.VariantTink,
			key2Variant: chacha20poly1305.VariantNoPrefix,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params1, err := chacha20poly1305.NewParameters(test.key1Variant)
			if err != nil {
				t.Fatalf("chacha20poly1305.NewParameters(%v) err = %v, want nil", test.key1Variant, err)
			}
			params2, err := chacha20poly1305.NewParameters(test.key2Variant)
			if err != nil {
				t.Fatalf("chacha20poly1305.NewParameters(%v) err = %v, want nil", test.key2Variant, err)
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
	variant chacha20poly1305.Variant
}

func TestNewKeyWorks(t *testing.T) {
	for _, tc := range []TestKey{
		{
			name:    "Tink variant",
			id:      0x01,
			key:     rawKey,
			variant: chacha20poly1305.VariantTink,
		},
		{
			name:    "Crunchy variant",
			id:      0x01,
			key:     rawKey,
			variant: chacha20poly1305.VariantCrunchy,
		},
		{
			name:    "NoPrefix variant",
			id:      0,
			key:     rawKey,
			variant: chacha20poly1305.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := chacha20poly1305.NewParameters(tc.variant)
			if err != nil {
				t.Fatalf("chacha20poly1305.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			keyBytes := secretdata.NewBytesFromData(tc.key, insecuresecretdataaccess.Token{})
			firstKey, err := chacha20poly1305.NewKey(keyBytes, tc.id, params)
			if err != nil {
				t.Fatalf("chacha20poly1305.NewKey(keyBytes, %v, %v) err = %v, want nil", tc.id, params, err)
			}
			if !firstKey.Parameters().Equal(params) {
				t.Errorf("firstKey.Parameters() = %v, want %v", firstKey.Parameters(), params)
			}
			firstKeyBytes := firstKey.KeyBytes()
			if !keyBytes.Equal(firstKeyBytes) {
				t.Errorf("keyBytes.Equal(firstKeyBytes) = false, want true")
			}
			id, required := firstKey.IDRequirement()
			if required != (tc.variant != chacha20poly1305.VariantNoPrefix) {
				t.Errorf("firstKey.ID() = %v, want %v", required, (tc.variant == chacha20poly1305.VariantNoPrefix))
			}
			if id != tc.id {
				t.Errorf("id = %v, want %v", id, tc.id)
			}
			// Test Equal.
			secondKey, err := chacha20poly1305.NewKey(keyBytes, tc.id, params)
			if err != nil {
				t.Fatalf("chacha20poly1305.NewKey(keyBytes, %v, %v) err = %v, want nil", tc.id, params, err)
			}
			if !firstKey.Equal(secondKey) {
				t.Errorf("firstKey.Equal(secondKey) = %v, want true", firstKey.Equal(secondKey))
			}
		})
	}
}

func TestNewKeyFailsIfNoPrefixAndIDIsNotZero(t *testing.T) {
	params, err := chacha20poly1305.NewParameters(chacha20poly1305.VariantNoPrefix)
	if err != nil {
		t.Fatalf("chacha20poly1305.NewParameters(%v) err = %v, want nil", chacha20poly1305.VariantNoPrefix, err)
	}
	keyBytes := secretdata.NewBytesFromData(rawKey, insecuresecretdataaccess.Token{})
	if _, err := chacha20poly1305.NewKey(keyBytes, 123, params); err == nil {
		t.Errorf("chacha20poly1305.NewKey(keyBytes, 123, %v) err = nil, want error", params)
	}
}

type stubKey struct{}

var _ key.Key = (*stubKey)(nil)

func (k *stubKey) Parameters() key.Parameters    { return nil }
func (k *stubKey) Equal(other key.Key) bool      { return true }
func (k *stubKey) IDRequirement() (uint32, bool) { return 123, true }

func TestKeyEqual_FalseIfDifferentType(t *testing.T) {
	params, err := chacha20poly1305.NewParameters(chacha20poly1305.VariantTink)
	if err != nil {
		t.Fatalf("chacha20poly1305.NewParameters(%v) err = %v, want nil", chacha20poly1305.VariantTink, err)
	}
	keyBytes := secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{})
	key, err := chacha20poly1305.NewKey(keyBytes, 1234, params)
	if err != nil {
		t.Fatalf("chacha20poly1305.NewKey(keyBytes, %v, %v) err = %v, want nil", 1234, params, err)
	}
	if key.Equal(&stubKey{}) {
		t.Errorf("key.Equal(&stubKey{}) = true, want false")
	}
}

func TestKeyEqualReturnsFalseIfDifferent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		first  TestKey
		second TestKey
	}{
		{
			name: "different prefix variant",
			first: TestKey{
				variant: chacha20poly1305.VariantTink,
				key:     rawKey,
				id:      0x01,
			},
			second: TestKey{
				variant: chacha20poly1305.VariantCrunchy,
				key:     rawKey,
				id:      0x01,
			},
		},
		{
			name: "different key IDs",
			first: TestKey{
				variant: chacha20poly1305.VariantTink,
				key:     rawKey,
				id:      0x01,
			},
			second: TestKey{
				variant: chacha20poly1305.VariantTink,
				key:     rawKey,
				id:      0x02,
			},
		},
		{
			name: "different key bytes",
			first: TestKey{
				variant: chacha20poly1305.VariantCrunchy,
				key:     rawKey,
				id:      0x01,
			},
			second: TestKey{
				variant: chacha20poly1305.VariantCrunchy,
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
			firstParams, err := chacha20poly1305.NewParameters(tc.first.variant)
			if err != nil {
				t.Fatalf("chacha20poly1305.NewParameters(%v) err = %v, want nil", tc.first.variant, err)
			}
			firstKeyBytes := secretdata.NewBytesFromData(tc.first.key, insecuresecretdataaccess.Token{})
			firstKey, err := chacha20poly1305.NewKey(firstKeyBytes, tc.first.id, firstParams)
			if err != nil {
				t.Fatalf("chacha20poly1305.NewKey(firstKeyBytes, %v, %v) err = %v, want nil", tc.first.id, firstParams, err)
			}
			secondParams, err := chacha20poly1305.NewParameters(tc.second.variant)
			if err != nil {
				t.Fatalf("chacha20poly1305.NewParameters(%v) err = %v, want nil", tc.second.variant, err)
			}
			secondKeyBytes := secretdata.NewBytesFromData(tc.second.key, insecuresecretdataaccess.Token{})
			secondKey, err := chacha20poly1305.NewKey(secondKeyBytes, tc.second.id, secondParams)
			if err != nil {
				t.Fatalf("chacha20poly1305.NewKey(secondKeyBytes, %v, %v) err = %v, want nil", tc.second.id, secondParams, err)
			}
			if firstKey.Equal(secondKey) {
				t.Errorf("firstKey.Equal(secondKey) = true, want false")
			}
		})
	}
}

func TestKeyCreator(t *testing.T) {
	keyCreator := chacha20poly1305.KeyCreator(internalapi.Token{})
	params, err := chacha20poly1305.NewParameters(chacha20poly1305.VariantTink)
	if err != nil {
		t.Fatalf("chacha20poly1305.NewParameters() err = %v, want nil", err)
	}

	key, err := keyCreator(params, 123)
	if err != nil {
		t.Fatalf("keyCreator(%v, 123) err = %v, want nil", params, err)
	}
	chaCha20Poly1305Key, ok := key.(*chacha20poly1305.Key)
	if !ok {
		t.Fatalf("keyCreator(%v, 123) returned key of type %T, want %T", params, key, (*chacha20poly1305.Key)(nil))
	}

	idRequirement, hasIDRequirement := chaCha20Poly1305Key.IDRequirement()
	if !hasIDRequirement || idRequirement != 123 {
		t.Errorf("chaCha20Poly1305Key.IDRequirement() (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 123, true)
	}
	if diff := cmp.Diff(chaCha20Poly1305Key.Parameters(), params); diff != "" {
		t.Errorf("chaCha20Poly1305Key.Parameters() diff (-want +got):\n%s", diff)
	}
}

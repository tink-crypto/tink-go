// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ed25519_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/signature/ed25519"
)

func TestNewParameters(t *testing.T) {
	for _, tc := range []struct {
		name    string
		variant ed25519.Variant
	}{
		{
			name:    "tink",
			variant: ed25519.VariantTink,
		},
		{
			name:    "legacy",
			variant: ed25519.VariantLegacy,
		},
		{
			name:    "crunchy",
			variant: ed25519.VariantCrunchy,
		},
		{
			name:    "no prefix",
			variant: ed25519.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := ed25519.NewParameters(tc.variant)
			if err != nil {
				t.Errorf("ed25519.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			if got := params.Variant(); got != tc.variant {
				t.Errorf("params.Variant() = %v, want %v", got, tc.variant)
			}
		})
	}
	t.Run("unknown", func(t *testing.T) {
		if _, err := ed25519.NewParameters(ed25519.VariantUnknown); err == nil {
			t.Errorf("ed25519.NewParameters(%v) err = nil, want error", ed25519.VariantUnknown)
		}
	})
}

func TestParametersHasIDRequirement(t *testing.T) {
	for _, tc := range []struct {
		name    string
		variant ed25519.Variant
		want    bool
	}{
		{
			name:    "tink",
			variant: ed25519.VariantTink,
			want:    true,
		},
		{
			name:    "legacy",
			variant: ed25519.VariantLegacy,
			want:    true,
		},
		{
			name:    "crunchy",
			variant: ed25519.VariantCrunchy,
			want:    true,
		},
		{
			name:    "no prefix",
			variant: ed25519.VariantNoPrefix,
			want:    false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := ed25519.NewParameters(tc.variant)
			if err != nil {
				t.Fatalf("ed25519.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			if got := params.HasIDRequirement(); got != tc.want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParametersEquals(t *testing.T) {
	tinkVariant, err := ed25519.NewParameters(ed25519.VariantTink)
	if err != nil {
		t.Fatalf("ed25519.NewParameters(%v) err = %v, want nil", ed25519.VariantTink, err)
	}
	legacyVariant, err := ed25519.NewParameters(ed25519.VariantLegacy)
	if err != nil {
		t.Fatalf("ed25519.NewParameters(%v) err = %v, want	 nil", ed25519.VariantLegacy, err)
	}
	crunchyVariant, err := ed25519.NewParameters(ed25519.VariantCrunchy)
	if err != nil {
		t.Fatalf("ed25519.NewParameters(%v) err = %v, want nil", ed25519.VariantCrunchy, err)
	}
	noPrefixVariant, err := ed25519.NewParameters(ed25519.VariantNoPrefix)
	if err != nil {
		t.Fatalf("ed25519.NewParameters(%v) err = %v, want	 nil", ed25519.VariantNoPrefix, err)
	}

	for _, params := range []ed25519.Parameters{tinkVariant, legacyVariant, crunchyVariant, noPrefixVariant} {
		if !params.Equals(&params) {
			t.Errorf("params.Equals(params) = false, want true")
		}
	}

	for _, tc := range []struct {
		name         string
		firstParams  ed25519.Parameters
		secondParams ed25519.Parameters
		want         bool
	}{
		{
			name:         "tink vs legacy",
			firstParams:  tinkVariant,
			secondParams: legacyVariant,
		},
		{
			name:         "tink vs crunchy",
			firstParams:  tinkVariant,
			secondParams: crunchyVariant,
		},
		{
			name:         "tink vs no prefix",
			firstParams:  tinkVariant,
			secondParams: noPrefixVariant,
		},
		{
			name:         "legacy vs crunchy",
			firstParams:  legacyVariant,
			secondParams: crunchyVariant,
		},
		{
			name:         "legacy vs no prefix",
			firstParams:  legacyVariant,
			secondParams: noPrefixVariant,
		},
		{
			name:         "crunchy vs no prefix",
			firstParams:  crunchyVariant,
			secondParams: noPrefixVariant,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.firstParams.Equals(&tc.secondParams) {
				t.Errorf("tc.firstParams.Equals(&tc.secondParams) = true, want false")
			}
		})
	}
}

func TestNewPublicKeyFails(t *testing.T) {
	tinkParams, err := ed25519.NewParameters(ed25519.VariantTink)
	if err != nil {
		t.Fatalf("ed25519.NewParameters(%v) err = %v, want nil", ed25519.VariantTink, err)
	}
	noPrefixParams, err := ed25519.NewParameters(ed25519.VariantNoPrefix)
	if err != nil {
		t.Fatalf("ed25519.NewParameters(%v) err = %v, want nil", ed25519.VariantNoPrefix, err)
	}
	for _, tc := range []struct {
		name          string
		params        ed25519.Parameters
		keyBytes      []byte
		idRequirement uint32
	}{
		{
			name:          "nil key bytes",
			params:        tinkParams,
			keyBytes:      nil,
			idRequirement: 123,
		},
		{
			name:          "invalid key bytes size",
			params:        tinkParams,
			keyBytes:      []byte("123"),
			idRequirement: 123,
		},
		{
			name:          "invalid ID requirement",
			params:        noPrefixParams,
			keyBytes:      []byte("12345678901234567890123456789012"),
			idRequirement: 123,
		},
		{
			name:          "invalid params",
			params:        ed25519.Parameters{},
			keyBytes:      []byte("12345678901234567890123456789012"),
			idRequirement: 123,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {

			if _, err := ed25519.NewPublicKey(tc.keyBytes, tc.idRequirement, tc.params); err == nil {
				t.Errorf("ed25519.NewPublicKey(%v, %v, %v) err = nil, want error", tc.keyBytes, tc.idRequirement, tc.params)
			}
		})
	}
}

func TestPublicKey(t *testing.T) {
	keyBytes := []byte("12345678901234567890123456789012")
	for _, tc := range []struct {
		name             string
		variant          ed25519.Variant
		keyBytes         []byte
		idRequirement    uint32
		wantOutputPrefix []byte
	}{
		{
			name:             "tink",
			variant:          ed25519.VariantTink,
			keyBytes:         keyBytes,
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:             "crunchy",
			variant:          ed25519.VariantCrunchy,
			keyBytes:         keyBytes,
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:             "legacy",
			variant:          ed25519.VariantLegacy,
			keyBytes:         keyBytes,
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:             "no prefix",
			variant:          ed25519.VariantNoPrefix,
			keyBytes:         keyBytes,
			idRequirement:    0,
			wantOutputPrefix: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := ed25519.NewParameters(tc.variant)
			if err != nil {
				t.Fatalf("ed25519.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			pubKey, err := ed25519.NewPublicKey(tc.keyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("ed25519.NewPublicKey(%v, %v, %v) err = %v, want nil", tc.keyBytes, tc.idRequirement, params, err)
			}
			if got := pubKey.OutputPrefix(); !bytes.Equal(got, tc.wantOutputPrefix) {
				t.Errorf("params.OutputPrefix() = %v, want %v", got, tc.wantOutputPrefix)
			}
			gotIDRequrement, gotRequired := pubKey.IDRequirement()
			if got, want := gotRequired, params.HasIDRequirement(); got != want {
				t.Errorf("params.IDRequirement() = %v, want %v", got, want)
			}
			if got, want := gotIDRequrement, tc.idRequirement; got != want {
				t.Errorf("params.IDRequirement() = %v, want %v", got, want)
			}

			otherPubKey, err := ed25519.NewPublicKey(tc.keyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("ed25519.NewPublicKey(%v, %v, %v) err = %v, want nil", tc.keyBytes, tc.idRequirement, params, err)
			}
			if !otherPubKey.Equals(pubKey) {
				t.Errorf("otherPubKey.Equals(pubKey) = false, want true")
			}
		})
	}
}

type TestPublicKeyParams struct {
	keyBytes      []byte
	idRequirement uint32
	variant       ed25519.Variant
}

func TestPublicKeyEqualsSelf(t *testing.T) {
	params, err := ed25519.NewParameters(ed25519.VariantTink)
	if err != nil {
		t.Fatalf("ed25519.NewParameters(%v) err = %v, want nil", ed25519.VariantTink, err)
	}
	keyBytes := []byte("12345678901234567890123456789012")
	pubKey, err := ed25519.NewPublicKey(keyBytes, 123, params)
	if err != nil {
		t.Fatalf("ed25519.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, 123, params, err)
	}
	if !pubKey.Equals(pubKey) {
		t.Errorf("pubKey.Equals(pubKey) = false, want true")
	}
}

func TestPublicKeyEqualsFalse(t *testing.T) {
	for _, tc := range []struct {
		name      string
		firstKey  *TestPublicKeyParams
		secondKey *TestPublicKeyParams
	}{
		{
			name: "different ID requirement",
			firstKey: &TestPublicKeyParams{
				keyBytes:      []byte("12345678901234567890123456789012"),
				idRequirement: 123,
				variant:       ed25519.VariantTink,
			},
			secondKey: &TestPublicKeyParams{
				keyBytes:      []byte("12345678901234567890123456789012"),
				idRequirement: 456,
				variant:       ed25519.VariantTink,
			},
		},
		{
			name: "different key bytes",
			firstKey: &TestPublicKeyParams{
				keyBytes:      []byte("12345678901234567890123456789012"),
				idRequirement: 123,
				variant:       ed25519.VariantTink,
			},
			secondKey: &TestPublicKeyParams{
				keyBytes:      []byte("11111111111111111111111111111111"),
				idRequirement: 123,
				variant:       ed25519.VariantTink,
			},
		},
		{
			name: "different variant",
			firstKey: &TestPublicKeyParams{
				keyBytes:      []byte("12345678901234567890123456789012"),
				idRequirement: 123,
				variant:       ed25519.VariantTink,
			},
			secondKey: &TestPublicKeyParams{
				keyBytes:      []byte("12345678901234567890123456789012"),
				idRequirement: 123,
				variant:       ed25519.VariantCrunchy,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			firstParams, err := ed25519.NewParameters(tc.firstKey.variant)
			if err != nil {
				t.Fatalf("ed25519.NewParameters(%v) err = %v, want nil", tc.firstKey.variant, err)
			}
			firstPubKey, err := ed25519.NewPublicKey(tc.firstKey.keyBytes, tc.firstKey.idRequirement, firstParams)
			if err != nil {
				t.Fatalf("ed25519.NewPublicKey(%v, %v, %v) err = %v, want nil", tc.firstKey.keyBytes, tc.firstKey.idRequirement, firstParams, err)
			}

			secondParams, err := ed25519.NewParameters(tc.secondKey.variant)
			if err != nil {
				t.Fatalf("ed25519.NewParameters(%v) err = %v, want nil", tc.secondKey.variant, err)
			}
			secondPubKey, err := ed25519.NewPublicKey(tc.secondKey.keyBytes, tc.secondKey.idRequirement, secondParams)
			if err != nil {
				t.Fatalf("ed25519.NewPublicKey(%v, %v, %v) err = %v, want nil", tc.secondKey.keyBytes, tc.secondKey.idRequirement, secondParams, err)
			}
			if firstPubKey.Equals(secondPubKey) {
				t.Errorf("firstPubKey.Equals(secondPubKey) = true, want false")
			}
		})
	}
}

func TestPublicKeyKeyBytes(t *testing.T) {
	params, err := ed25519.NewParameters(ed25519.VariantTink)
	if err != nil {
		t.Fatalf("ed25519.NewParameters(%v) err = %v, want nil", ed25519.VariantTink, err)
	}
	keyBytes := []byte("12345678901234567890123456789012")
	pubKey, err := ed25519.NewPublicKey(keyBytes, 123, params)
	if err != nil {
		t.Fatalf("ed25519.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, 123, params, err)
	}
	gotPubKeyBytes := pubKey.KeyBytes()
	if !bytes.Equal(gotPubKeyBytes, keyBytes) {
		t.Errorf("bytes.Equal(gotPubKeyBytes, keyBytes) = false, want true")
	}
	// Make sure a copy is made when creating the public key.
	keyBytes[0] = 0x99
	fmt.Println(keyBytes)
	if bytes.Equal(pubKey.KeyBytes(), keyBytes) {
		t.Errorf("bytes.Equal(pubKey.KeyBytes(), keyBytes) = true, want false")
	}
	// Make sure no changes are made to the internal state of the public key.
	gotPubKeyBytes[1] = 0x99
	if bytes.Equal(pubKey.KeyBytes(), gotPubKeyBytes) {
		t.Errorf("bytes.Equal((pubKey.KeyBytes(), gotPubKeyBytes) = true, want false")
	}
}

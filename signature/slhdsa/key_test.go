// Copyright 2025 Google LLC
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

package slhdsa_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature/slhdsa"
)

func TestNewParameters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType slhdsa.HashType
		keySize  int
		sigType  slhdsa.SignatureType
		variant  slhdsa.Variant
	}{
		{
			name:     "tink SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			variant:  slhdsa.VariantTink,
		},
		{
			name:     "no prefix SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			variant:  slhdsa.VariantNoPrefix,
		},
		{
			name:     "tink SHAKE-256f",
			hashType: slhdsa.SHAKE,
			keySize:  128,
			sigType:  slhdsa.FastSigning,
			variant:  slhdsa.VariantTink,
		},
		{
			name:     "no prefix SHAKE-256f",
			hashType: slhdsa.SHAKE,
			keySize:  128,
			sigType:  slhdsa.FastSigning,
			variant:  slhdsa.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant)
			if err != nil {
				t.Errorf("slhdsa.NewParameters(%v, %v, %v, %v) err = %v, want nil", tc.hashType, tc.keySize, tc.sigType, tc.variant, err)
			}
			if got := params.HashType(); got != tc.hashType {
				t.Errorf("params.HashType() = %v, want %v", got, tc.hashType)
			}
			if got := params.KeySize(); got != tc.keySize {
				t.Errorf("params.KeySize() = %v, want %v", got, tc.keySize)
			}
			if got := params.SignatureType(); got != tc.sigType {
				t.Errorf("params.SignatureType() = %v, want %v", got, tc.sigType)
			}
			if got := params.Variant(); got != tc.variant {
				t.Errorf("params.Variant() = %v, want %v", got, tc.variant)
			}
		})
	}
}

func TestNewParametersFails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType slhdsa.HashType
		keySize  int
		sigType  slhdsa.SignatureType
		variant  slhdsa.Variant
	}{
		{
			name:     "unknown",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			variant:  slhdsa.VariantUnknown,
		},
		{
			name:     "invalid hash type",
			hashType: slhdsa.SHAKE,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			variant:  slhdsa.VariantTink,
		},
		{
			name:     "invalid key size",
			hashType: slhdsa.SHA2,
			keySize:  128,
			sigType:  slhdsa.SmallSignature,
			variant:  slhdsa.VariantTink,
		},
		{
			name:     "invalid signature type",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.FastSigning,
			variant:  slhdsa.VariantTink,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant); err == nil {
				t.Errorf("slhdsa.NewParameters(%v, %v, %v, %v) err = nil, want error", tc.hashType, tc.keySize, tc.sigType, tc.variant)
			}
		})
	}
}

func TestParametersHasIDRequirement(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType slhdsa.HashType
		keySize  int
		sigType  slhdsa.SignatureType
		variant  slhdsa.Variant
		want     bool
	}{
		{
			name:     "tink",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			variant:  slhdsa.VariantTink,
			want:     true,
		},
		{
			name:     "no prefix",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			variant:  slhdsa.VariantNoPrefix,
			want:     false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v, %v, %v, %v) err = %v, want nil", tc.hashType, tc.keySize, tc.sigType, tc.variant, err)
			}
			if got := params.HasIDRequirement(); got != tc.want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParametersEqual(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType slhdsa.HashType
		keySize  int
		sigType  slhdsa.SignatureType
	}{
		{
			name:     "SLH-DSA_SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
		},
		{
			name:     "SLH-DSA_SHAKE-256f",
			hashType: slhdsa.SHAKE,
			keySize:  128,
			sigType:  slhdsa.FastSigning,
		},
	} {
		t.Run(fmt.Sprintf("%s", tc.name), func(t *testing.T) {
			tinkVariant, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			noPrefixVariant, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want	 nil", slhdsa.VariantNoPrefix, err)
			}

			if !tinkVariant.Equal(tinkVariant) {
				t.Errorf("tinkVariant.Equal(tinkVariant) = false, want true")
			}
			if !noPrefixVariant.Equal(noPrefixVariant) {
				t.Errorf("noPrefixVariant.Equal(noPrefixVariant) = false, want true")
			}
			if tinkVariant.Equal(noPrefixVariant) {
				t.Errorf("tinkVariant.Equal(noPrefixVariant) = true, want false")
			}
		})
	}
}

func TestNewPublicKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType slhdsa.HashType
		keySize  int
		sigType  slhdsa.SignatureType
		privHex  string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			privHex:  privKeySHA2128sHex,
		},
		{
			name:     "SLH-DSA-SHAKE-256f",
			hashType: slhdsa.SHAKE,
			keySize:  128,
			sigType:  slhdsa.FastSigning,
			privHex:  privKeySHAKE256fHex,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tinkParams, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			noPrefixParams, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantNoPrefix, err)
			}
			privKeyBytes, err := hex.DecodeString(tc.privHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(inst.privHex) err = %v, want nil", err)
			}
			for _, tc := range []struct {
				name          string
				params        *slhdsa.Parameters
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
					keyBytes:      privKeyBytes,
					idRequirement: 123,
				},
				{
					name:          "invalid params",
					params:        &slhdsa.Parameters{},
					keyBytes:      privKeyBytes,
					idRequirement: 123,
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if _, err := slhdsa.NewPublicKey(tc.keyBytes, tc.idRequirement, tc.params); err == nil {
						t.Errorf("slhdsa.NewPublicKey(%v, %v, %v) err = nil, want error", tc.keyBytes, tc.idRequirement, tc.params)
					}
				})
			}
		})
	}
}

func TestPublicKey(t *testing.T) {
	for _, tc := range []struct {
		name             string
		hashType         slhdsa.HashType
		keySize          int
		sigType          slhdsa.SignatureType
		variant          slhdsa.Variant
		pubKeyHex        string
		idRequirement    uint32
		wantOutputPrefix []byte
	}{
		{
			name:             "tink SHA2-128s",
			hashType:         slhdsa.SHA2,
			keySize:          64,
			sigType:          slhdsa.SmallSignature,
			variant:          slhdsa.VariantTink,
			pubKeyHex:        pubKeySHA2128sHex,
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:             "no prefix SHA2-128s",
			hashType:         slhdsa.SHA2,
			keySize:          64,
			sigType:          slhdsa.SmallSignature,
			variant:          slhdsa.VariantNoPrefix,
			pubKeyHex:        pubKeySHA2128sHex,
			idRequirement:    0,
			wantOutputPrefix: nil,
		},
		{
			name:             "tink SHAKE-256f",
			hashType:         slhdsa.SHAKE,
			keySize:          128,
			sigType:          slhdsa.FastSigning,
			variant:          slhdsa.VariantTink,
			pubKeyHex:        pubKeySHAKE256fHex,
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:             "no prefix SHAKE-256f",
			hashType:         slhdsa.SHAKE,
			keySize:          128,
			sigType:          slhdsa.FastSigning,
			variant:          slhdsa.VariantNoPrefix,
			pubKeyHex:        pubKeySHAKE256fHex,
			idRequirement:    0,
			wantOutputPrefix: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyBytes, err := hex.DecodeString(tc.pubKeyHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
			}
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			pubKey, err := slhdsa.NewPublicKey(keyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, tc.idRequirement, params, err)
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

			otherPubKey, err := slhdsa.NewPublicKey(keyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, tc.idRequirement, params, err)
			}
			if !otherPubKey.Equal(pubKey) {
				t.Errorf("otherPubKey.Equal(pubKey) = false, want true")
			}
		})
	}
}

func TestPublicKeyEqualSelf(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:      "SLH-DSA-SHA2-128s",
			hashType:  slhdsa.SHA2,
			keySize:   64,
			sigType:   slhdsa.SmallSignature,
			pubKeyHex: pubKeySHA2128sHex,
		},
		{
			name:      "SLH-DSA-SHAKE-256f",
			hashType:  slhdsa.SHAKE,
			keySize:   128,
			sigType:   slhdsa.FastSigning,
			pubKeyHex: pubKeySHAKE256fHex,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			keyBytes, err := hex.DecodeString(tc.pubKeyHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
			}
			pubKey, err := slhdsa.NewPublicKey(keyBytes, 123, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, 123, params, err)
			}
			if !pubKey.Equal(pubKey) {
				t.Errorf("pubKey.Equal(pubKey) = false, want true")
			}
		})
	}
}

type stubKey struct{}

var _ key.Key = (*stubKey)(nil)

func (k *stubKey) Parameters() key.Parameters    { return nil }
func (k *stubKey) Equal(other key.Key) bool      { return true }
func (k *stubKey) IDRequirement() (uint32, bool) { return 123, true }

func TestPublicKeyEqual_FalseIfDifferentType(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:      "SLH-DSA-SHA2-128s",
			hashType:  slhdsa.SHA2,
			keySize:   64,
			sigType:   slhdsa.SmallSignature,
			pubKeyHex: pubKeySHA2128sHex,
		},
		{
			name:      "SLH-DSA-SHAKE-256f",
			hashType:  slhdsa.SHAKE,
			keySize:   128,
			sigType:   slhdsa.FastSigning,
			pubKeyHex: pubKeySHAKE256fHex,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			keyBytes, err := hex.DecodeString(tc.pubKeyHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
			}
			pubKey, err := slhdsa.NewPublicKey(keyBytes, 123, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, 123, params, err)
			}
			if pubKey.Equal(&stubKey{}) {
				t.Errorf("pubKey.Equal(&stubKey{}) = true, want false")
			}
		})
	}
}

type TestPublicKeyParams struct {
	keyHex         string
	changeKeyBytes bool
	idRequirement  uint32
	hashType       slhdsa.HashType
	keySize        int
	sigType        slhdsa.SignatureType
	variant        slhdsa.Variant
}

func TestPublicKeyEqualFalse(t *testing.T) {
	for _, tc := range []struct {
		name      string
		firstKey  *TestPublicKeyParams
		secondKey *TestPublicKeyParams
	}{
		{
			name: "different ID requirement",
			firstKey: &TestPublicKeyParams{
				keyHex:        pubKeySHA2128sHex,
				idRequirement: 123,
				hashType:      slhdsa.SHA2,
				keySize:       64,
				sigType:       slhdsa.SmallSignature,
				variant:       slhdsa.VariantTink,
			},
			secondKey: &TestPublicKeyParams{
				keyHex:        pubKeySHA2128sHex,
				idRequirement: 456,
				hashType:      slhdsa.SHA2,
				keySize:       64,
				sigType:       slhdsa.SmallSignature,
				variant:       slhdsa.VariantTink,
			},
		},
		{
			name: "different key bytes",
			firstKey: &TestPublicKeyParams{
				keyHex:        pubKeySHA2128sHex,
				idRequirement: 123,
				hashType:      slhdsa.SHA2,
				keySize:       64,
				sigType:       slhdsa.SmallSignature,
				variant:       slhdsa.VariantTink,
			},
			secondKey: &TestPublicKeyParams{
				keyHex:         pubKeySHA2128sHex,
				changeKeyBytes: true,
				idRequirement:  123,
				hashType:       slhdsa.SHA2,
				keySize:        64,
				sigType:        slhdsa.SmallSignature,
				variant:        slhdsa.VariantTink,
			},
		},
		{
			name: "different variant",
			firstKey: &TestPublicKeyParams{
				keyHex:        pubKeySHA2128sHex,
				idRequirement: 0,
				hashType:      slhdsa.SHA2,
				keySize:       64,
				sigType:       slhdsa.SmallSignature,
				variant:       slhdsa.VariantTink,
			},
			secondKey: &TestPublicKeyParams{
				keyHex:        pubKeySHA2128sHex,
				idRequirement: 0,
				hashType:      slhdsa.SHA2,
				keySize:       64,
				sigType:       slhdsa.SmallSignature,
				variant:       slhdsa.VariantNoPrefix,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			firstKeyBytes, err := hex.DecodeString(tc.firstKey.keyHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(tc.firstKey.keyHex) err = %v, want nil", err)
			}
			if tc.firstKey.changeKeyBytes {
				firstKeyBytes[0] = 0x99
			}
			secondKeyBytes, err := hex.DecodeString(tc.secondKey.keyHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(tc.secondKey.keyHex) err = %v, want nil", err)
			}
			if tc.secondKey.changeKeyBytes {
				secondKeyBytes[0] = 0x99
			}
			firstParams, err := slhdsa.NewParameters(tc.firstKey.hashType, tc.firstKey.keySize, tc.firstKey.sigType, tc.firstKey.variant)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", tc.firstKey.variant, err)
			}
			firstPubKey, err := slhdsa.NewPublicKey(firstKeyBytes, tc.firstKey.idRequirement, firstParams)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", firstKeyBytes, tc.firstKey.idRequirement, firstParams, err)
			}
			secondParams, err := slhdsa.NewParameters(tc.secondKey.hashType, tc.secondKey.keySize, tc.secondKey.sigType, tc.secondKey.variant)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", tc.secondKey.variant, err)
			}
			secondPubKey, err := slhdsa.NewPublicKey(secondKeyBytes, tc.secondKey.idRequirement, secondParams)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", secondKeyBytes, tc.secondKey.idRequirement, secondParams, err)
			}
			if firstPubKey.Equal(secondPubKey) {
				t.Errorf("firstPubKey.Equal(secondPubKey) = true, want false")
			}
		})
	}
}

func TestPublicKeyKeyBytes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType slhdsa.HashType
		keySize  int
		sigType  slhdsa.SignatureType
		keyHex   string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			keyHex:   pubKeySHA2128sHex,
		},
		{
			name:     "SLH-DSA-SHAKE-256f",
			hashType: slhdsa.SHAKE,
			keySize:  128,
			sigType:  slhdsa.FastSigning,
			keyHex:   pubKeySHAKE256fHex,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			keyBytes, err := hex.DecodeString(tc.keyHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(tc.keyHex) err = %v, want nil", err)
			}
			pubKey, err := slhdsa.NewPublicKey(keyBytes, 123, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, 123, params, err)
			}
			gotPubKeyBytes := pubKey.KeyBytes()
			if !bytes.Equal(gotPubKeyBytes, keyBytes) {
				t.Errorf("bytes.Equal(gotPubKeyBytes, keyBytes) = false, want true")
			}
			// Make sure a copy is made when creating the public key.
			keyBytes[0] = 0x99
			if bytes.Equal(pubKey.KeyBytes(), keyBytes) {
				t.Errorf("bytes.Equal(pubKey.KeyBytes(), keyBytes) = true, want false")
			}
			// Make sure no changes are made to the internal state of the public key.
			gotPubKeyBytes[1] = 0x99
			if bytes.Equal(pubKey.KeyBytes(), gotPubKeyBytes) {
				t.Errorf("bytes.Equal((pubKey.KeyBytes(), gotPubKeyBytes) = true, want false")
			}
		})
	}
}

var testCases = []struct {
	name             string
	hashType         slhdsa.HashType
	keySize          int
	sigType          slhdsa.SignatureType
	variant          slhdsa.Variant
	privKeyBytesHex  string
	pubKeyBytesHex   string
	idRequirement    uint32
	wantOutputPrefix []byte
}{
	{
		name:             "tink SHA2-128s",
		hashType:         slhdsa.SHA2,
		keySize:          64,
		sigType:          slhdsa.SmallSignature,
		variant:          slhdsa.VariantTink,
		privKeyBytesHex:  privKeySHA2128sHex,
		pubKeyBytesHex:   pubKeySHA2128sHex,
		idRequirement:    uint32(0x01020304),
		wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
	},
	{
		name:             "no prefix SHA2-128s",
		hashType:         slhdsa.SHA2,
		keySize:          64,
		sigType:          slhdsa.SmallSignature,
		variant:          slhdsa.VariantNoPrefix,
		privKeyBytesHex:  privKeySHA2128sHex,
		pubKeyBytesHex:   pubKeySHA2128sHex,
		idRequirement:    0,
		wantOutputPrefix: nil,
	},
	{
		name:             "tink SHAKE-256f",
		hashType:         slhdsa.SHAKE,
		keySize:          128,
		sigType:          slhdsa.FastSigning,
		variant:          slhdsa.VariantTink,
		privKeyBytesHex:  privKeySHAKE256fHex,
		pubKeyBytesHex:   pubKeySHAKE256fHex,
		idRequirement:    uint32(0x01020304),
		wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
	},
	{
		name:             "no prefix SHAKE-256f",
		hashType:         slhdsa.SHAKE,
		keySize:          128,
		sigType:          slhdsa.FastSigning,
		variant:          slhdsa.VariantNoPrefix,
		privKeyBytesHex:  privKeySHAKE256fHex,
		pubKeyBytesHex:   pubKeySHAKE256fHex,
		idRequirement:    0,
		wantOutputPrefix: nil,
	},
}

func TestPrivateKeyNewPrivateKeyWithPublicKey(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			keyPair := generateTestKeyPair(t, tc.hashType, tc.keySize, tc.sigType)
			pubKey, err := slhdsa.NewPublicKey(keyPair.pubKey, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyPair.pubKey, tc.idRequirement, params, err)
			}
			secretKey := secretdata.NewBytesFromData(keyPair.privKey, insecuresecretdataaccess.Token{})
			privKey, err := slhdsa.NewPrivateKeyWithPublicKey(secretKey, pubKey)
			if err != nil {
				t.Fatalf("slhdsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v, want nil", secretKey, pubKey, err)
			}

			// Test IDRequirement.
			gotIDRequrement, gotRequired := privKey.IDRequirement()
			if got, want := gotRequired, params.HasIDRequirement(); got != want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, want)
			}
			if got, want := gotIDRequrement, tc.idRequirement; got != want {
				t.Errorf("params.IDRequirement() = %v, want %v", got, want)
			}

			// Test OutputPrefix.
			if got := privKey.OutputPrefix(); !bytes.Equal(got, tc.wantOutputPrefix) {
				t.Errorf("params.OutputPrefix() = %v, want %v", got, tc.wantOutputPrefix)
			}

			// Test Equal.
			otherPubKey, err := slhdsa.NewPublicKey(keyPair.pubKey, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyPair.pubKey, tc.idRequirement, params, err)
			}
			otherPrivKey, err := slhdsa.NewPrivateKeyWithPublicKey(secretKey, otherPubKey)
			if err != nil {
				t.Fatalf("slhdsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v, want nil", secretKey, pubKey, err)
			}
			if !otherPrivKey.Equal(privKey) {
				t.Errorf("otherPrivKey.Equal(privKey) = false, want true")
			}

			// Test PublicKey.
			got, err := privKey.PublicKey()
			if err != nil {
				t.Fatalf("privKey.PublicKey() err = %v, want nil", err)
			}
			if !got.Equal(pubKey) {
				t.Errorf("privKey.PublicKey().Equal(pubKey) = false, want true")
			}

			// Test Parameters.
			if got := privKey.Parameters(); !got.Equal(params) {
				t.Errorf("privKey.Parameters().Equal(&params) = false, want true")
			}
		})
	}
}

func TestPrivateKeyNewPrivateKey(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			keyPair := generateTestKeyPair(t, tc.hashType, tc.keySize, tc.sigType)
			secretKey := secretdata.NewBytesFromData(keyPair.privKey, insecuresecretdataaccess.Token{})
			privKey, err := slhdsa.NewPrivateKey(secretKey, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", secretKey, tc.idRequirement, params, err)
			}

			// Test IDRequirement.
			gotIDRequrement, gotRequired := privKey.IDRequirement()
			if got, want := gotRequired, params.HasIDRequirement(); got != want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, want)
			}
			if got, want := gotIDRequrement, tc.idRequirement; got != want {
				t.Errorf("params.IDRequirement() = %v, want %v", got, want)
			}

			// Test OutputPrefix.
			if got := privKey.OutputPrefix(); !bytes.Equal(got, tc.wantOutputPrefix) {
				t.Errorf("params.OutputPrefix() = %v, want %v", got, tc.wantOutputPrefix)
			}

			// Test Equal.
			otherPrivKey, err := slhdsa.NewPrivateKey(secretKey, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", secretKey, tc.idRequirement, params, err)
			}
			if !otherPrivKey.Equal(privKey) {
				t.Errorf("otherPrivKey.Equal(privKey) = false, want true")
			}

			// Test PublicKey.
			want, err := slhdsa.NewPublicKey(keyPair.pubKey, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyPair.pubKey, tc.idRequirement, params, err)
			}
			got, err := privKey.PublicKey()
			if err != nil {
				t.Fatalf("privKey.PublicKey() err = %v, want nil", err)
			}
			if !got.Equal(want) {
				t.Errorf("privKey.PublicKey().Equal(want) = false, want true")
			}

			// Test Parameters.
			if got := privKey.Parameters(); !got.Equal(params) {
				t.Errorf("privKey.Parameters().Equal(&params) = false, want true")
			}
		})
	}
}

func TestNewPrivateKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
		},
		{
			name:     "SLH-DSA-SHAKE-256f",
			hashType: slhdsa.SHAKE,
			keySize:  128,
			sigType:  slhdsa.FastSigning,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paramsTink, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			paramsNoPrefix, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantNoPrefix, err)
			}
			for _, tc := range []struct {
				name         string
				params       *slhdsa.Parameters
				idRequrement uint32
				privKeyBytes secretdata.Bytes
			}{
				{
					name:         "nil private key bytes",
					params:       paramsTink,
					idRequrement: 123,
					privKeyBytes: secretdata.NewBytesFromData(nil, insecuresecretdataaccess.Token{}),
				},
				{
					name:         "invalid private key bytes size",
					params:       paramsTink,
					idRequrement: 123,
					privKeyBytes: secretdata.NewBytesFromData([]byte("123"), insecuresecretdataaccess.Token{}),
				},
				{
					name:         "empty params",
					params:       &slhdsa.Parameters{},
					idRequrement: 123,
					privKeyBytes: secretdata.NewBytesFromData([]byte("12345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
				},
				{
					name:         "invalid ID requiremet",
					idRequrement: 123,
					params:       paramsNoPrefix,
					privKeyBytes: secretdata.NewBytesFromData([]byte("12345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if _, err := slhdsa.NewPrivateKey(tc.privKeyBytes, tc.idRequrement, tc.params); err == nil {
						t.Errorf("slhdsa.NewPrivateKey(%v, %v, %v) err = nil, want error", tc.privKeyBytes, tc.idRequrement, tc.params)
					}
				})
			}
		})
	}
}

func TestNewPrivateKeyWithPublicKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
		},
		{
			name:     "SLH-DSA-SHAKE-256f",
			hashType: slhdsa.SHAKE,
			keySize:  128,
			sigType:  slhdsa.FastSigning,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			keyPair := generateTestKeyPair(t, tc.hashType, tc.keySize, tc.sigType)
			pubKey, err := slhdsa.NewPublicKey(keyPair.pubKey, 123, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyPair.pubKey, 123, params, err)
			}
			for _, tc := range []struct {
				name            string
				params          *slhdsa.Parameters
				pubKey          *slhdsa.PublicKey
				privateKeyBytes secretdata.Bytes
			}{
				{
					name:            "nil private key bytes",
					pubKey:          pubKey,
					privateKeyBytes: secretdata.NewBytesFromData(nil, insecuresecretdataaccess.Token{}),
				},
				{
					name:            "invalid private key bytes size",
					pubKey:          pubKey,
					privateKeyBytes: secretdata.NewBytesFromData([]byte("123"), insecuresecretdataaccess.Token{}),
				},
				{
					name:            "empty public key",
					pubKey:          &slhdsa.PublicKey{},
					privateKeyBytes: secretdata.NewBytesFromData(keyPair.privKey, insecuresecretdataaccess.Token{}),
				},
				{
					name:            "nil public key",
					pubKey:          nil,
					privateKeyBytes: secretdata.NewBytesFromData(keyPair.privKey, insecuresecretdataaccess.Token{}),
				},
				{
					name:            "invalid public key",
					pubKey:          pubKey,
					privateKeyBytes: secretdata.NewBytesFromData([]byte("12345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if _, err := slhdsa.NewPrivateKeyWithPublicKey(tc.privateKeyBytes, tc.pubKey); err == nil {
						t.Errorf("slhdsa.NewPrivateKeyWithPublicKey(%v, %v) err = nil, want error", tc.privateKeyBytes, tc.pubKey)
					}
				})
			}
		})
	}
}

func TestPrivateKeyEqualSelf(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
		},
		{
			name:     "SLH-DSA-SHAKE-256f",
			hashType: slhdsa.SHAKE,
			keySize:  128,
			sigType:  slhdsa.FastSigning,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			keyPair := generateTestKeyPair(t, tc.hashType, tc.keySize, tc.sigType)
			pubKey, err := slhdsa.NewPublicKey(keyPair.pubKey, 123, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v", keyPair.pubKey, 123, params, err)
			}
			secretKey := secretdata.NewBytesFromData(keyPair.privKey, insecuresecretdataaccess.Token{})
			privKey, err := slhdsa.NewPrivateKeyWithPublicKey(secretKey, pubKey)
			if err != nil {
				t.Fatalf("slhdsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v", secretKey, pubKey, err)
			}
			if !privKey.Equal(privKey) {
				t.Errorf("privKey.Equal(privKey) = false, want true")
			}
		})
	}
}

func TestPrivateKeyEqual_FalseIfDifferentType(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
		},
		{
			name:     "SLH-DSA-SHAKE-256f",
			hashType: slhdsa.SHAKE,
			keySize:  128,
			sigType:  slhdsa.FastSigning,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			keyPair := generateTestKeyPair(t, tc.hashType, tc.keySize, tc.sigType)
			pubKey, err := slhdsa.NewPublicKey(keyPair.pubKey, 123, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v", keyPair.pubKey, 123, params, err)
			}
			secretKey := secretdata.NewBytesFromData(keyPair.privKey, insecuresecretdataaccess.Token{})
			privKey, err := slhdsa.NewPrivateKeyWithPublicKey(secretKey, pubKey)
			if err != nil {
				t.Fatalf("slhdsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v", secretKey, pubKey, err)
			}
			if privKey.Equal(&stubKey{}) {
				t.Errorf("privKey.Equal(&stubKey{}) = true, want false")
			}
		})
	}
}

func TestPrivateKeyEqualFalse(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paramsTink, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			paramsNoPrefix, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantNoPrefix, err)
			}
			for _, tc := range []struct {
				name           string
				privKeyBytes1  secretdata.Bytes
				params1        *slhdsa.Parameters
				idRequirement1 uint32
				privKeyBytes2  secretdata.Bytes
				params2        *slhdsa.Parameters
				idRequirement2 uint32
			}{
				{
					name:           "different private key bytes",
					privKeyBytes1:  secretdata.NewBytesFromData([]byte("1234567812345678123456781234567812345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params1:        paramsTink,
					idRequirement1: 123,
					privKeyBytes2:  secretdata.NewBytesFromData([]byte("1234567812345678123456781234567812345678123456781234567812345679"), insecuresecretdataaccess.Token{}),
					params2:        paramsTink,
					idRequirement2: 123,
				},
				{
					name:           "different ID requirement",
					privKeyBytes1:  secretdata.NewBytesFromData([]byte("1234567812345678123456781234567812345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params1:        paramsTink,
					idRequirement1: 123,
					privKeyBytes2:  secretdata.NewBytesFromData([]byte("1234567812345678123456781234567812345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params2:        paramsTink,
					idRequirement2: 456,
				},
				{
					name:           "different params",
					privKeyBytes1:  secretdata.NewBytesFromData([]byte("1234567812345678123456781234567812345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params1:        paramsTink,
					idRequirement1: 0,
					privKeyBytes2:  secretdata.NewBytesFromData([]byte("1234567812345678123456781234567812345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params2:        paramsNoPrefix,
					idRequirement2: 0,
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					firstPrivKey, err := slhdsa.NewPrivateKey(tc.privKeyBytes1, tc.idRequirement1, tc.params1)
					if err != nil {
						t.Fatalf("slhdsa.NewPrivateKey(%v, %v, %v) err = %v", tc.privKeyBytes1, tc.idRequirement1, tc.params1, err)
					}
					secondPrivKey, err := slhdsa.NewPrivateKey(tc.privKeyBytes2, tc.idRequirement2, tc.params2)
					if err != nil {
						t.Fatalf("slhdsa.NewPrivateKey(%v, %v, %v) err = %v", tc.privKeyBytes2, tc.idRequirement2, tc.params2, err)
					}
					if firstPrivKey.Equal(secondPrivKey) {
						t.Errorf("firstPrivKey.Equal(secondPrivKey) = true, want false")
					}
				})
			}
		})
	}
}

func TestPrivateKeyKeyBytes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
		},
		{
			name:     "SLH-DSA-SHAKE-256f",
			hashType: slhdsa.SHAKE,
			keySize:  128,
			sigType:  slhdsa.FastSigning,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyPair := generateTestKeyPair(t, tc.hashType, tc.keySize, tc.sigType)
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			pubKey, err := slhdsa.NewPublicKey(keyPair.pubKey, 123, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyPair.pubKey, 123, params, err)
			}
			secretKey := secretdata.NewBytesFromData(keyPair.privKey, insecuresecretdataaccess.Token{})
			privKey, err := slhdsa.NewPrivateKeyWithPublicKey(secretKey, pubKey)
			if err != nil {
				t.Fatalf("slhdsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v, want nil", secretKey, pubKey, err)
			}
			if got, want := privKey.PrivateKeyBytes().Data(insecuresecretdataaccess.Token{}), keyPair.privKey; !bytes.Equal(got, want) {
				t.Errorf("bytes.Equal(got, want) = false, want true")
			}
		})
	}
}

func TestKeyCreator(t *testing.T) {
	params, err := slhdsa.NewParameters(slhdsa.SHA2, 64, slhdsa.SmallSignature, slhdsa.VariantTink)
	if err != nil {
		t.Fatalf("slhdsa.NewParameters() err = %v, want nil", err)
	}

	key, err := keygenregistry.CreateKey(params, 0x1234)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey(%v, 0x1234) err = %v, want nil", params, err)
	}
	slhdsaPrivateKey, ok := key.(*slhdsa.PrivateKey)
	if !ok {
		t.Fatalf("keygenregistry.CreateKey(%v, 0x1234) returned key of type %T, want %T", params, key, (*slhdsa.PrivateKey)(nil))
	}
	idRequirement, hasIDRequirement := slhdsaPrivateKey.IDRequirement()
	if !hasIDRequirement || idRequirement != 0x1234 {
		t.Errorf("slhdsaPrivateKey.IDRequirement() (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 123, true)
	}
	if diff := cmp.Diff(slhdsaPrivateKey.Parameters(), params); diff != "" {
		t.Errorf("slhdsaPrivateKey.Parameters() diff (-want +got):\n%s", diff)
	}
}

func TestPrivateKeyCreator_Fails(t *testing.T) {
	paramsNoPrefix, err := slhdsa.NewParameters(slhdsa.SHA2, 64, slhdsa.SmallSignature, slhdsa.VariantNoPrefix)
	if err != nil {
		t.Fatalf("slhdsa.NewParameters() err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name          string
		params        *slhdsa.Parameters
		idRequirement uint32
	}{
		{
			name:          "invalid id requirement",
			params:        paramsNoPrefix,
			idRequirement: 0x1234,
		},
		{
			name:          "invalid parameters",
			params:        &slhdsa.Parameters{},
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

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

package mldsa_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/signprehash/mldsa"
)

const (
	privKey44SeedHex = "dddaccfaa05b0332b3fd7269c7d42de6cbe370735431f735346ccb6be7ad3174"
	privKey65SeedHex = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D"
	privKey87SeedHex = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D"
)

func TestNewPrehashFailsForVariantNoPrefix(t *testing.T) {
	seedBytes, _ := hex.DecodeString(privKey65SeedHex)
	noPrefixParams, err := tinkmldsa.NewParameters(tinkmldsa.MLDSA65, tinkmldsa.VariantNoPrefix)
	if err != nil {
		t.Fatalf("tinkmldsa.NewParameters(VariantNoPrefix) err = %v, want nil", err)
	}
	noPrefixPrivKey, err := tinkmldsa.NewPrivateKey(
		secretdata.NewBytesFromData(seedBytes, insecuresecretdataaccess.Token{}),
		0,
		noPrefixParams,
	)
	if err != nil {
		t.Fatalf("tinkmldsa.NewPrivateKey() err = %v, want nil", err)
	}
	noPrefixPubKey, err := noPrefixPrivKey.PublicKey()
	if err != nil {
		t.Fatalf("noPrefixPrivKey.PublicKey() err = %v, want nil", err)
	}

	if _, err := mldsa.NewPrehash(noPrefixPubKey.(*tinkmldsa.PublicKey), internalapi.Token{}); err == nil {
		t.Errorf("mldsa.NewPrehash(noPrefixPubKey) err = nil, want error")
	}
}

func TestNewPrehashSucceedsForNonNoPrefixVariants(t *testing.T) {
	seedBytes, _ := hex.DecodeString(privKey65SeedHex)
	for _, variant := range []tinkmldsa.Variant{
		tinkmldsa.VariantTink,
		tinkmldsa.VariantNoPrefixWithPrehashID,
	} {
		t.Run(variant.String(), func(t *testing.T) {
			params, err := tinkmldsa.NewParameters(tinkmldsa.MLDSA65, variant)
			if err != nil {
				t.Fatalf("tinkmldsa.NewParameters(%v) err = %v, want nil", variant, err)
			}
			privKey, err := tinkmldsa.NewPrivateKey(
				secretdata.NewBytesFromData(seedBytes, insecuresecretdataaccess.Token{}),
				12345,
				params,
			)
			if err != nil {
				t.Fatalf("tinkmldsa.NewPrivateKey() err = %v, want nil", err)
			}
			pubKey, err := privKey.PublicKey()
			if err != nil {
				t.Fatalf("privKey.PublicKey() err = %v, want nil", err)
			}

			if _, err := mldsa.NewPrehash(pubKey.(*tinkmldsa.PublicKey), internalapi.Token{}); err != nil {
				t.Errorf("mldsa.NewPrehash(%v) err = %v, want nil", variant, err)
			}
		})
	}
}

func TestComputePrehash(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance tinkmldsa.Instance
		variant  tinkmldsa.Variant
		seedHex  string
		keyID    uint32
		data     []byte
		wantHex  string
	}{
		{
			name:     "ML-DSA-44 prehash test message",
			instance: tinkmldsa.MLDSA44,
			variant:  tinkmldsa.VariantNoPrefixWithPrehashID,
			seedHex:  privKey44SeedHex,
			keyID:    0x01020304,
			data:     []byte("test message"),
			wantHex:  "ff0102030453f84bf56586f50685133f76896c1186d9d44c8cfad6d40d027bf44151852b5e20a38b82f6a725e26f1fdeb1358a874132a46b4376751d4a487e6184b69b009b",
		},
		{
			name:     "ML-DSA-65 prehash test message",
			instance: tinkmldsa.MLDSA65,
			variant:  tinkmldsa.VariantNoPrefixWithPrehashID,
			seedHex:  privKey65SeedHex,
			keyID:    0x12345678,
			data:     []byte("hello world"),
			wantHex:  "ff123456780c970fce4b97eea9bbdf1a95fae39af4f7351cfa744221305428c7136f904110c225c26d8b6cb3e0b4bc0602e185791e232c7cf5e994ec00843fae3e3fe828f7",
		},
		{
			name:     "ML-DSA-87 prehash empty message",
			instance: tinkmldsa.MLDSA87,
			variant:  tinkmldsa.VariantNoPrefixWithPrehashID,
			seedHex:  privKey87SeedHex,
			keyID:    0xdeadbeef,
			data:     []byte(""),
			wantHex:  "ffdeadbeef5bab747309f58b83d7361d6fcad44aa3e6b3cfce96deb9641d8ef71acb1f2a4e2448841dcf23b9190001811d241069dd882ffd8cd1d097d943711b74f7fa70bb",
		},
		{
			name:     "ML-DSA-65 prehash Tink variant",
			instance: tinkmldsa.MLDSA65,
			variant:  tinkmldsa.VariantTink,
			seedHex:  privKey65SeedHex,
			keyID:    0x12345678,
			data:     []byte("hello world"),
			wantHex:  "ff123456780c970fce4b97eea9bbdf1a95fae39af4f7351cfa744221305428c7136f904110c225c26d8b6cb3e0b4bc0602e185791e232c7cf5e994ec00843fae3e3fe828f7",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := tinkmldsa.NewParameters(tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("tinkmldsa.NewParameters() err = %v, want nil", err)
			}
			seedBytes, err := hex.DecodeString(tc.seedHex)
			if err != nil {
				t.Fatalf("hex.DecodeString() err = %v, want nil", err)
			}
			privKey, err := tinkmldsa.NewPrivateKey(
				secretdata.NewBytesFromData(seedBytes, insecuresecretdataaccess.Token{}),
				tc.keyID,
				params,
			)
			if err != nil {
				t.Fatalf("tinkmldsa.NewPrivateKey() err = %v, want nil", err)
			}
			pubKey, err := privKey.PublicKey()
			if err != nil {
				t.Fatalf("privKey.PublicKey() err = %v, want nil", err)
			}

			prehash, err := mldsa.NewPrehash(pubKey.(*tinkmldsa.PublicKey), internalapi.Token{})
			if err != nil {
				t.Fatalf("mldsa.NewPrehash() err = %v, want nil", err)
			}

			gotPayload, err := prehash.ComputePrehash(tc.data)
			if err != nil {
				t.Fatalf("prehash.ComputePrehash() err = %v, want nil", err)
			}

			wantPayload, err := hex.DecodeString(tc.wantHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(tc.wantHex) err = %v, want nil", err)
			}

			if !bytes.Equal(gotPayload, wantPayload) {
				t.Errorf("ComputePrehash() = %x, want %x", gotPayload, wantPayload)
			}

			// Determinism check: computing again with same input produces exact same output.
			gotPayload2, err := prehash.ComputePrehash(tc.data)
			if err != nil {
				t.Fatalf("prehash.ComputePrehash() 2nd run err = %v, want nil", err)
			}
			if !bytes.Equal(gotPayload, gotPayload2) {
				t.Errorf("deterministic check failed: %x != %x", gotPayload, gotPayload2)
			}
		})
	}
}

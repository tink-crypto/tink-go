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

package mldsa_test

import (
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
)

func TestVerifyFails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance tinkmldsa.Instance
		variant  tinkmldsa.Variant
	}{
		{
			name:     "TINK",
			instance: tinkmldsa.MLDSA65,
			variant:  tinkmldsa.VariantTink,
		},
		{
			name:     "RAW",
			instance: tinkmldsa.MLDSA65,
			variant:  tinkmldsa.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv := keyGen(t, tc.instance)
			publicKey, privateKey := keyPair(t, pub, priv, tc.variant)
			signer, err := tinkmldsa.NewSigner(privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewSigner(%v, internalapi.Token{}) err = %v, want nil", privateKey, err)
			}
			verifier, err := tinkmldsa.NewVerifier(publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewVerifier(%v, internalapi.Token{}) err = %v, want nil", publicKey, err)
			}
			data := random.GetRandomBytes(20)
			signature, err := signer.Sign(data)
			if err != nil {
				t.Fatalf("signer.Sign(%x) err = %v, want nil", data, err)
			}

			prefix := signature[:len(publicKey.OutputPrefix())]
			rawSignature := signature[len(publicKey.OutputPrefix()):]

			// Modify the prefix.
			for i := 0; i < len(prefix); i++ {
				modifiedPrefix := slices.Clone(prefix)
				for j := 0; j < 8; j++ {
					modifiedPrefix[i] = byte(modifiedPrefix[i] ^ (1 << uint32(j)))
					s := slices.Concat(modifiedPrefix, rawSignature)
					if err := verifier.Verify(s, data); err == nil {
						t.Errorf("verifier.Verify(%x, data) err = nil, want error", s)
					}
				}
			}
			// Modify the signature.
			// This is slow, so we do not test every possible bit flip.
			for i := 0; i < len(rawSignature); i++ {
				modifiedRawSignature := slices.Clone(rawSignature)
				mask := byte(1 + random.GetRandomUint32()&0xFE)
				modifiedRawSignature[i] = byte(modifiedRawSignature[i] ^ mask)
				s := slices.Concat(prefix, modifiedRawSignature)
				if err := verifier.Verify(s, data); err == nil {
					t.Errorf("verifier.Verify(%x, data) err = nil, want error", s)
				}
			}
			// Modify the message.
			for i := 0; i < len(data); i++ {
				modifiedData := slices.Clone(data)
				for j := 0; j < 8; j++ {
					modifiedData[i] = byte(modifiedData[i] ^ (1 << uint32(j)))
					if err := verifier.Verify(signature, modifiedData); err == nil {
						t.Errorf("verifier.Verify(signature, %x) err = nil, want error", modifiedData)
					}
				}
			}
		})
	}
}

func TestSignVerify(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance tinkmldsa.Instance
		variant  tinkmldsa.Variant
	}{
		{
			name:     "TINK",
			instance: tinkmldsa.MLDSA65,
			variant:  tinkmldsa.VariantTink,
		},
		{
			name:     "RAW",
			instance: tinkmldsa.MLDSA65,
			variant:  tinkmldsa.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv := keyGen(t, tc.instance)
			publicKey, privateKey := keyPair(t, pub, priv, tc.variant)
			signer, err := tinkmldsa.NewSigner(privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewSigner(%v, internalapi.Token{}) err = %v, want nil", privateKey, err)
			}
			verifier, err := tinkmldsa.NewVerifier(publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewVerifier(%v, internalapi.Token{}) err = %v, want nil", publicKey, err)
			}
			for i := 0; i < 100; i++ {
				data := random.GetRandomBytes(20)
				signatureBytes, err := signer.Sign(data)
				if err != nil {
					t.Fatalf("signer.Sign(%x) err = %v, want nil", data, err)
				}
				if err := verifier.Verify(signatureBytes, data); err != nil {
					t.Errorf("verifier.Verify(%x, %x) err = %v, want nil", signatureBytes, data, err)
				}
			}
		})
	}
}

func keyGen(t *testing.T, instance tinkmldsa.Instance) (*mldsa.PublicKey, *mldsa.SecretKey) {
	switch instance {
	case tinkmldsa.MLDSA65:
		return mldsa.MLDSA65.KeyGen()
	default:
		t.Fatalf("unsupported instance: %v", instance)
		return nil, nil
	}
}

func keyPair(t *testing.T, pub *mldsa.PublicKey, priv *mldsa.SecretKey, variant tinkmldsa.Variant) (*tinkmldsa.PublicKey, *tinkmldsa.PrivateKey) {
	params, err := tinkmldsa.NewParameters(tinkmldsa.MLDSA65, variant)
	if err != nil {
		t.Fatalf("tinkmldsa.NewParameters(%v) err = %v, want nil", variant, err)
	}
	idRequirement := uint32(0x01020304)
	if variant == tinkmldsa.VariantNoPrefix {
		idRequirement = 0
	}
	pubBytes := pub.Encode()
	pubKey, err := tinkmldsa.NewPublicKey(pubBytes, idRequirement, params)
	if err != nil {
		t.Fatalf("tinkmldsa.NewPublicKey(%v, %v	, %v) err = %v, want nil", pubBytes, idRequirement, params, err)
	}
	privBytes := priv.Seed()
	privKey, err := tinkmldsa.NewPrivateKey(secretdata.NewBytesFromData(privBytes[:], insecuresecretdataaccess.Token{}), idRequirement, params)
	if err != nil {
		t.Fatalf("tinkmldsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", privBytes, idRequirement, params, err)
	}
	return pubKey, privKey
}

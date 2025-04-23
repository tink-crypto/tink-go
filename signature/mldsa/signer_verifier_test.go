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
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
)

func TestSignVerifyManager(t *testing.T) {
	message := random.GetRandomBytes(20)
	for _, tc := range []struct {
		name          string
		instance      tinkmldsa.Instance
		variant       tinkmldsa.Variant
		idRequirement uint32
	}{
		{
			name:          "TINK",
			instance:      tinkmldsa.MLDSA65,
			variant:       tinkmldsa.VariantTink,
			idRequirement: uint32(0x01020304),
		},
		{
			name:          "RAW",
			instance:      tinkmldsa.MLDSA65,
			variant:       tinkmldsa.VariantNoPrefix,
			idRequirement: uint32(0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := tinkmldsa.NewParameters(tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("tinkmldsa.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			publicKeyBytes, privateKeyBytes := getTestKeyPair(t, tc.instance)
			publicKey, err := tinkmldsa.NewPublicKey(publicKeyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("tinkmldsa.NewPublicKey(%v, %v, %v) err = %v, want nil", publicKeyBytes, tc.idRequirement, params, err)
			}
			privateKey, err := tinkmldsa.NewPrivateKey(secretdata.NewBytesFromData(privateKeyBytes, insecuresecretdataaccess.Token{}), tc.idRequirement, params)
			if err != nil {
				t.Fatalf("tinkmldsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", privateKeyBytes, tc.idRequirement, params, err)
			}

			// Signer verifier from keys.
			signer, err := tinkmldsa.NewSigner(privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewSigner(%v, internalapi.Token{}) err = %v, want nil", privateKey, err)
			}
			sigBytes, err := signer.Sign(message)
			if err != nil {
				t.Fatalf("signer.Sign(%x) err = %v, want nil", message, err)
			}

			verifier, err := tinkmldsa.NewVerifier(publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewVerifier(%v, internalapi.Token{}) err = %v, want nil", publicKey, err)
			}
			if err := verifier.Verify(sigBytes, message); err != nil {
				t.Errorf("verifier.Verify(%x, %x) err = %v, want nil", sigBytes, message, err)
			}

			// Signer verifier from keyset handle.
			km := keyset.NewManager()
			keyID, err := km.AddKey(privateKey)
			if err != nil {
				t.Fatalf("km.AddKey(%v) err = %v, want nil", privateKey, err)
			}
			if err := km.SetPrimary(keyID); err != nil {
				t.Fatalf("km.SetPrimary(%v) err = %v, want nil", keyID, err)
			}
			keysetHandle, err := km.Handle()
			if err != nil {
				t.Fatalf("km.Handle() err = %v, want nil", err)
			}
			publicKeysetHandle, err := keysetHandle.Public()
			if err != nil {
				t.Fatalf("keysetHandle.Public() err = %v, want nil", err)
			}

			signerFromKeyset, err := signature.NewSigner(keysetHandle)
			if err != nil {
				t.Fatalf("signature.NewSigner(%v) err = %v, want nil", keysetHandle, err)
			}
			sigBytesFromKeyset, err := signerFromKeyset.Sign(message)
			if err != nil {
				t.Fatalf("signerFromKeyset.Sign(%x) err = %v, want nil", message, err)
			}

			verifierFromKeyset, err := signature.NewVerifier(publicKeysetHandle)
			if err != nil {
				t.Fatalf("signature.NewVerifier() err = %v, want nil", err)
			}
			if err := verifierFromKeyset.Verify(sigBytesFromKeyset, message); err != nil {
				t.Errorf("verifierFromKeyset.Verify(%x, %x) err = %v, want nil", sigBytesFromKeyset, message, err)
			}
		})
	}
}

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
			seed := random.GetRandomBytes(32)
			params, err := tinkmldsa.NewParameters(tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("tinkmldsa.NewParameters(%v, %v) err = %v, want nil", tc.instance, tc.variant, err)
			}
			privateKey, err := tinkmldsa.NewPrivateKey(secretdata.NewBytesFromData(seed, insecuresecretdataaccess.Token{}), 0, params)
			if err != nil {
				t.Fatalf("tinkmldsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", seed, 0, params, err)
			}
			publicKey, _ := privateKey.PublicKey()
			mldsaPublicKey, ok := publicKey.(*tinkmldsa.PublicKey)
			if !ok {
				t.Fatalf("privateKey.PublicKey() is not a *tinkmldsa.PublicKey")
			}
			signer, err := tinkmldsa.NewSigner(privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewSigner(%v, internalapi.Token{}) err = %v, want nil", privateKey, err)
			}
			verifier, err := tinkmldsa.NewVerifier(mldsaPublicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewVerifier(%v, internalapi.Token{}) err = %v, want nil", mldsaPublicKey, err)
			}
			data := random.GetRandomBytes(20)
			signature, err := signer.Sign(data)
			if err != nil {
				t.Fatalf("signer.Sign(%x) err = %v, want nil", data, err)
			}

			prefix := signature[:len(mldsaPublicKey.OutputPrefix())]
			rawSignature := signature[len(mldsaPublicKey.OutputPrefix()):]

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

func TestSignVerifyCorrectness(t *testing.T) {
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
			seed := random.GetRandomBytes(32)
			params, err := tinkmldsa.NewParameters(tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("tinkmldsa.NewParameters(%v, %v) err = %v, want nil", tc.instance, tc.variant, err)
			}
			privateKey, err := tinkmldsa.NewPrivateKey(secretdata.NewBytesFromData(seed, insecuresecretdataaccess.Token{}), 0, params)
			if err != nil {
				t.Fatalf("tinkmldsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", seed, 0, params, err)
			}
			publicKey, _ := privateKey.PublicKey()
			mldsaPublicKey, ok := publicKey.(*tinkmldsa.PublicKey)
			if !ok {
				t.Fatalf("privateKey.PublicKey() is not a *tinkmldsa.PublicKey")
			}
			signer, err := tinkmldsa.NewSigner(privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewSigner(%v, internalapi.Token{}) err = %v, want nil", privateKey, err)
			}
			verifier, err := tinkmldsa.NewVerifier(mldsaPublicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewVerifier(%v, internalapi.Token{}) err = %v, want nil", mldsaPublicKey, err)
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

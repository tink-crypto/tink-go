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

package slhdsa_test

import (
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/signature/slhdsa"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature"
	tinkslhdsa "github.com/tink-crypto/tink-go/v2/signature/slhdsa"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
)

func TestSignVerifyManager(t *testing.T) {
	message := random.GetRandomBytes(20)
	for _, tc := range []struct {
		name          string
		hashType      tinkslhdsa.HashType
		keySize       int
		sigType       tinkslhdsa.SignatureType
		variant       tinkslhdsa.Variant
		idRequirement uint32
	}{
		{
			name:          "TINK SHA2-128s",
			hashType:      tinkslhdsa.SHA2,
			keySize:       64,
			sigType:       tinkslhdsa.SmallSignature,
			variant:       tinkslhdsa.VariantTink,
			idRequirement: uint32(0x01020304),
		},
		{
			name:          "RAW SHA2-128s",
			hashType:      tinkslhdsa.SHA2,
			keySize:       64,
			sigType:       tinkslhdsa.SmallSignature,
			variant:       tinkslhdsa.VariantNoPrefix,
			idRequirement: uint32(0),
		},
		{
			name:          "TINK SHAKE-256f",
			hashType:      tinkslhdsa.SHAKE,
			keySize:       128,
			sigType:       tinkslhdsa.FastSigning,
			variant:       tinkslhdsa.VariantTink,
			idRequirement: uint32(0x01020304),
		},
		{
			name:          "RAW SHAKE-256f",
			hashType:      tinkslhdsa.SHAKE,
			keySize:       128,
			sigType:       tinkslhdsa.FastSigning,
			variant:       tinkslhdsa.VariantNoPrefix,
			idRequirement: uint32(0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := tinkslhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant)
			if err != nil {
				t.Fatalf("tinkslhdsa.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			keyPair := generateTestKeyPair(t, tc.hashType, tc.keySize, tc.sigType)
			publicKey, err := tinkslhdsa.NewPublicKey(keyPair.pubKey, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("tinkslhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyPair.pubKey, tc.idRequirement, params, err)
			}
			privateKey, err := tinkslhdsa.NewPrivateKey(secretdata.NewBytesFromData(keyPair.privKey, testonlyinsecuresecretdataaccess.Token()), tc.idRequirement, params)
			if err != nil {
				t.Fatalf("tinkslhdsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", keyPair.privKey, tc.idRequirement, params, err)
			}

			// Signer verifier from keys.
			signer, err := tinkslhdsa.NewSigner(privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkslhdsa.NewSigner(%v, internalapi.Token{}) err = %v, want nil", privateKey, err)
			}
			sigBytes, err := signer.Sign(message)
			if err != nil {
				t.Fatalf("signer.Sign(%x) err = %v, want nil", message, err)
			}

			verifier, err := tinkslhdsa.NewVerifier(publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkslhdsa.NewVerifier(%v, internalapi.Token{}) err = %v, want nil", publicKey, err)
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

// This test is extremely slow and times out for the large SLH-DSA parameter sets,
// so we only test the fast enough configurations. The verification correctness is
// already tested in the internal implementation for all SLH-DSA configurations.
func TestVerifyFails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType tinkslhdsa.HashType
		keySize  int
		sigType  tinkslhdsa.SignatureType
		variant  tinkslhdsa.Variant
	}{
		{
			name:     "TINK SHA2-128s",
			hashType: tinkslhdsa.SHA2,
			keySize:  64,
			sigType:  tinkslhdsa.SmallSignature,
			variant:  tinkslhdsa.VariantTink,
		},
		{
			name:     "RAW SHA2-128s",
			hashType: tinkslhdsa.SHA2,
			keySize:  64,
			sigType:  tinkslhdsa.SmallSignature,
			variant:  tinkslhdsa.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sk, _ := keyGen(t, tc.hashType, tc.keySize, tc.sigType)
			params, err := tinkslhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant)
			if err != nil {
				t.Fatalf("tinkslhdsa.NewParameters(%v, %v, %v, %v) err = %v, want nil", tc.hashType, tc.keySize, tc.sigType, tc.variant, err)
			}
			privateKey, err := tinkslhdsa.NewPrivateKey(secretdata.NewBytesFromData(sk.Encode(), testonlyinsecuresecretdataaccess.Token()), 0, params)
			if err != nil {
				t.Fatalf("tinkslhdsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", sk.Encode(), 0, params, err)
			}
			publicKey, _ := privateKey.PublicKey()
			slhdsaPublicKey, ok := publicKey.(*tinkslhdsa.PublicKey)
			if !ok {
				t.Fatalf("privateKey.PublicKey() is not a *tinkslhdsa.PublicKey")
			}
			signer, err := tinkslhdsa.NewSigner(privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkslhdsa.NewSigner(%v, internalapi.Token{}) err = %v, want nil", privateKey, err)
			}
			verifier, err := tinkslhdsa.NewVerifier(slhdsaPublicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkslhdsa.NewVerifier(%v, internalapi.Token{}) err = %v, want nil", slhdsaPublicKey, err)
			}
			data := random.GetRandomBytes(10)
			signature, err := signer.Sign(data)
			if err != nil {
				t.Fatalf("signer.Sign(%x) err = %v, want nil", data, err)
			}

			prefix := signature[:len(slhdsaPublicKey.OutputPrefix())]
			rawSignature := signature[len(slhdsaPublicKey.OutputPrefix()):]

			// Modify the prefix.
			// This is slow, so we do not test every possible bit flip.
			for i := 0; i < len(prefix); i++ {
				modifiedPrefix := slices.Clone(prefix)
				mask := byte(1 + random.GetRandomUint32()&0xFE)
				modifiedPrefix[i] = byte(modifiedPrefix[i] ^ mask)
				s := slices.Concat(modifiedPrefix, rawSignature)
				if err := verifier.Verify(s, data); err == nil {
					t.Errorf("verifier.Verify(%x, data) err = nil, want error", s)
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
			// This is slow, so we do not test every possible bit flip.
			for i := 0; i < len(data); i++ {
				modifiedData := slices.Clone(data)
				mask := byte(1 + random.GetRandomUint32()&0xFE)
				modifiedData[i] = byte(modifiedData[i] ^ mask)
				if err := verifier.Verify(signature, modifiedData); err == nil {
					t.Errorf("verifier.Verify(signature, %x) err = nil, want error", modifiedData)
				}
			}
		})
	}
}

func TestSignVerifyCorrectness(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType tinkslhdsa.HashType
		keySize  int
		sigType  tinkslhdsa.SignatureType
		variant  tinkslhdsa.Variant
	}{
		{
			name:     "TINK SHA2-128s",
			hashType: tinkslhdsa.SHA2,
			keySize:  64,
			sigType:  tinkslhdsa.SmallSignature,
			variant:  tinkslhdsa.VariantTink,
		},
		{
			name:     "RAW SHA2-128s",
			hashType: tinkslhdsa.SHA2,
			keySize:  64,
			sigType:  tinkslhdsa.SmallSignature,
			variant:  tinkslhdsa.VariantNoPrefix,
		},
		{
			name:     "TINK SHAKE-256f",
			hashType: tinkslhdsa.SHAKE,
			keySize:  128,
			sigType:  tinkslhdsa.FastSigning,
			variant:  tinkslhdsa.VariantTink,
		},
		{
			name:     "RAW SHAKE-256f",
			hashType: tinkslhdsa.SHAKE,
			keySize:  128,
			sigType:  tinkslhdsa.FastSigning,
			variant:  tinkslhdsa.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sk, _ := keyGen(t, tc.hashType, tc.keySize, tc.sigType)
			params, err := tinkslhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant)
			if err != nil {
				t.Fatalf("tinkslhdsa.NewParameters(%v, %v, %v, %v) err = %v, want nil", tc.hashType, tc.keySize, tc.sigType, tc.variant, err)
			}
			privateKey, err := tinkslhdsa.NewPrivateKey(secretdata.NewBytesFromData(sk.Encode(), testonlyinsecuresecretdataaccess.Token()), 0, params)
			if err != nil {
				t.Fatalf("tinkslhdsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", sk.Encode(), 0, params, err)
			}
			publicKey, _ := privateKey.PublicKey()
			slhdsaPublicKey, ok := publicKey.(*tinkslhdsa.PublicKey)
			if !ok {
				t.Fatalf("privateKey.PublicKey() is not a *tinkslhdsa.PublicKey")
			}
			signer, err := tinkslhdsa.NewSigner(privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkslhdsa.NewSigner(%v, internalapi.Token{}) err = %v, want nil", privateKey, err)
			}
			verifier, err := tinkslhdsa.NewVerifier(slhdsaPublicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkslhdsa.NewVerifier(%v, internalapi.Token{}) err = %v, want nil", slhdsaPublicKey, err)
			}
			// This is slow, so we limit the number of iterations.
			for i := 0; i < 10; i++ {
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

func keyGen(t *testing.T, hashType tinkslhdsa.HashType, keySize int, sigType tinkslhdsa.SignatureType) (*slhdsa.SecretKey, *slhdsa.PublicKey) {
	if hashType == tinkslhdsa.SHA2 && keySize == 64 && sigType == tinkslhdsa.SmallSignature {
		return slhdsa.SLH_DSA_SHA2_128s.KeyGen()
	}
	if hashType == tinkslhdsa.SHAKE && keySize == 128 && sigType == tinkslhdsa.FastSigning {
		return slhdsa.SLH_DSA_SHAKE_256f.KeyGen()
	}
	t.Fatalf("unsupported parameters: %v, %v, %v", hashType, keySize, sigType)
	return nil, nil
}

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

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/signature/slhdsa"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	tinkslhdsa "github.com/tink-crypto/tink-go/v2/signature/slhdsa"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
)

func TestVerifyFails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType tinkslhdsa.HashType
		keySize  int
		sigType  tinkslhdsa.SignatureType
		variant  tinkslhdsa.Variant
	}{
		{
			name:     "TINK",
			hashType: tinkslhdsa.SHA2,
			keySize:  64,
			sigType:  tinkslhdsa.SmallSignature,
			variant:  tinkslhdsa.VariantTink,
		},
		{
			name:     "RAW",
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
			privateKey, err := tinkslhdsa.NewPrivateKey(secretdata.NewBytesFromData(sk.Encode(), insecuresecretdataaccess.Token{}), 0, params)
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
			name:     "TINK",
			hashType: tinkslhdsa.SHA2,
			keySize:  64,
			sigType:  tinkslhdsa.SmallSignature,
			variant:  tinkslhdsa.VariantTink,
		},
		{
			name:     "RAW",
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
			privateKey, err := tinkslhdsa.NewPrivateKey(secretdata.NewBytesFromData(sk.Encode(), insecuresecretdataaccess.Token{}), 0, params)
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
	t.Fatalf("unsupported parameters: %v, %v, %v", hashType, keySize, sigType)
	return nil, nil
}

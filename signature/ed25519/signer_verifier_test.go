// Copyright 2020 Google LLC
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

package ed25519_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/testing/wycheproof"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	tinked25519 "github.com/tink-crypto/tink-go/v2/signature/ed25519"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil"
)

func TestSignVerifyCorrectness(t *testing.T) {
	// Taken from https://datatracker.ietf.org/doc/html/rfc8032#section-7.1 - TEST 3.
	message := []byte{0xaf, 0x82}
	signatureHex := "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
	signatureLegacyHex := "afeae7a4fcd7d710a03353dfbe11a9906c6918633bb4dfef655d62d21f7535a1108ea3ef5bef2b0d0acefbf0e051f62ee2582652ae769df983ad1b11a95d3a08"
	wantSignature, err := hex.DecodeString(signatureHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", signatureHex, err)
	}
	wantLegacySignature, err := hex.DecodeString(signatureLegacyHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", signatureHex, err)
	}
	tinkPrefix := []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04}
	crunchyAndLefacyPrefix := []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04}
	for _, tc := range []struct {
		name          string
		variant       tinked25519.Variant
		idRequirement uint32
		signature     []byte
	}{

		{
			name:          "TINK",
			variant:       tinked25519.VariantTink,
			idRequirement: uint32(0x01020304),
			signature:     slices.Concat(tinkPrefix, wantSignature),
		},
		{
			name:          "CRUNCHY",
			variant:       tinked25519.VariantCrunchy,
			idRequirement: uint32(0x01020304),
			signature:     slices.Concat(crunchyAndLefacyPrefix, wantSignature),
		},
		{
			name:          "RAW",
			variant:       tinked25519.VariantNoPrefix,
			idRequirement: uint32(0),
			signature:     wantSignature,
		},
		{
			name:          "LEGACY",
			variant:       tinked25519.VariantLegacy,
			idRequirement: uint32(0x01020304),
			signature:     slices.Concat(crunchyAndLefacyPrefix, wantLegacySignature),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := tinked25519.NewParameters(tc.variant)
			if err != nil {
				t.Fatalf("tinked25519.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			publicKeyBytes, privateKeyBytes := getTestKeyPair(t)
			publicKey, err := tinked25519.NewPublicKey(publicKeyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("tinked25519.NewPublicKey(%v, %v, %v) err = %v, want nil", publicKeyBytes, tc.idRequirement, params, err)
			}
			privateKey, err := tinked25519.NewPrivateKey(secretdata.NewBytesFromData(privateKeyBytes, insecuresecretdataaccess.Token{}), tc.idRequirement, params)
			if err != nil {
				t.Fatalf("tinked25519.NewPrivateKey(%v, %v, %v) err = %v, want nil", privateKeyBytes, tc.idRequirement, params, err)
			}

			// Signer verifier from keys.
			signer, err := tinked25519.NewSigner(privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinked25519.NewSigner(%v, internalapi.Token{}) err = %v, want nil", privateKey, err)
			}
			gotSignature, err := signer.Sign(message)
			if err != nil {
				t.Fatalf("signer.Sign(%x) err = %v, want nil", message, err)
			}
			if diff := cmp.Diff(gotSignature, tc.signature); diff != "" {
				t.Errorf("signer.Sign() returned unexpected diff (-want +got):\n%s", diff)
			}

			verifier, err := tinked25519.NewVerifier(publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinked25519.NewVerifier(%v, internalapi.Token{}) err = %v, want nil", publicKey, err)
			}
			if err := verifier.Verify(tc.signature, message); err != nil {
				t.Errorf("verifier.Verify(%x, %x) err = %v, want nil", tc.signature, message, err)
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
			gotSignatureFromKeyset, err := signerFromKeyset.Sign(message)
			if err != nil {
				t.Fatalf("signerFromKeyset.Sign(%x) err = %v, want nil", message, err)
			}
			if diff := cmp.Diff(gotSignatureFromKeyset, tc.signature); diff != "" {
				t.Errorf("signerFromKeyset.Sign() returned unexpected diff (-want +got):\n%s", diff)
			}

			verifierFromKeyset, err := signature.NewVerifier(publicKeysetHandle)
			if err != nil {
				t.Fatalf("tinked25519.NewVerifier() err = %v, want nil", err)
			}
			if err := verifierFromKeyset.Verify(tc.signature, message); err != nil {
				t.Errorf("verifierFromKeyset.Verify(%x, %x) err = %v, want nil", tc.signature, message, err)
			}
		})
	}
}

func TestVerifyFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		variant tinked25519.Variant
	}{
		{
			name:    "TINK",
			variant: tinked25519.VariantTink,
		},
		{
			name:    "CRUNCHY",
			variant: tinked25519.VariantCrunchy,
		},
		{
			name:    "LEGACY",
			variant: tinked25519.VariantLegacy,
		},
		{
			name:    "RAW",
			variant: tinked25519.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			public, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("key generation error: %s", err)
			}
			publicKey, privateKey := keyPair(t, public, priv, tc.variant)
			signer, err := tinked25519.NewSigner(privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinked25519.NewSigner(%v, internalapi.Token{}) err = %v, want nil", privateKey, err)
			}
			verifier, err := tinked25519.NewVerifier(publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinked25519.NewVerifier(%v, internalapi.Token{}) err = %v, want nil", publicKey, err)
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
			for i := 0; i < len(rawSignature); i++ {
				modifiedRawSignature := slices.Clone(rawSignature)
				for j := 0; j < 8; j++ {
					modifiedRawSignature[i] = byte(modifiedRawSignature[i] ^ (1 << uint32(j)))
					s := slices.Concat(prefix, modifiedRawSignature)
					if err := verifier.Verify(s, data); err == nil {
						t.Errorf("verifier.Verify(%x, data) err = nil, want error", s)
					}
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
	public, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation error: %s", err)
	}
	publicKey, privateKey := keyPair(t, public, priv, tinked25519.VariantNoPrefix)
	signer, err := tinked25519.NewSigner(privateKey, internalapi.Token{})
	if err != nil {
		t.Fatalf("tinked25519.NewSigner(%v, internalapi.Token{}) err = %v, want nil", privateKey, err)
	}
	verifier, err := tinked25519.NewVerifier(publicKey, internalapi.Token{})
	if err != nil {
		t.Fatalf("tinked25519.NewVerifier(%v, internalapi.Token{}) err = %v, want nil", publicKey, err)
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
}

type ed25519Suite struct {
	wycheproof.Suite
	TestGroups []*ed25519Group `json:"testGroups"`
}

type ed25519Group struct {
	wycheproof.Group
	PublicKeyDER string          `json:"publicKeyDer"`
	PublicKeyPEM string          `json:"publicKeyPem"`
	SHA          string          `json:"sha"`
	PublicKey    *ed25519TestKey `json:"publicKey"`
	Tests        []*ed25519Case  `json:"tests"`
}

type ed25519Case struct {
	wycheproof.Case
	Message   testutil.HexBytes `json:"msg"`
	Signature testutil.HexBytes `json:"sig"`
}

type ed25519TestKey struct {
	PK testutil.HexBytes `json:"pk"`
}

func TestWycheproof(t *testing.T) {
	suite := new(ed25519Suite)
	wycheproof.PopulateSuiteV1(t, suite, "ed25519_test.json")

	for _, group := range suite.TestGroups {
		public := ed25519.PublicKey(group.PublicKey.PK)
		variant := tinked25519.VariantNoPrefix
		idRequirement := uint32(0)
		params, err := tinked25519.NewParameters(variant)
		if err != nil {
			t.Fatalf("tinked25519.NewParameters(%v) err = %v, want nil", variant, err)
		}
		publicKey, err := tinked25519.NewPublicKey(public, idRequirement, params)
		if err != nil {
			t.Fatalf("tinked25519.NewPublicKey(%v, %v, %v) err = %v, want nil", public, idRequirement, params, err)
		}

		verifier, err := tinked25519.NewVerifier(publicKey, internalapi.Token{})
		if err != nil {
			continue
		}
		for _, test := range group.Tests {
			caseName := fmt.Sprintf("Verify-%s-%s:Case-%d", suite.Algorithm, group.Type, test.CaseID)
			t.Run(caseName, func(t *testing.T) {
				err := verifier.Verify(test.Signature, test.Message)
				switch test.Result {
				case "valid":
					if err != nil {
						t.Fatalf("ED25519Verifier.Verify() failed in a valid test case: %v", err)
					}
				case "invalid":
					if err == nil {
						t.Fatal("ED25519Verifier.Verify() succeeded in an invalid test case.")
					}
				default:
					t.Fatalf("unsupported test result: %q", test.Result)
				}
			})
		}
	}
}

func keyPair(t *testing.T, public, priv []byte, variant tinked25519.Variant) (*tinked25519.PublicKey, *tinked25519.PrivateKey) {
	params, err := tinked25519.NewParameters(variant)
	if err != nil {
		t.Fatalf("tinked25519.NewParameters(%v) err = %v, want nil", variant, err)
	}
	idRequirement := uint32(0x01020304)
	if variant == tinked25519.VariantNoPrefix {
		idRequirement = 0
	}
	pubKey, err := tinked25519.NewPublicKey(public, idRequirement, params)
	if err != nil {
		t.Fatalf("tinked25519.NewPublicKey(%v, %v	, %v) err = %v, want nil", public, idRequirement, params, err)
	}
	privKey, err := tinked25519.NewPrivateKey(secretdata.NewBytesFromData(priv[:32], insecuresecretdataaccess.Token{}), idRequirement, params)
	if err != nil {
		t.Fatalf("tinked25519.NewPrivateKey(%v, %v, %v) err = %v, want nil", priv[:32], idRequirement, params, err)
	}
	return pubKey, privKey
}

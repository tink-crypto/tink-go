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

package subtle_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	subtleSignature "github.com/tink-crypto/tink-go/v2/signature/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestED25519SignVerifyCorrectness(t *testing.T) {
	// Taken from https://datatracker.ietf.org/doc/html/rfc8032#section-7.1 - TEST 3.
	message := []byte{0xaf, 0x82}
	privKeyHex := "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
	privKeySeed, err := hex.DecodeString(privKeyHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", privKeyHex, err)
	}
	privateKey := ed25519.NewKeyFromSeed(privKeySeed)
	pubKeyHex := "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", pubKeyHex, err)
	}
	publicKey := ed25519.PublicKey(pubKeyBytes)
	signatureHex := "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
	wantSignature, err := hex.DecodeString(signatureHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", signatureHex, err)
	}

	signer, err := subtleSignature.NewED25519SignerFromPrivateKey(&privateKey)
	if err != nil {
		t.Fatalf("unexpected error when creating ED25519 Signer: %s", err)
	}
	verifier, err := subtleSignature.NewED25519VerifierFromPublicKey(&publicKey)
	if err != nil {
		t.Fatalf("unexpected error when creating ED25519 Verifier: %s", err)
	}

	gotSignature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("signer.Sign(%x) err = %v, want nil", message, err)
	}
	if diff := cmp.Diff(gotSignature, wantSignature); diff != "" {
		t.Errorf("signer.Sign() returned unexpected diff (-want +got):\n%s", diff)
	}

	if err := verifier.Verify(wantSignature, message); err != nil {
		t.Errorf("verifier.Verify(%x, %x) err = %v, want nil", wantSignature, message, err)
	}
}

func TestED25519VerifyFails(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation error: %s", err)
	}
	signer, err := subtleSignature.NewED25519SignerFromPrivateKey(&privateKey)
	if err != nil {
		t.Fatalf("unexpected error when creating ED25519 Signer: %s", err)
	}
	verifier, err := subtleSignature.NewED25519VerifierFromPublicKey(&publicKey)
	if err != nil {
		t.Fatalf("unexpected error when creating ED25519 Verifier: %s", err)
	}
	data := random.GetRandomBytes(20)
	signatureBytes, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("signer.Sign(%x) err = %v, want nil", data, err)
	}

	// Modify the signature.
	for i := 0; i < len(signatureBytes); i++ {
		modifiedRawSignature := slices.Clone(signatureBytes)
		for j := 0; j < 8; j++ {
			modifiedRawSignature[i] = byte(modifiedRawSignature[i] ^ (1 << uint32(j)))
			if err := verifier.Verify(modifiedRawSignature, data); err == nil {
				t.Errorf("verifier.Verify(%x, data) err = nil, want error", modifiedRawSignature)
			}
		}
	}
	// Modify the message.
	for i := 0; i < len(data); i++ {
		modifiedData := slices.Clone(data)
		for j := 0; j < 8; j++ {
			modifiedData[i] = byte(modifiedData[i] ^ (1 << uint32(j)))
			if err := verifier.Verify(signatureBytes, modifiedData); err == nil {
				t.Errorf("verifier.Verify(signature, %x) err = nil, want error", modifiedData)
			}
		}
	}
}

func TestED25519SignVerify(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation error: %s", err)
	}
	for _, tc := range []struct {
		name     string
		signer   tink.Signer
		verifier tink.Verifier
	}{
		{
			name: "signer from private key",
			signer: func() tink.Signer {
				signer, err := subtleSignature.NewED25519SignerFromPrivateKey(&privateKey)
				if err != nil {
					t.Fatalf("unexpected error when creating ED25519 Signer: %s", err)
				}
				return signer
			}(),
			verifier: func() tink.Verifier {
				verifier, err := subtleSignature.NewED25519VerifierFromPublicKey(&publicKey)
				if err != nil {
					t.Fatalf("unexpected error when creating ED25519 Verifier: %s", err)
				}
				return verifier
			}(),
		},
		{
			name: "signer from slice",
			signer: func() tink.Signer {
				signer, err := subtleSignature.NewED25519Signer(privateKey[:ed25519.SeedSize])
				if err != nil {
					t.Fatalf("unexpected error when creating ED25519 Signer: %s", err)
				}
				return signer
			}(),
			verifier: func() tink.Verifier {
				verifier, err := subtleSignature.NewED25519VerifierFromPublicKey(&publicKey)
				if err != nil {
					t.Fatalf("unexpected error when creating ED25519 Verifier: %s", err)
				}
				return verifier
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				data := random.GetRandomBytes(20)
				signatureBytes, err := tc.signer.Sign(data)
				if err != nil {
					t.Fatalf("signer.Sign(%x) err = %v, want nil", data, err)
				}
				if err := tc.verifier.Verify(signatureBytes, data); err != nil {
					t.Errorf("tc.verifier.Verify(%x, %x) err = %v, want nil", signatureBytes, data, err)
				}
			}
		})
	}
}

func TestED25519WycheproofCases(t *testing.T) {
	suite := new(ed25519Suite)
	if err := testutil.PopulateSuite(suite, "eddsa_test.json"); err != nil {
		t.Fatalf("failed populating suite: %s", err)
	}
	for _, group := range suite.TestGroups {
		private := ed25519.PrivateKey(group.Key.SK)
		public := ed25519.PrivateKey(group.Key.PK)
		signer, err := subtleSignature.NewED25519Signer(private)
		if err != nil {
			continue
		}
		verifier, err := subtleSignature.NewED25519Verifier(public)
		if err != nil {
			continue
		}
		for _, test := range group.Tests {
			caseName := fmt.Sprintf("Sign-%s-%s:Case-%d", suite.Algorithm, group.Type, test.CaseID)
			t.Run(caseName, func(t *testing.T) {
				got, err := signer.Sign(test.Message)
				switch test.Result {
				case "valid":
					if err != nil {
						t.Fatalf("ED25519Signer.Sign() failed in a valid test case: %s", err)
					}
					if !bytes.Equal(got, test.Signature) {
						// Ed25519 is deterministic.
						// Getting an alternative signature may leak the private key.
						// This is especially the case if an attacker can also learn the valid signature.
						t.Fatalf("ED25519Signer.Sign() = %s, want = %s", hex.EncodeToString(got), hex.EncodeToString(test.Signature))
					}
				case "invalid":
					if err == nil && bytes.Equal(got, test.Signature) {
						t.Fatalf("ED25519Signer.Sign() produced a matching signature in an invalid test case.")
					}
				default:
					t.Fatalf("unrecognized result: %q", test.Result)
				}
			})

			caseName = fmt.Sprintf("Verify-%s-%s:Case-%d", suite.Algorithm, group.Type, test.CaseID)
			t.Run(caseName, func(t *testing.T) {
				err := verifier.Verify(test.Signature, test.Message)
				switch test.Result {
				case "valid":
					if err != nil {
						t.Fatalf("ED25519Verifier.Verify() failed in a valid test case: %s", err)
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

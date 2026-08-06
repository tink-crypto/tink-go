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
	"encoding/hex"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/testing/wycheproof"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/signprehash/mldsa"
	"github.com/tink-crypto/tink-go/v2/testutil"
)

const (
	signerTestSeed44Hex = "dddaccfaa05b0332b3fd7269c7d42de6cbe370735431f735346ccb6be7ad3174"
	signerTestSeed65Hex = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D"
	signerTestSeed87Hex = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D"
)

func TestNewPrehashSignerFailsForVariantNoPrefix(t *testing.T) {
	seedBytes, _ := hex.DecodeString(signerTestSeed65Hex)
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

	if _, err := mldsa.NewPrehashSigner(noPrefixPrivKey, internalapi.Token{}); err == nil {
		t.Errorf("mldsa.NewPrehashSigner(noPrefixPrivKey) err = nil, want error")
	}
}

func TestNewPrehashSignerSucceedsForNonNoPrefixVariants(t *testing.T) {
	seedBytes, _ := hex.DecodeString(signerTestSeed65Hex)
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

			if _, err := mldsa.NewPrehashSigner(privKey, internalapi.Token{}); err != nil {
				t.Errorf("mldsa.NewPrehashSigner(%v) err = %v, want nil", variant, err)
			}
		})
	}
}

func TestSignPrehashFailureModes(t *testing.T) {
	seedBytes, _ := hex.DecodeString(signerTestSeed65Hex)
	params, err := tinkmldsa.NewParameters(tinkmldsa.MLDSA65, tinkmldsa.VariantNoPrefixWithPrehashID)
	if err != nil {
		t.Fatalf("tinkmldsa.NewParameters() err = %v, want nil", err)
	}
	const keyID uint32 = 0x12345678
	privKey, err := tinkmldsa.NewPrivateKey(
		secretdata.NewBytesFromData(seedBytes, insecuresecretdataaccess.Token{}),
		keyID,
		params,
	)
	if err != nil {
		t.Fatalf("tinkmldsa.NewPrivateKey() err = %v, want nil", err)
	}
	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Fatalf("privKey.PublicKey() err = %v, want nil", err)
	}

	prehasher, err := mldsa.NewPrehash(pubKey.(*tinkmldsa.PublicKey), internalapi.Token{})
	if err != nil {
		t.Fatalf("mldsa.NewPrehash() err = %v, want nil", err)
	}
	prehashSigner, err := mldsa.NewPrehashSigner(privKey, internalapi.Token{})
	if err != nil {
		t.Fatalf("mldsa.NewPrehashSigner() err = %v, want nil", err)
	}

	validPrehash, err := prehasher.ComputePrehash([]byte("test message"))
	if err != nil {
		t.Fatalf("prehasher.ComputePrehash() err = %v, want nil", err)
	}

	// 1. Invalid length
	shortPrehash := validPrehash[:10]
	if _, err := prehashSigner.SignPrehash(shortPrehash); err == nil {
		t.Errorf("SignPrehash(shortPrehash) err = nil, want error")
	}

	// 2. Invalid start byte
	invalidStartByte := make([]byte, len(validPrehash))
	copy(invalidStartByte, validPrehash)
	invalidStartByte[0] = 0x00
	if _, err := prehashSigner.SignPrehash(invalidStartByte); err == nil {
		t.Errorf("SignPrehash(invalidStartByte) err = nil, want error")
	}

	// 3. Key ID mismatch
	mismatchedKeyID := make([]byte, len(validPrehash))
	copy(mismatchedKeyID, validPrehash)
	mismatchedKeyID[1] ^= 0xff
	if _, err := prehashSigner.SignPrehash(mismatchedKeyID); err == nil {
		t.Errorf("SignPrehash(mismatchedKeyID) err = nil, want error")
	}
}

func TestSignPrehashAndVerify(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance tinkmldsa.Instance
		variant  tinkmldsa.Variant
		seedHex  string
		keyID    uint32
		msg      []byte
	}{
		{
			name:     "ML-DSA-44 NoPrefixWithPrehashID",
			instance: tinkmldsa.MLDSA44,
			variant:  tinkmldsa.VariantNoPrefixWithPrehashID,
			seedHex:  signerTestSeed44Hex,
			keyID:    0x01020304,
			msg:      []byte("hello ML-DSA-44"),
		},
		{
			name:     "ML-DSA-65 NoPrefixWithPrehashID",
			instance: tinkmldsa.MLDSA65,
			variant:  tinkmldsa.VariantNoPrefixWithPrehashID,
			seedHex:  signerTestSeed65Hex,
			keyID:    0x12345678,
			msg:      []byte("hello ML-DSA-65"),
		},
		{
			name:     "ML-DSA-87 NoPrefixWithPrehashID",
			instance: tinkmldsa.MLDSA87,
			variant:  tinkmldsa.VariantNoPrefixWithPrehashID,
			seedHex:  signerTestSeed87Hex,
			keyID:    0xdeadbeef,
			msg:      []byte("hello ML-DSA-87"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := tinkmldsa.NewParameters(tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("tinkmldsa.NewParameters() err = %v, want nil", err)
			}
			seedBytes, _ := hex.DecodeString(tc.seedHex)
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

			prehasher, err := mldsa.NewPrehash(pubKey.(*tinkmldsa.PublicKey), internalapi.Token{})
			if err != nil {
				t.Fatalf("mldsa.NewPrehash() err = %v, want nil", err)
			}
			signer, err := mldsa.NewPrehashSigner(privKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("mldsa.NewPrehashSigner() err = %v, want nil", err)
			}
			verifier, err := tinkmldsa.NewVerifier(pubKey.(*tinkmldsa.PublicKey), internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewVerifier() err = %v, want nil", err)
			}

			prehash, err := prehasher.ComputePrehash(tc.msg)
			if err != nil {
				t.Fatalf("prehasher.ComputePrehash() err = %v, want nil", err)
			}

			sig, err := signer.SignPrehash(prehash)
			if err != nil {
				t.Fatalf("signer.SignPrehash() err = %v, want nil", err)
			}

			standardSigner, err := tinkmldsa.NewSigner(privKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewSigner() err = %v, want nil", err)
			}
			standardSig, err := standardSigner.Sign(tc.msg)
			if err != nil {
				t.Fatalf("standardSigner.Sign() err = %v, want nil", err)
			}

			// Verify both prehash signature and standard signature using standard ML-DSA verifier.
			if err := verifier.Verify(sig, tc.msg); err != nil {
				t.Errorf("verifier.Verify(sig, msg) err = %v, want nil", err)
			}
			if err := verifier.Verify(standardSig, tc.msg); err != nil {
				t.Errorf("verifier.Verify(standardSig, msg) err = %v, want nil", err)
			}

			// Verify fails for modified signature
			invalidSig := make([]byte, len(sig))
			copy(invalidSig, sig)
			invalidSig[len(invalidSig)-1] ^= 0xff
			if err := verifier.Verify(invalidSig, tc.msg); err == nil {
				t.Errorf("verifier.Verify(invalidSig, msg) err = nil, want error")
			}

			// Verify fails for modified message
			modifiedMsg := append([]byte(nil), tc.msg...)
			modifiedMsg = append(modifiedMsg, '!')
			if err := verifier.Verify(sig, modifiedMsg); err == nil {
				t.Errorf("verifier.Verify(sig, modifiedMsg) err = nil, want error")
			}
		})
	}
}

func TestWycheproofPrehashSignVerify(t *testing.T) {
	vectors := []struct {
		filename string
		instance tinkmldsa.Instance
	}{
		{
			filename: "mldsa_44_verify_test.json",
			instance: tinkmldsa.MLDSA44,
		},
		{
			filename: "mldsa_65_verify_test.json",
			instance: tinkmldsa.MLDSA65,
		},
		{
			filename: "mldsa_87_verify_test.json",
			instance: tinkmldsa.MLDSA87,
		},
	}

	type wycheproofCase struct {
		wycheproof.Case
		Message   testutil.HexBytes `json:"msg"`
		Signature testutil.HexBytes `json:"sig"`
		Context   testutil.HexBytes `json:"ctx"`
	}

	type wycheproofGroup struct {
		wycheproof.Group
		PublicKey testutil.HexBytes `json:"publicKey"`
		Tests     []*wycheproofCase `json:"tests"`
	}

	type wycheproofSuite struct {
		wycheproof.Suite
		TestGroups []*wycheproofGroup `json:"testGroups"`
	}

	for _, v := range vectors {
		t.Run(v.filename, func(t *testing.T) {
			suite := new(wycheproofSuite)
			wycheproof.PopulateSuiteV1(t, suite, v.filename)

			params, err := tinkmldsa.NewParameters(v.instance, tinkmldsa.VariantNoPrefixWithPrehashID)
			if err != nil {
				t.Fatalf("tinkmldsa.NewParameters() err = %v, want nil", err)
			}
			const keyID uint32 = 0x01020304
			seedBytes, _ := hex.DecodeString(signerTestSeed65Hex)
			privKey, err := tinkmldsa.NewPrivateKey(
				secretdata.NewBytesFromData(seedBytes, insecuresecretdataaccess.Token{}),
				keyID,
				params,
			)
			if err != nil {
				t.Fatalf("tinkmldsa.NewPrivateKey() err = %v, want nil", err)
			}
			pubKey, err := privKey.PublicKey()
			if err != nil {
				t.Fatalf("privKey.PublicKey() err = %v, want nil", err)
			}

			prehasher, err := mldsa.NewPrehash(pubKey.(*tinkmldsa.PublicKey), internalapi.Token{})
			if err != nil {
				t.Fatalf("mldsa.NewPrehash() err = %v, want nil", err)
			}
			prehashSigner, err := mldsa.NewPrehashSigner(privKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("mldsa.NewPrehashSigner() err = %v, want nil", err)
			}
			standardSigner, err := tinkmldsa.NewSigner(privKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewSigner() err = %v, want nil", err)
			}
			verifier, err := tinkmldsa.NewVerifier(pubKey.(*tinkmldsa.PublicKey), internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewVerifier() err = %v, want nil", err)
			}

			for _, group := range suite.TestGroups {
				for _, test := range group.Tests {
					if len(test.Context) != 0 {
						continue
					}
					prehash, err := prehasher.ComputePrehash(test.Message)
					if err != nil {
						t.Fatalf("prehasher.ComputePrehash() err = %v, want nil", err)
					}
					prehashSig, err := prehashSigner.SignPrehash(prehash)
					if err != nil {
						t.Fatalf("prehashSigner.SignPrehash() err = %v, want nil", err)
					}
					standardSig, err := standardSigner.Sign(test.Message)
					if err != nil {
						t.Fatalf("standardSigner.Sign() err = %v, want nil", err)
					}
					// Verify that SignPrehash(ComputePrehash(msg)) generates a signature valid under standard ML-DSA verifier,
					// matching the behavior of standard Sign(msg).
					if err := verifier.Verify(prehashSig, test.Message); err != nil {
						t.Errorf("verifier.Verify(prehashSig, test.Message) err = %v, want nil for test ID %d", err, test.CaseID)
					}
					if err := verifier.Verify(standardSig, test.Message); err != nil {
						t.Errorf("verifier.Verify(standardSig, test.Message) err = %v, want nil for test ID %d", err, test.CaseID)
					}
				}
			}
		})
	}
}

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

package compositemldsa_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	tinkcompositemldsa "github.com/tink-crypto/tink-go/v2/signature/compositemldsa"
	"github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/signature/ed25519"
	"github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapss"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
)

// parametersForClassicalAlgorithm returns the parameters for the given classical algorithm.
func parametersForClassicalAlgorithm(classicalAlgorithm tinkcompositemldsa.ClassicalAlgorithm) (key.Parameters, error) {
	switch classicalAlgorithm {
	case tinkcompositemldsa.Ed25519:
		params, err := ed25519.NewParameters(ed25519.VariantNoPrefix)
		if err != nil {
			return nil, err
		}
		return &params, nil
	case tinkcompositemldsa.ECDSAP256:
		return ecdsa.NewParameters(ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantNoPrefix)
	case tinkcompositemldsa.ECDSAP384:
		return ecdsa.NewParameters(ecdsa.NistP384, ecdsa.SHA384, ecdsa.DER, ecdsa.VariantNoPrefix)
	case tinkcompositemldsa.ECDSAP521:
		return ecdsa.NewParameters(ecdsa.NistP521, ecdsa.SHA512, ecdsa.DER, ecdsa.VariantNoPrefix)
	case tinkcompositemldsa.RSA3072PSS:
		return rsassapss.NewParameters(rsassapss.ParametersValues{
			ModulusSizeBits: 3072,
			SigHashType:     rsassapss.SHA256,
			MGF1HashType:    rsassapss.SHA256,
			PublicExponent:  f4,
			SaltLengthBytes: 32,
		}, rsassapss.VariantNoPrefix)
	case tinkcompositemldsa.RSA4096PSS:
		return rsassapss.NewParameters(rsassapss.ParametersValues{
			ModulusSizeBits: 4096,
			SigHashType:     rsassapss.SHA384,
			MGF1HashType:    rsassapss.SHA384,
			PublicExponent:  f4,
			SaltLengthBytes: 48,
		}, rsassapss.VariantNoPrefix)
	case tinkcompositemldsa.RSA3072PKCS1:
		return rsassapkcs1.NewParameters(3072, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantNoPrefix)
	case tinkcompositemldsa.RSA4096PKCS1:
		return rsassapkcs1.NewParameters(4096, rsassapkcs1.SHA384, f4, rsassapkcs1.VariantNoPrefix)
	default:
		return nil, fmt.Errorf("unsupported classical algorithm: %v", classicalAlgorithm)
	}
}

// parametersForMLDSA returns the parameters for the given ML-DSA instance.
func parametersForMLDSA(mlDSAInstance tinkcompositemldsa.MLDSAInstance) (*mldsa.Parameters, error) {
	switch mlDSAInstance {
	case tinkcompositemldsa.MLDSA65:
		return mldsa.NewParameters(mldsa.MLDSA65, mldsa.VariantNoPrefix)
	case tinkcompositemldsa.MLDSA87:
		return mldsa.NewParameters(mldsa.MLDSA87, mldsa.VariantNoPrefix)
	default:
		return nil, fmt.Errorf("unsupported ML-DSA instance: %v", mlDSAInstance)
	}
}

// This test uses test vectors from compositemldsa_test_vectors_test.go, which were extracted from IEFT draft.
// https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-14#appendix-E.
func createTestPrivateKeyDeterministic(params *tinkcompositemldsa.Parameters, idRequirement uint32) (*tinkcompositemldsa.PrivateKey, []byte, error) {
	mlDsaParams, err := parametersForMLDSA(params.MLDSAInstance())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get ML-DSA parameters: %v", err)
	}
	classicalParams, err := parametersForClassicalAlgorithm(params.ClassicalAlgorithm())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get classical parameters: %v", err)
	}

	var mlDsaSeedHex string
	var classPrivKey key.Key
	var signatureHex string

	switch params.MLDSAInstance() {
	case tinkcompositemldsa.MLDSA65:
		switch params.ClassicalAlgorithm() {
		case tinkcompositemldsa.Ed25519:
			mlDsaSeedHex = hexMlDsa65PrivSeedForEd25519
			signatureHex = hexMlDsa65Ed25519Signature
			classPrivKey, err = ed25519.NewPrivateKey(mustSecretBytes(hexMlDsa65Ed25519Priv), 0, *classicalParams.(*ed25519.Parameters))
		case tinkcompositemldsa.ECDSAP256:
			mlDsaSeedHex = hexMlDsa65PrivSeedForEcdsaP256
			signatureHex = hexMlDsa65EcdsaP256Signature
			classPrivKey, err = ecdsa.NewPrivateKey(mustSecretBytes(hexMlDsa65EcdsaP256Priv), 0, classicalParams.(*ecdsa.Parameters))
		case tinkcompositemldsa.ECDSAP384:
			mlDsaSeedHex = hexMlDsa65PrivSeedForEcdsaP384
			signatureHex = hexMlDsa65EcdsaP384Signature
			classPrivKey, err = ecdsa.NewPrivateKey(mustSecretBytes(hexMlDsa65EcdsaP384Priv), 0, classicalParams.(*ecdsa.Parameters))
		case tinkcompositemldsa.RSA3072PSS:
			mlDsaSeedHex = hexMlDsa65PrivSeedForRsa3072Pss
			signatureHex = hexMlDsa65Rsa3072PssSignature
			var pubKey *rsassapss.PublicKey
			pubKey, err = rsassapss.NewPublicKey(mustHexDecode(hexMlDsa65Rsa3072PssN), 0, classicalParams.(*rsassapss.Parameters))
			if err == nil {
				classPrivKey, err = rsassapss.NewPrivateKey(pubKey, rsassapss.PrivateKeyValues{
					P: mustSecretBytes(hexMlDsa65Rsa3072PssP),
					Q: mustSecretBytes(hexMlDsa65Rsa3072PssQ),
					D: mustSecretBytes(hexMlDsa65Rsa3072PssD),
				})
			}
		case tinkcompositemldsa.RSA4096PSS:
			mlDsaSeedHex = hexMlDsa65PrivSeedForRsa4096Pss
			signatureHex = hexMlDsa65Rsa4096PssSignature
			var pubKey *rsassapss.PublicKey
			pubKey, err = rsassapss.NewPublicKey(mustHexDecode(hexMlDsa65Rsa4096PssN), 0, classicalParams.(*rsassapss.Parameters))
			if err == nil {
				classPrivKey, err = rsassapss.NewPrivateKey(pubKey, rsassapss.PrivateKeyValues{
					P: mustSecretBytes(hexMlDsa65Rsa4096PssP),
					Q: mustSecretBytes(hexMlDsa65Rsa4096PssQ),
					D: mustSecretBytes(hexMlDsa65Rsa4096PssD),
				})
			}
		case tinkcompositemldsa.RSA3072PKCS1:
			mlDsaSeedHex = hexMlDsa65PrivSeedForRsa3072Pkcs1
			signatureHex = hexMlDsa65Rsa3072Pkcs1Signature
			var pubKey *rsassapkcs1.PublicKey
			pubKey, err = rsassapkcs1.NewPublicKey(mustHexDecode(hexMlDsa65Rsa3072Pkcs1N), 0, classicalParams.(*rsassapkcs1.Parameters))
			if err == nil {
				classPrivKey, err = rsassapkcs1.NewPrivateKey(pubKey, rsassapkcs1.PrivateKeyValues{
					P: mustSecretBytes(hexMlDsa65Rsa3072Pkcs1P),
					Q: mustSecretBytes(hexMlDsa65Rsa3072Pkcs1Q),
					D: mustSecretBytes(hexMlDsa65Rsa3072Pkcs1D),
				})
			}
		case tinkcompositemldsa.RSA4096PKCS1:
			mlDsaSeedHex = hexMlDsa65PrivSeedForRsa4096Pkcs1
			signatureHex = hexMlDsa65Rsa4096Pkcs1Signature
			var pubKey *rsassapkcs1.PublicKey
			pubKey, err = rsassapkcs1.NewPublicKey(mustHexDecode(hexMlDsa65Rsa4096Pkcs1N), 0, classicalParams.(*rsassapkcs1.Parameters))
			if err == nil {
				classPrivKey, err = rsassapkcs1.NewPrivateKey(pubKey, rsassapkcs1.PrivateKeyValues{
					P: mustSecretBytes(hexMlDsa65Rsa4096Pkcs1P),
					Q: mustSecretBytes(hexMlDsa65Rsa4096Pkcs1Q),
					D: mustSecretBytes(hexMlDsa65Rsa4096Pkcs1D),
				})
			}
		}
	case tinkcompositemldsa.MLDSA87:
		switch params.ClassicalAlgorithm() {
		case tinkcompositemldsa.ECDSAP384:
			mlDsaSeedHex = hexMlDsa87PrivSeedForEcdsaP384
			signatureHex = hexMlDsa87EcdsaP384Signature
			classPrivKey, err = ecdsa.NewPrivateKey(mustSecretBytes(hexMlDsa87EcdsaP384Priv), 0, classicalParams.(*ecdsa.Parameters))
		case tinkcompositemldsa.ECDSAP521:
			mlDsaSeedHex = hexMlDsa87PrivSeedForEcdsaP521
			signatureHex = hexMlDsa87EcdsaP521Signature
			classPrivKey, err = ecdsa.NewPrivateKey(mustSecretBytes(hexMlDsa87EcdsaP521Priv), 0, classicalParams.(*ecdsa.Parameters))
		case tinkcompositemldsa.RSA3072PSS:
			mlDsaSeedHex = hexMlDsa87PrivSeedForRsa3072Pss
			signatureHex = hexMlDsa87Rsa3072PssSignature
			var pubKey *rsassapss.PublicKey
			pubKey, err = rsassapss.NewPublicKey(mustHexDecode(hexMlDsa87Rsa3072PssN), 0, classicalParams.(*rsassapss.Parameters))
			if err == nil {
				classPrivKey, err = rsassapss.NewPrivateKey(pubKey, rsassapss.PrivateKeyValues{
					P: mustSecretBytes(hexMlDsa87Rsa3072PssP),
					Q: mustSecretBytes(hexMlDsa87Rsa3072PssQ),
					D: mustSecretBytes(hexMlDsa87Rsa3072PssD),
				})
			}
		case tinkcompositemldsa.RSA4096PSS:
			mlDsaSeedHex = hexMlDsa87PrivSeedForRsa4096Pss
			signatureHex = hexMlDsa87Rsa4096PssSignature
			var pubKey *rsassapss.PublicKey
			pubKey, err = rsassapss.NewPublicKey(mustHexDecode(hexMlDsa87Rsa4096PssN), 0, classicalParams.(*rsassapss.Parameters))
			if err == nil {
				classPrivKey, err = rsassapss.NewPrivateKey(pubKey, rsassapss.PrivateKeyValues{
					P: mustSecretBytes(hexMlDsa87Rsa4096PssP),
					Q: mustSecretBytes(hexMlDsa87Rsa4096PssQ),
					D: mustSecretBytes(hexMlDsa87Rsa4096PssD),
				})
			}
		}
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to create classical private key: %v", err)
	}

	mlDsaPrivKey, err := mldsa.NewPrivateKey(mustSecretBytes(mlDsaSeedHex), 0, mlDsaParams)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create ML-DSA private key: %v", err)
	}

	compPrivKey, err := tinkcompositemldsa.NewPrivateKey(mlDsaPrivKey, classPrivKey, idRequirement, params)
	return compPrivKey, mustHexDecode(signatureHex), err
}

func mustHexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustSecretBytes(s string) secretdata.Bytes {
	return secretdata.NewBytesFromData(mustHexDecode(s), insecuresecretdataaccess.Token{})
}

func createTestPrivateKeyRandom(t *testing.T, params *tinkcompositemldsa.Parameters, idRequirement uint32) *tinkcompositemldsa.PrivateKey {
	t.Helper()
	mlDsaPrivKey, _ := generateMLDSAKeyPair(t, params.MLDSAInstance())
	classicalParams, err := parametersForClassicalAlgorithm(params.ClassicalAlgorithm())
	if err != nil {
		t.Errorf("parametersForClassicalAlgorithm(%v) err = %v, want nil", params.ClassicalAlgorithm(), err)
	}
	classicalPrivKey, _ := generateClassicalKeyPair(t, params.ClassicalAlgorithm(), classicalParams)

	compPrivKey, err := tinkcompositemldsa.NewPrivateKey(mlDsaPrivKey, classicalPrivKey, idRequirement, params)
	if err != nil {
		t.Fatalf("NewPrivateKey() err = %v, want nil", err)
	}
	return compPrivKey
}

func TestSignVerifyCorrectnessRandom(t *testing.T) {
	const numRandomSignVerifyIterations = 10
	for _, tc := range testCasesSupportedParameters(t) {
		testName := fmt.Sprintf("%v_%v_%v", tc.classicalAlgorithm, tc.instance, tc.variant)
		t.Run(testName, func(t *testing.T) {
			params, err := tinkcompositemldsa.NewParameters(tc.classicalAlgorithm, tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v, %v) err = %v, want nil", tc.classicalAlgorithm, tc.instance, tc.variant, err)
			}
			idReq := uint32(0)
			if tc.variant == tinkcompositemldsa.VariantTink {
				idReq = 0x01020304
			}
			compPrivKey := createTestPrivateKeyRandom(t, params, idReq)
			pubKey, _ := compPrivKey.PublicKey()
			compPubKey := pubKey.(*tinkcompositemldsa.PublicKey)

			signer, err := tinkcompositemldsa.NewSigner(compPrivKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("NewSigner() err = %v, want nil", err)
			}
			verifier, err := tinkcompositemldsa.NewVerifier(compPubKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("NewVerifier() err = %v, want nil", err)
			}

			for i := 0; i < numRandomSignVerifyIterations; i++ {
				data := random.GetRandomBytes(random.GetRandomUint32()%128 + 1)
				signature, err := signer.Sign(data)
				if err != nil {
					t.Fatalf("Sign(%x) err = %v, want nil", data, err)
				}
				if err := verifier.Verify(signature, data); err != nil {
					t.Errorf("Verify(%x, %x) err = %v, want nil", signature, data, err)
				}
			}
		})
	}
}

func TestSignVerifyCorrectnessDeterministic(t *testing.T) {
	for _, tc := range testCasesSupportedParameters(t) {
		testName := fmt.Sprintf("%v_%v_%v", tc.classicalAlgorithm, tc.instance, tc.variant)
		t.Run(testName, func(t *testing.T) {
			params, err := tinkcompositemldsa.NewParameters(tc.classicalAlgorithm, tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v, %v) err = %v, want nil", tc.classicalAlgorithm, tc.instance, tc.variant, err)
			}
			// If the variant is Tink, the signature needs to have a 5-byte prefix
			// (0x01 followed by the 4-byte key ID). The test case verifies that
			// signatures with test vectors are correctly prepended with this prefix.
			idReq := uint32(0)
			if tc.variant == tinkcompositemldsa.VariantTink {
				idReq = 0x01020304
			}
			compPrivKey, expectedSignature, err := createTestPrivateKeyDeterministic(params, idReq)
			if err != nil {
				t.Fatalf("createTestPrivateKeyDeterministic fails: %v", err)
			}

			pubKey, _ := compPrivKey.PublicKey()
			compPubKey := pubKey.(*tinkcompositemldsa.PublicKey)

			signer, err := tinkcompositemldsa.NewSigner(compPrivKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("NewSigner() err = %v, want nil", err)
			}
			verifier, err := tinkcompositemldsa.NewVerifier(compPubKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("NewVerifier() err = %v, want nil", err)
			}

			expectedMessage := mustHexDecode(hexMessage)
			if tc.variant == tinkcompositemldsa.VariantTink {
				// We append the 5-byte Tink identifier prefix to the raw signature bytes
				// from the test vector so the keyset routing validates correctly.
				prefix := make([]byte, 5)
				prefix[0] = 1
				binary.BigEndian.PutUint32(prefix[1:], idReq)
				expectedSignature = append(prefix, expectedSignature...)
			}

			if err := verifier.Verify(expectedSignature, expectedMessage); err != nil {
				testSig, _ := signer.Sign(expectedMessage)
				if bytes.Equal(testSig, expectedSignature) {
					t.Fatalf("test signature matches expected signature but verification failed!")
				} else {
					t.Fatalf("Mismatch! len(testSig)=%d len(expected)=%d err=%v\nexpectedSig[:20]=%x\ntestSig[:20]=%x", len(testSig), len(expectedSignature), err, expectedSignature[:20], testSig[:20])
				}
			}

			// Roundtrip deterministic signature test
			data := random.GetRandomBytes(random.GetRandomUint32()%128 + 1)
			signature, err := signer.Sign(data)
			if err != nil {
				t.Fatalf("Sign(%x) err = %v, want nil", data, err)
			}
			if err := verifier.Verify(signature, data); err != nil {
				t.Errorf("Verify(%x, %x) err = %v, want nil", signature, data, err)
			}
		})
	}
}

func TestVerifyFails(t *testing.T) {
	for _, tc := range testCasesSupportedParameters(t) {
		testName := fmt.Sprintf("%v_%v_%v", tc.classicalAlgorithm, tc.instance, tc.variant)
		t.Run(testName, func(t *testing.T) {
			params, err := tinkcompositemldsa.NewParameters(tc.classicalAlgorithm, tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v, %v) err = %v, want nil", tc.classicalAlgorithm, tc.instance, tc.variant, err)
			}
			idReq := uint32(0)
			if tc.variant == tinkcompositemldsa.VariantTink {
				idReq = 0x01020304
			}
			compPrivKey, _, err := createTestPrivateKeyDeterministic(params, idReq)
			if err != nil {
				t.Fatalf("createTestPrivateKeyDeterministic(%v, %v) err = %v, want nil", params, idReq, err)
			}
			pubKey, _ := compPrivKey.PublicKey()
			compPubKey := pubKey.(*tinkcompositemldsa.PublicKey)

			signer, err := tinkcompositemldsa.NewSigner(compPrivKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("NewSigner() err = %v, want nil", err)
			}
			verifier, err := tinkcompositemldsa.NewVerifier(compPubKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("NewVerifier() err = %v, want nil", err)
			}

			data := random.GetRandomBytes(20)
			signature, err := signer.Sign(data)
			if err != nil {
				t.Fatalf("Sign(%x) err = %v, want nil", data, err)
			}

			// Modify the message.
			if len(data) > 0 {
				modifiedData := slices.Clone(data)
				modifiedData[0] ^= 0x01
				if err := verifier.Verify(signature, modifiedData); err == nil {
					t.Errorf("Verify(signature, %x) err = nil, want error", modifiedData)
				}
			}

			// Message too short.
			if len(data) > 0 {
				shortData := data[:len(data)-1]
				if err := verifier.Verify(signature, shortData); err == nil {
					t.Errorf("Verify(signature, %x) err = nil, want error", shortData)
				}
			}

			// Modify the signature.
			if len(signature) > 0 {
				modifiedSignature := slices.Clone(signature)
				modifiedSignature[len(modifiedSignature)-1] ^= 0x01
				if err := verifier.Verify(modifiedSignature, data); err == nil {
					t.Errorf("Verify(%x, %x) err = nil, want error", modifiedSignature, data)
				}
			}

			// Modify the prefix.
			if tc.variant == tinkcompositemldsa.VariantTink && len(signature) > 4 {
				modifiedSignature := slices.Clone(signature)
				modifiedSignature[0] ^= 0x01
				if err := verifier.Verify(modifiedSignature, data); err == nil {
					t.Errorf("Verify(%x, %x) err = nil, want error", modifiedSignature, data)
				}
			}
		})
	}
}

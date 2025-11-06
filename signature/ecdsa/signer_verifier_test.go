// Copyright 2024 Google LLC
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

package ecdsa_test

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/subtle"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type primitiveTestCase struct {
	name       string
	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
	curve      elliptic.Curve
	signature  []byte
	message    []byte
}

func mustCreatePrivateKey(t *testing.T, keyValue []byte, id uint32, params *ecdsa.Parameters) *ecdsa.PrivateKey {
	t.Helper()
	token := insecuresecretdataaccess.Token{}
	privateKey, err := ecdsa.NewPrivateKey(secretdata.NewBytesFromData(keyValue, token), id, params)
	if err != nil {
		t.Fatalf("ecdsa.NewPrivateKey() err = %v, want nil", err)
	}
	return privateKey
}

// primitiveTestVectors returns a list of test vectors similar to
// https://github.com/tink-crypto/tink-java/blob/1.15/src/main/java/com/google/crypto/tink/signature/internal/testing/EcdsaTestUtil.java
func primitiveTestVectors(t *testing.T) []primitiveTestCase {
	t.Helper()
	testCases := []primitiveTestCase{}
	// Test case 0.
	params0 := mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.IEEEP1363, ecdsa.VariantNoPrefix)
	testCases = append(testCases, primitiveTestCase{
		name:       "P256-SHA256-IEEE_P1363-NO_PREFIX",
		publicKey:  mustCreatePublicKey(t, bytesFromHex(t, pubKeyUncompressedP256Hex), 0, params0),
		privateKey: mustCreatePrivateKey(t, bytesFromHex(t, privKeyValueP256Hex), 0, params0),
		curve:      elliptic.P256(),
		signature:  bytesFromHex(t, "70cbee11e536e9c83d2a2abc6be049117fdab0c420db8191e36f8ce2855262bb5d0b69eefc4dea7b086aa62186e9a7c8600e7b0f1252f704271d5189e7a5cf03"),
		message:    bytesFromHex(t, ""),
	})

	// Test case 1.
	params1 := mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantNoPrefix)
	testCases = append(testCases, primitiveTestCase{
		name:       "P256-SHA256-DER-NO_PREFIX",
		publicKey:  mustCreatePublicKey(t, bytesFromHex(t, pubKeyUncompressedP256Hex), 0, params1),
		privateKey: mustCreatePrivateKey(t, bytesFromHex(t, privKeyValueP256Hex), 0, params1),
		curve:      elliptic.P256(),
		signature:  bytesFromHex(t, "3046022100baca7d618e43d44f2754a5368f60b4a41925e2c04d27a672b276ae1f4b3c63a2022100d404a3015cb229f7cb036c2b5f77cc546065eed4b75837cec2883d1e35d5eb9f"),
		message:    bytesFromHex(t, ""),
	})

	// Test case 1 with TINK prefix.
	params1 = mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantTink)
	testCases = append(testCases, primitiveTestCase{
		name:       "P256-SHA256-DER-TINK",
		publicKey:  mustCreatePublicKey(t, bytesFromHex(t, pubKeyUncompressedP256Hex), 0x99887766, params1),
		privateKey: mustCreatePrivateKey(t, bytesFromHex(t, privKeyValueP256Hex), 0x99887766, params1),
		curve:      elliptic.P256(),
		signature:  bytesFromHex(t, strings.Join([]string{"0199887766", "3046022100baca7d618e43d44f2754a5368f60b4a41925e2c04d27a672b276ae1f4b3c63a2022100d404a3015cb229f7cb036c2b5f77cc546065eed4b75837cec2883d1e35d5eb9f"}, "")),
		message:    bytesFromHex(t, ""),
	})

	// Test case 2.
	params2 := mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.IEEEP1363, ecdsa.VariantTink)
	testCases = append(testCases, primitiveTestCase{
		name:       "P256-SHA256-IEEE_P1363-TINK",
		publicKey:  mustCreatePublicKey(t, bytesFromHex(t, pubKeyUncompressedP256Hex), 0x99887766, params2),
		privateKey: mustCreatePrivateKey(t, bytesFromHex(t, privKeyValueP256Hex), 0x99887766, params2),
		curve:      elliptic.P256(),
		signature:  bytesFromHex(t, strings.Join([]string{"0199887766", "9b04881165ae47c99c637d306c537bdc97a336ed6f358c7fac1124b3f7166f7d5da6a7b20c61090200276fa25ff25e6e39cf56fb5499973b66f25bc1921a1fda"}, "")),
		message:    bytesFromHex(t, ""),
	})

	// Test case 3.
	params3 := mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.IEEEP1363, ecdsa.VariantCrunchy)
	testCases = append(testCases, primitiveTestCase{
		name:       "P256-SHA256-IEEE_P1363-CRUNCHY",
		publicKey:  mustCreatePublicKey(t, bytesFromHex(t, pubKeyUncompressedP256Hex), 0x99887766, params3),
		privateKey: mustCreatePrivateKey(t, bytesFromHex(t, privKeyValueP256Hex), 0x99887766, params3),
		curve:      elliptic.P256(),
		signature:  bytesFromHex(t, strings.Join([]string{"0099887766", "9b04881165ae47c99c637d306c537bdc97a336ed6f358c7fac1124b3f7166f7d5da6a7b20c61090200276fa25ff25e6e39cf56fb5499973b66f25bc1921a1fda"}, "")),
		message:    bytesFromHex(t, ""),
	})

	// Test case 4.
	params4 := mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.IEEEP1363, ecdsa.VariantLegacy)
	testCases = append(testCases, primitiveTestCase{
		name:       "P256-SHA256-IEEE_P1363-LEGACY",
		publicKey:  mustCreatePublicKey(t, bytesFromHex(t, pubKeyUncompressedP256Hex), 0x99887766, params4),
		privateKey: mustCreatePrivateKey(t, bytesFromHex(t, privKeyValueP256Hex), 0x99887766, params4),
		curve:      elliptic.P256(),
		signature:  bytesFromHex(t, strings.Join([]string{"0099887766", "515b67e48efb8ebc12e0ce691cf210b18c1e96409667aaedd8d744c64aff843a4e09ebfb9b6c40a6540dd0d835693ca08da8c1d8e434770511459088243b0bbb"}, "")),
		message:    bytesFromHex(t, ""),
	})

	// Test case 5.
	params5 := mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.IEEEP1363, ecdsa.VariantNoPrefix)
	testCases = append(testCases, primitiveTestCase{
		name:       "P256-SHA256-IEEE_P1363-RAW-Nonempty",
		publicKey:  mustCreatePublicKey(t, bytesFromHex(t, pubKeyUncompressedP256Hex), 0, params5),
		privateKey: mustCreatePrivateKey(t, bytesFromHex(t, privKeyValueP256Hex), 0, params5),
		curve:      elliptic.P256(),
		signature:  bytesFromHex(t, "bfec68e554a26e161b657efb368a6cd0ec3499c92f2b6240e1b92fa724366a79ca37137274c9125e34c286439c848ce3594a3f9450f4108a2fc287a120dfab4f"),
		message:    bytesFromHex(t, "001122"),
	})

	// P-384.

	xP384Hex := "9d92e0330dfc60ba8b2be32e10f7d2f8457678a112cafd4544b29b7e6addf0249968f54c732aa49bc4a38f467edb8424"
	yP384Hex := "81a3a9c9e878b86755f018a8ec3c5e80921910af919b95f18976e35acc04efa2962e277a0b2c990ae92b62d6c75180ba"
	// Test case 6.
	params6 := mustCreateParameters(t, ecdsa.NistP384, ecdsa.SHA384, ecdsa.IEEEP1363, ecdsa.VariantNoPrefix)
	testCases = append(testCases, primitiveTestCase{
		name:       "P384-SHA384-IEEE_P1363-RAW",
		publicKey:  mustCreatePublicKey(t, bytesFromHex(t, "04"+xP384Hex+yP384Hex), 0, params6),
		privateKey: mustCreatePrivateKey(t, bytesFromHex(t, "670dc60402d8a4fe52f4e552d2b71f0f81bcf195d8a71a6c7d84efb4f0e4b4a5d0f60a27c94caac46bdeeb79897a3ed9"), 0, params6),
		curve:      elliptic.P384(),
		signature:  bytesFromHex(t, "eb19dc251dcbb0aac7634c646b27ccc59a21d6231e08d2b6031ec729ecb0e9927b70bfa66d458b5e1b7186355644fa9150602bade9f0c358b9d28263cb427f58bf7d9b892ac75f43ab048360b34ee81653f85ec2f10e6e4f0f0e0cafbe91f883"),
		message:    bytesFromHex(t, ""),
	})

	// Test case 7.
	params7 := mustCreateParameters(t, ecdsa.NistP384, ecdsa.SHA512, ecdsa.IEEEP1363, ecdsa.VariantNoPrefix)
	testCases = append(testCases, primitiveTestCase{
		name:       "P384-SHA512-IEEE_P1363-RAW",
		publicKey:  mustCreatePublicKey(t, bytesFromHex(t, "04"+xP384Hex+yP384Hex), 0, params7),
		privateKey: mustCreatePrivateKey(t, bytesFromHex(t, "670dc60402d8a4fe52f4e552d2b71f0f81bcf195d8a71a6c7d84efb4f0e4b4a5d0f60a27c94caac46bdeeb79897a3ed9"), 0, params7),
		curve:      elliptic.P384(),
		signature:  bytesFromHex(t, "3db99cec1a865909886f8863ccfa3147f21ccad262a41abc8d964fafa55141a9d89efa6bf0acb4e5ec357c6056542e7e016d4a653fde985aad594763900f3f9c4494f45f7a4450422640f57b0ad467950f78ddb56641676cb91d392410ed606d"),
		message:    bytesFromHex(t, ""),
	})

	// P-521.

	// Test case 8.
	params8 := mustCreateParameters(t, ecdsa.NistP521, ecdsa.SHA512, ecdsa.IEEEP1363, ecdsa.VariantNoPrefix)
	testCases = append(testCases, primitiveTestCase{
		name:       "P521-SHA512-IEEE_P1363-RAW",
		publicKey:  mustCreatePublicKey(t, bytesFromHex(t, pubKeyUncompressedP521Hex), 0, params8),
		privateKey: mustCreatePrivateKey(t, bytesFromHex(t, privKeyValueP521Hex), 0, params8),
		curve:      elliptic.P521(),
		signature:  bytesFromHex(t, "00eaf6672f0696a46046d3b1572814b697c7904fe265fece75e33b90833d08af6513adfb6cbf0a4971442633c981d11cd068fcf9431cbe49448b4240a067d860f7fb0168a8d7bf1602050b2255e844aea1df8d8ad770053d2c915cca2af6e175c2fb0944f6a9e3262fb9b99910e7fbd6ef4aca887b901ec78678d3ec48529c7f06e8c815"),
		message:    bytesFromHex(t, ""),
	})

	return testCases
}

func TestSignVerify(t *testing.T) {
	for _, tc := range primitiveTestVectors(t) {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := ecdsa.NewSigner(tc.privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("ecdsa.NewSigner(%v) err = %v, want nil", tc.privateKey, err)
			}
			verifier, err := ecdsa.NewVerifier(tc.publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("ecdsa.NewVerifier(%v) err = %v, want nil", tc.publicKey, err)
			}
			data := []byte("plaintext")
			encodedSignature, err := signer.Sign(data)
			if err != nil {
				t.Fatalf("signer.Sign(0x%x) err = %v, want nil", data, err)
			}
			if !bytes.HasPrefix(encodedSignature, tc.privateKey.OutputPrefix()) {
				t.Fatalf("encodedSignature[:%d] = 0x%x, want prefix 0x%x", len(tc.privateKey.OutputPrefix()), encodedSignature[:len(tc.privateKey.OutputPrefix())], tc.privateKey.OutputPrefix())
			}
			if err := verifier.Verify(encodedSignature, data); err != nil {
				t.Errorf("verifier.Verify(0x%x, 0x%x) err = %v, want nil", encodedSignature, data, err)
			}
		})
	}
}

func TestVerifyWorks(t *testing.T) {
	for _, tc := range primitiveTestVectors(t) {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Verify using the verifier from the public key.
			verifier, err := ecdsa.NewVerifier(tc.publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("ecdsa.NewVerifier(%v) err = %v, want nil", tc.publicKey, err)
			}
			if err := verifier.Verify(tc.signature, tc.message); err != nil {
				t.Errorf("verifier.Verify(0x%x, 0x%x) err = %v, want nil", tc.signature, tc.message, err)
			}

			// 2. Verify using the verifier from the keyset handle.
			verifierFromKeysetHandle := func() tink.Verifier {
				manager := keyset.NewManager()
				keyID, err := manager.AddKey(tc.publicKey)
				if err != nil {
					t.Fatalf("manager.AddKey(%v) err = %v, want nil", tc.publicKey, err)
				}
				manager.SetPrimary(keyID)
				handle, err := manager.Handle()
				if err != nil {
					t.Fatalf("manager.Handle() err = %v, want nil", err)
				}
				verifier, err := signature.NewVerifier(handle)
				if err != nil {
					t.Fatalf("signature.NewVerifier(handle) err = %v, want nil", err)
				}
				return verifier
			}()
			if err := verifierFromKeysetHandle.Verify(tc.signature, tc.message); err != nil {
				t.Errorf("verifierFromKeysetHandle.Verify(0x%x, 0x%x) err = %v, want nil", tc.signature, tc.message, err)
			}
		})
	}
}

func TestVerifyFails(t *testing.T) {
	data := []byte("plaintext")
	for _, tc := range []struct {
		name       string
		publicKey  *ecdsa.PublicKey
		privateKey *ecdsa.PrivateKey
		signature  []byte
	}{
		{
			name:      "different prefix type",
			publicKey: mustCreatePublicKey(t, bytesFromHex(t, pubKeyUncompressedP256Hex), 123, mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantTink)),
			signature: func() []byte {
				privateKey := mustCreatePrivateKey(t, bytesFromHex(t, privKeyValueP256Hex), 123, mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantCrunchy))
				s, err := ecdsa.NewSigner(privateKey, internalapi.Token{})
				if err != nil {
					t.Fatalf("ecdsa.NewSigner(%v) err = %v, want nil", privateKey, err)
				}
				signature, err := s.Sign(data)
				if err != nil {
					t.Fatalf("signer.Sign(%v) err = %v, want nil", data, err)
				}
				return signature
			}(),
		},
		{
			name:      "missing prefix",
			publicKey: mustCreatePublicKey(t, bytesFromHex(t, pubKeyUncompressedP256Hex), 123, mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantTink)),
			signature: func() []byte {
				privateKey := mustCreatePrivateKey(t, bytesFromHex(t, privKeyValueP256Hex), 0, mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantNoPrefix))
				s, err := ecdsa.NewSigner(privateKey, internalapi.Token{})
				if err != nil {
					t.Fatalf("ecdsa.NewSigner(%v) err = %v, want nil", privateKey, err)
				}
				signature, err := s.Sign(data)
				if err != nil {
					t.Fatalf("signer.Sign(%v) err = %v, want nil", data, err)
				}
				return signature
			}(),
		},
		{
			name:      "different key ID",
			publicKey: mustCreatePublicKey(t, bytesFromHex(t, pubKeyUncompressedP256Hex), 123, mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantTink)),
			signature: func() []byte {
				privateKey := mustCreatePrivateKey(t, bytesFromHex(t, privKeyValueP256Hex), 456, mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantTink))
				s, err := ecdsa.NewSigner(privateKey, internalapi.Token{})
				if err != nil {
					t.Fatalf("ecdsa.NewSigner(%v) err = %v, want nil", privateKey, err)
				}
				signature, err := s.Sign(data)
				if err != nil {
					t.Fatalf("signer.Sign(%v) err = %v, want nil", data, err)
				}
				return signature
			}(),
		},
		{
			name:      "different signature encoding",
			publicKey: mustCreatePublicKey(t, bytesFromHex(t, pubKeyUncompressedP256Hex), 123, mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantTink)),
			signature: func() []byte {
				privateKey := mustCreatePrivateKey(t, bytesFromHex(t, privKeyValueP256Hex), 123, mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.IEEEP1363, ecdsa.VariantTink))
				s, err := ecdsa.NewSigner(privateKey, internalapi.Token{})
				if err != nil {
					t.Fatalf("ecdsa.NewSigner(%v) err = %v, want nil", privateKey, err)
				}
				signature, err := s.Sign(data)
				if err != nil {
					t.Fatalf("signer.Sign(%v) err = %v, want nil", data, err)
				}
				return signature
			}(),
		},
		{
			name:      "invalid signature",
			publicKey: mustCreatePublicKey(t, bytesFromHex(t, pubKeyUncompressedP256Hex), 123, mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantTink)),
			signature: func() []byte {
				privateKey := mustCreatePrivateKey(t, bytesFromHex(t, privKeyValueP256Hex), 123, mustCreateParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantTink))
				s, err := ecdsa.NewSigner(privateKey, internalapi.Token{})
				if err != nil {
					t.Fatalf("ecdsa.NewSigner(%v) err = %v, want nil", privateKey, err)
				}
				signature, err := s.Sign(data)
				if err != nil {
					t.Fatalf("signer.Sign(%v) err = %v, want nil", data, err)
				}
				// Corrupt the 1st byte after the prefix.
				signature[len(privateKey.OutputPrefix())] ^= 1
				return signature
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier, err := ecdsa.NewVerifier(tc.publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("ecdsa.NewVerifier(%v) err = %v, want nil", tc.publicKey, err)
			}
			if err := verifier.Verify(tc.signature, data); err == nil {
				t.Errorf("verifier.Verify(%v, %v) err = nil, want error", tc.signature, data)
			}
		})
	}
}

type wycheproofSuite struct {
	testutil.WycheproofSuite
	TestGroups []*wycheproofGroup `json:"testGroups"`
}

type wycheproofGroup struct {
	testutil.WycheproofGroup
	JWK    *wycheproofJWK    `json:"jwk,omitempty"`
	KeyDER string            `json:"keyDer"`
	KeyPEM string            `json:"keyPem"`
	SHA    string            `json:"sha"`
	Type   string            `json:"type"`
	Key    *wycheproofKey    `json:"key"`
	Tests  []*wycheproofCase `json:"tests"`
}

type wycheproofCase struct {
	testutil.WycheproofCase
	Message   testutil.HexBytes `json:"msg"`
	Signature testutil.HexBytes `json:"sig"`
}

type wycheproofKey struct {
	Curve string `json:"curve"`
	Type  string `json:"type"`
	Wx    string `json:"wx"`
	Wy    string `json:"wy"`
}

type wycheproofJWK struct {
	JWK   string `json:"jwk"`
	Curve string `json:"crv"`
	Kid   string `json:"kid"`
	Kty   string `json:"kty"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

func hash(sha string) ecdsa.HashType {
	switch sha {
	case "SHA256":
		return ecdsa.SHA256
	case "SHA384":
		return ecdsa.SHA384
	case "SHA512":
		return ecdsa.SHA512
	default:
		return ecdsa.UnknownHashType
	}
}

func curve(sha string) ecdsa.CurveType {
	switch sha {
	case "NIST_P256":
		return ecdsa.NistP256
	case "NIST_P384":
		return ecdsa.NistP384
	case "NIST_P521":
		return ecdsa.NistP521
	default:
		return ecdsa.UnknownCurveType
	}
}

func encoding(encoding string) ecdsa.SignatureEncoding {
	switch encoding {
	case "DER":
		return ecdsa.DER
	case "IEEE_P1363":
		return ecdsa.IEEEP1363
	default:
		return ecdsa.UnknownSignatureEncoding
	}
}

func TestWycheproof(t *testing.T) {
	vectors := []struct {
		Filename string
		Encoding string
	}{
		{"ecdsa_test.json", "DER"},
		{"ecdsa_secp256r1_sha256_p1363_test.json", "IEEE_P1363"},
		{"ecdsa_secp384r1_sha512_p1363_test.json", "IEEE_P1363"},
		{"ecdsa_secp521r1_sha512_p1363_test.json", "IEEE_P1363"},
	}

	for _, v := range vectors {
		suite := new(wycheproofSuite)
		if err := testutil.PopulateSuite(suite, v.Filename); err != nil {
			t.Fatalf("failed populating suite: %s", err)
		}
		for _, group := range suite.TestGroups {
			h := hash(subtle.ConvertHashName(group.SHA))
			c := curve(subtle.ConvertCurveName(group.Key.Curve))
			e := encoding(v.Encoding)
			params, err := ecdsa.NewParameters(c, h, e, ecdsa.VariantNoPrefix)
			if err != nil {
				continue
			}
			x, err := subtle.NewBigIntFromHex(group.Key.Wx)
			if err != nil {
				t.Errorf("failed decoding x: %s", err)
				continue
			}
			y, err := subtle.NewBigIntFromHex(group.Key.Wy)
			if err != nil {
				t.Errorf("failed decoding y: %s", err)
				continue
			}
			publicKey, err := ecdsa.NewPublicKey(slices.Concat([]byte{0x04}, x.Bytes(), y.Bytes()), 0, params)
			if err != nil {
				continue
			}
			verifier, err := ecdsa.NewVerifier(publicKey, internalapi.Token{})
			if err != nil {
				continue
			}
			for _, test := range group.Tests {
				caseName := fmt.Sprintf("%s-%s-%s:Case-%d", group.Type, group.Key.Curve, group.SHA, test.CaseID)
				t.Run(caseName, func(t *testing.T) {
					err := verifier.Verify(test.Signature, test.Message)
					switch test.Result {
					case "valid":
						if err != nil {
							t.Fatalf("verifier.Verify() failed in a valid test case: %s", err)
						}
					case "invalid":
						if err == nil {
							t.Fatalf("verifier.Verify() succeeded in an invalid test case")
						}
					case "acceptable":
						// TODO: b/379282500 - Use acceptable test vectors.
					default:
						t.Fatalf("unsupported test result: %q", test.Result)
					}
				})
			}
		}
	}
}

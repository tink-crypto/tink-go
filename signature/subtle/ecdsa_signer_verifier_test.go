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
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/internal/testing/wycheproof"
	subtleSignature "github.com/tink-crypto/tink-go/v2/signature/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/subtle"
)

func TestSignVerify(t *testing.T) {
	data := random.GetRandomBytes(20)
	hash := "SHA256"
	curve := "NIST_P256"
	encodings := []string{"DER", "IEEE_P1363"}
	for _, encoding := range encodings {
		priv, err := ecdsa.GenerateKey(subtle.GetCurve(curve), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey() err = %q, want nil", err)
		}
		// Use the private key and public key directly to create new instances
		signer, err := subtleSignature.NewECDSASignerFromPrivateKey(hash, encoding, priv)
		if err != nil {
			t.Errorf("unexpected error when creating ECDSASigner: %s", err)
		}
		verifier, err := subtleSignature.NewECDSAVerifierFromPublicKey(hash, encoding, &priv.PublicKey)
		if err != nil {
			t.Errorf("unexpected error when creating ECDSAVerifier: %s", err)
		}
		signature, err := signer.Sign(data)
		if err != nil {
			t.Errorf("unexpected error when signing: %s", err)
		}
		if err := verifier.Verify(signature, data); err != nil {
			t.Errorf("unexpected error when verifying: %s", err)
		}

		// Use byte slices to create new instances
		signer, err = subtleSignature.NewECDSASigner(hash, curve, encoding, priv.D.Bytes())
		if err != nil {
			t.Errorf("unexpected error when creating ECDSASigner: %s", err)
		}
		verifier, err = subtleSignature.NewECDSAVerifier(hash, curve, encoding, priv.X.Bytes(), priv.Y.Bytes())
		if err != nil {
			t.Errorf("unexpected error when creating ECDSAVerifier: %s", err)
		}
		signature, err = signer.Sign(data)
		if err != nil {
			t.Errorf("unexpected error when signing: %s", err)
		}
		if err = verifier.Verify(signature, data); err != nil {
			t.Errorf("unexpected error when verifying: %s", err)
		}
	}
}

func TestECDSAInvalidPublicKey(t *testing.T) {
	if _, err := subtleSignature.NewECDSAVerifier("SHA256", "NIST_P256", "IEEE_P1363", []byte{0, 32, 0}, []byte{0, 32}); err == nil {
		t.Errorf("subtleSignature.NewECDSAVerifier() err = nil, want error")
	}
}

func TestECDSAInvalidCurve(t *testing.T) {
	priv, err := ecdsa.GenerateKey(subtle.GetCurve("NIST_P256"), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() err = %q, want nil", err)
	}
	if _, err := subtleSignature.NewECDSAVerifier("SHA256", "INVALID", "IEEE_P1363", priv.X.Bytes(), priv.Y.Bytes()); err == nil {
		t.Errorf("subtleSignature.NewECDSAVerifier() err = nil, want error")
	}
}

func TestECDSAWycheproofCases(t *testing.T) {
	vectors := []struct {
		Filename string
		Encoding string
	}{
		{Filename: "ecdsa_secp256r1_sha256_test.json", Encoding: "DER"},
		{Filename: "ecdsa_secp384r1_sha512_test.json", Encoding: "DER"},
		{Filename: "ecdsa_secp521r1_sha512_test.json", Encoding: "DER"},
		{Filename: "ecdsa_secp256r1_sha256_p1363_test.json", Encoding: "IEEE_P1363"},
		{Filename: "ecdsa_secp384r1_sha512_p1363_test.json", Encoding: "IEEE_P1363"},
		{Filename: "ecdsa_secp521r1_sha512_p1363_test.json", Encoding: "IEEE_P1363"},
	}

	for _, v := range vectors {
		suite := new(ecdsaSuite)
		wycheproof.PopulateSuiteV1(t, suite, v.Filename)

		for _, group := range suite.TestGroups {
			hash := subtle.ConvertHashName(group.SHA)
			curve := subtle.ConvertCurveName(group.PublicKey.Curve)
			if hash == "" || curve == "" {
				continue
			}
			x, err := subtle.NewBigIntFromHex(group.PublicKey.Wx)
			if err != nil {
				t.Errorf("cannot decode wx: %s", err)
				continue
			}
			y, err := subtle.NewBigIntFromHex(group.PublicKey.Wy)
			if err != nil {
				t.Errorf("cannot decode wy: %s", err)
				continue
			}

			verifier, err := subtleSignature.NewECDSAVerifier(hash, curve, v.Encoding, x.Bytes(), y.Bytes())
			if err != nil {
				continue
			}
			for _, test := range group.Tests {
				// There is no requirement that libraries check the length of P1363 encoded signatures.
				//
				// See https://github.com/C2SP/wycheproof/blob/fca0d3ba9f1286c3af57801ace39c633e29a88f1/testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json#L66-L69
				//
				expectedSignatureSizeNilErr := slices.Contains(test.Flags, "SignatureSize") && v.Encoding == "IEEE_P1363"

				caseName := fmt.Sprintf("%s-%s:Case-%d", group.Type, group.SHA, test.CaseID)
				t.Run(caseName, func(t *testing.T) {
					err := verifier.Verify(test.Signature, test.Message)
					switch test.Result {
					case "valid":
						if err != nil {
							t.Fatalf("ECDSAVerifier.Verify() failed in a valid test case: %s", err)
						}
					case "invalid":
						if err == nil {
							if expectedSignatureSizeNilErr {
								return
							}
							t.Fatalf("ECDSAVerifier.Verify() succeeded in an invalid test case")
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

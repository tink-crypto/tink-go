// Copyright 2022 Google LLC
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

package signature_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"slices"
	"testing"

	internal "github.com/tink-crypto/tink-go/v2/internal/signature"
	"github.com/tink-crypto/tink-go/v2/internal/testing/wycheproof"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/subtle"
	"github.com/tink-crypto/tink-go/v2/testutil"
)

const (
	// Taken from:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_2048_test.json#L13
	n2048Base64 = "s1EKK81M5kTFtZSuUFnhKy8FS2WNXaWVmi_fGHG4CLw98-Yo0nkuUarVwSS0O9pFPcpc3kvPKOe9Tv-6DLS3Qru21aATy2PRqjqJ4CYn71OYtSwM_ZfSCKvrjXybzgu-sBmobdtYm-sppbdL-GEHXGd8gdQw8DDCZSR6-dPJFAzLZTCdB-Ctwe_RXPF-ewVdfaOGjkZIzDoYDw7n-OHnsYCYozkbTOcWHpjVevipR-IBpGPi1rvKgFnlcG6d_tj0hWRl_6cS7RqhjoiNEtxqoJzpXs_Kg8xbCxXbCchkf11STA8udiCjQWuWI8rcDwl69XMmHJjIQAqhKvOOQ8rYTQ"
	d2048Base64 = "GlAtDupse2niHVg5EB9wVFbtDvhS-0f-IQcfVMXzPIzrBmxi1yfjLSbFgTcyn4nTGVMlt5UmTBldhUcvdQfb0JYdKVH5NaJrNPCsJNFUkOESiptxOJFbx9v6j-OWNXExxUOunJhQc2jZzrCMHGGYo-2nrqGFoOl2zULCLQDwA9nxnZbqTJr8v-FEHMyALPsGifWdgExqTk9ATBUXR0XtbLi8iO8LM7oNKoDjXkO8kPNQBS5yAW51sA01ejgcnA1GcGnKZgiHyYd2Y0n8xDRgtKpRa84Hnt2HuhZDB7dSwnftlSitO6C_GHc0ntO3lmpsJAEQQJv00PreDGj9rdhH_Q"
	p2048Base64 = "7BJc834xCi_0YmO5suBinWOQAF7IiRPU-3G9TdhWEkSYquupg9e6K9lC5k0iP-t6I69NYF7-6mvXDTmv6Z01o6oV50oXaHeAk74O3UqNCbLe9tybZ_-FdkYlwuGSNttMQBzjCiVy0-y0-Wm3rRnFIsAtd0RlZ24aN3bFTWJINIs"
	q2048Base64 = "wnQqvNmJe9SwtnH5c_yCqPhKv1cF_4jdQZSGI6_p3KYNxlQzkHZ_6uvrU5V27ov6YbX8vKlKfO91oJFQxUD6lpTdgAStI3GMiJBJIZNpyZ9EWNSvwUj28H34cySpbZz3s4XdhiJBShgy-fKURvBQwtWmQHZJ3EGrcOI7PcwiyYc"

	// Taken from:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_3072_test.json#L21
	n3072Base64 = "3I94gGcvDPnWNheopYvdJxoQm63aD6gm-UuKeVUmtqSagFZMyrqKlJGpNaU-3q4dmntUY9ni7z7gznv_XUtsgUe1wHPC8iBRXVMdVaNmh6bePDR3XC8VGRrAp0LXNCIoyNkQ_mu8pDlTnEhd68vQ7g5LrjF1A7g87oEArHu0WHRny8Q3PEvaLu33xBYx5QkitYD1vOgdJLIIyrzS11_P6Z91tJPf_Fyb2ZD3_Dvy7-OS_srjbz5O9EVsG13pnMdFFzOpELaDS2HsKSdNmGvjdSw1CxOjJ9q8CN_PZWVJmtJuhTRGYz6tspcMqVvPa_Bf_bwqgEN412mFpx8G-Ql5-f73FsNqpiWkW17t9QglpT6dlDWyPKq55cZNOP06dn4YWtdyfW4V-em6svQYTWSHaV25ommMZysugjQQ2-8dk_5AydNX7p_Hf4Sd4RNj9YOvjM9Rgcoa65RMQiUWy0AelQkj5L2IFDn6EJPHdYK_4axZk2dHALZDQzngJFMV2G_L"
	d3072Base64 = "BQEgW9F7iNDWYm3Q_siYoP1_aPjd3MMU900WfEBJW5WKh-TtYyAuasaPT09LiOPsegfYV1enRYRot2aq2aQPdzN4VUCLKNFA51wuazYE6okHu9f46VeMJACuZF0o4t7vi_cY4pzxL8y5L--YafQ67lvWrcIjhI0WnNbCfCdmZSdm_4GZOz4BWlU97O4P_cFiTzn42Wtu1dlQR8FXC1n6LrPWiN1eFKzJQHuAlPGLRpQkTrGtzWVdhz9X_5r25P7EcL4ja687IMIECrNg11nItOYYv4vU4OxmmPG3LHFg7QUhyCtRdrYPtjUD0K4j9uL7emCTBbCvYhULkhrFP03omWZssB2wydi2UHUwFcG25oLmvzggTln3QJw4CMDlPyVJNVQKOBqWPCwad8b5h_BqB6BXJobtIogtvILngjzsCApY1ysJ0AzB0kXPFY_0nMQFmdOvcZ3DAbSqf1sDYproU-naq-KE24bVxB0EARQ98rRZPvTjdHIJxSP1p_gPAtAR"
	p3072Base64 = "_sahC_xJtYoshQ6v69uZdkmpVXWgwXYxsBHLINejICMqgVua9gQNe_I9Jn5eBjBMM-BMhebUgUQvAQqXWLoINkpwA175npyY7rQxUFsq-2d50ckdDqL7CmXcOR557Np9Uv191pkjsl365EjKzoKeusprPIo8tkqBgAYUQ0iVd4wg1imxJbafQpRfZrZE84QLz6b842EHQlbFCGPsyiznVrSp-36ZPQ8fpIssxIW36qYUBfvvFQ51Y8IVCBF2feD5"
	q3072Base64 = "3Z7BzubYqXGxZpAsRKTwLvN6YgU7QSiKHYc9OZy8nnvTBu2QZIfaL0m8HBgJwNTYgQbWh5UY7ZJf62aq1f88K4NGbFVO2XuWq-9Vs7AjFPUNA4WgodikauA-j86RtBISDwoQ3GgVcPpWS2hzus2Ze2FrK9dzP7cjreI7wQidoy5QlYNDbx40SLV5-yGyQGINIEWNCPD5lauswKOY8KtqZ8n1vPfgMvsdZo_mmNgDJ1ma4_3zqqqxm68XY5RDGUvj"

	// Taken from:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_4096_test.json#L21
	n4096Base64 = "9gG-DczQSqQLEvPxka4XwfnIwLaOenfhS-JcPHkHyx0zpu9BjvQYUvMsmDkrxcmu2RwaFQHFA-q4mz7m9PjrLg_PxBvQNgnPao6zqm8PviMYezPbTTS2bRKKiroKKr9Au50T2OJVRWmlerHYxhuMrS3IhZmuDaU0bhXazhuse_aXN8IvCDvptGu4seq1lXstp0AnXpbIcZW5b-EUUhWdr8_ZFs7l10mne8OQWl69OHrkRej-cPFumghmOXec7_v9QVV72Zrqajcaa0sWBhWhoSvGlY00vODIWty9g5L6EM7KUiCdVhlro9JzziKPHxERkqqS3ioDl5ihe87LTcYQDm-K6MJkPyrnaLIlXwgsl46VylUVVfEGCCMc-AA7v4B5af_x5RkUuajJuPRWRkW55dcF_60pZj9drj12ZStCLkPxPmwUkQkIBcLRJop0olEXdCfjOpqRF1w2cLkXRgCLzh_SMebk8q1wy0OspfB2AKbTHdApFSQ9_dlDoCFl2jZ6a35Nrh3S6Lg2kDCAeV0lhQdswcFd2ejS5eBHUmVpsb_TldlX65_eMl00LRRCbnHv3BiHUV5TzepYNJIfkoYp50ju0JesQCTivyVdcEEfhzc5SM-Oiqfv-isKtH1RZgkeGu3sYFaLFVvZwnvFXz7ONfg9Y2281av0hToFHblNUEU"
	d4096Base64 = "01Gb2G7fXb6cZKN4FxPdBJt0f1ZR_ZGMzoqbgLbWovtqqzNKtWmom1iYLgquNzCQKZ-iJ_llK4AtI-5cpoJMQz0B1AuwRzsWGQqL-xN8CnBLT0m0UBW_vuH2cERvB1lSWdcMfXmulfmyVDsBYuu3Y-u4HEtu3_nRl97eHb5X5ARm0VbU39XXY0xFU0-yu70b8leBehc8B5X9vMUzl29KDQQWDyma9dwnKoFLNtW65RFrlUIXjx1VTKt6ZFMDVIK5ga3UvY_9XVAIObI-MOvT84aPB1hMvRK6CJMlmChg9p8r3HB3tsYPWKInKCM3nhAjcEFl98FPZKGP1bJFoYFJt-2jOFpWup55UConvxOGXN41vhXeA9BqpvCLFyt-60tzy8FXAZxdkzWEqNGt1ht9vKOyU8oM-T3JqKOqwvUCJwIuaS97R2dVZiDMko1j4xB4w2Diq0txqRfhnn6wk4BILltOqIIChxwqKcpvZrL-MEr2CVIOT4HWTCZ2i7gSqGZ5NmYR9M9uieK9HZ1-KHKcfw5OMVLXrX8Yb6MvAeFp_wahIAG8F539DclCy6vFVfZ_X9BD4KM1Q0D6SQ0vEjNnvpJus-Hf_nDDFRyHRQ8yF9wqoLWnBpxaF9VWFMmZQTn3s3tJ6f54CvZaDoni5Y_qr_4WO8nRnq_ZzSmw7zzvPQE"
	p4096Base64 = "_CG4VcWtTKK2lwUWQG9xxuee_EEm5lmHctseCC3msN3aqiopUfBBSOhuC94oITt_YA-YcwgwHqzqE0Biuww932KNqav5PvHOPnWwlTpITb01VL1cBkmTPdd-UnVj6Q8FqAE_3ayVjDKTeOlDA7MEvl-d8f5bBDp_3ZRwCj8LHLvQUWt82UxXypbZ_SqMqXOZEhjLozocI9gQ91GdH3cCq3Kv_bP4ShsqiBFuQDO8TQz8eYnGV-D-lOlkR2rli65reHbzbAnTKxpj-MR8lKdMku7fdfwnz_4PhFI2PkvI92U_PLVer2k87HDRPIdd6TWosgQ5q36T92mBxZV_xbtE2Q"
	q4096Base64 = "-cf3SKUF0j7O-ahfgJfIz31wKO9skOIqM2URWC0sw2NuNOrTcgTb0i8UKj-x1fhXsDEMekM_Ua4U1GCLAbQ6qMeuZ4Nff74LnZeUiznpui06FoftuLVu5w_wU22rTQVR9x7Q2u6eQSRJ9fCZvMFeTvBVTcefh_7FoN6nF8cFQ5K_REYTk3QBu-88Ivv35zjFh3m5gWCaH5wR3W8LvpmW4nc0WeTO8kewKp_CEpasV6WxBWGCQxDPvezJDgZZg3DjaYcT_b4lKOxO89zKrnAe7cPlStbnr05o47Ob0ul6yRGZNsZHpQNRHLKD35hM_XwH8PVqqK4xZpSO8_QbCFmTTQ"
)

func base64Decode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(value)
	if err != nil {
		t.Fatalf("base64 decoding failed: %v", err)
	}
	return decoded
}

type testCase struct {
	name       string
	hash       string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func testCases(t *testing.T) []testCase {
	t.Helper()
	var testCases []testCase
	for _, hash := range []string{"SHA256", "SHA384", "SHA512"} {
		publicKey2048 := &rsa.PublicKey{
			N: new(big.Int).SetBytes(base64Decode(t, n2048Base64)),
			E: 65537,
		}
		privateKey2048 := &rsa.PrivateKey{
			PublicKey: *publicKey2048,
			D:         new(big.Int).SetBytes(base64Decode(t, d2048Base64)),
			Primes: []*big.Int{
				new(big.Int).SetBytes(base64Decode(t, p2048Base64)),
				new(big.Int).SetBytes(base64Decode(t, q2048Base64)),
			},
		}
		privateKey2048.Precompute()
		testCases = append(testCases, testCase{
			name:       fmt.Sprintf("2048-%s", hash),
			hash:       hash,
			publicKey:  publicKey2048,
			privateKey: privateKey2048,
		})

		publicKey3072 := &rsa.PublicKey{
			N: new(big.Int).SetBytes(base64Decode(t, n3072Base64)),
			E: 65537,
		}
		privateKey3072 := &rsa.PrivateKey{
			PublicKey: *publicKey3072,
			D:         new(big.Int).SetBytes(base64Decode(t, d3072Base64)),
			Primes: []*big.Int{
				new(big.Int).SetBytes(base64Decode(t, p3072Base64)),
				new(big.Int).SetBytes(base64Decode(t, q3072Base64)),
			},
		}
		privateKey3072.Precompute()
		testCases = append(testCases, testCase{
			name:       fmt.Sprintf("3072-%s", hash),
			hash:       hash,
			publicKey:  publicKey3072,
			privateKey: privateKey3072,
		})

		publicKey4096 := &rsa.PublicKey{
			N: new(big.Int).SetBytes(base64Decode(t, n4096Base64)),
			E: 65537,
		}
		privateKey4096 := &rsa.PrivateKey{
			PublicKey: *publicKey4096,
			D:         new(big.Int).SetBytes(base64Decode(t, d4096Base64)),
			Primes: []*big.Int{
				new(big.Int).SetBytes(base64Decode(t, p4096Base64)),
				new(big.Int).SetBytes(base64Decode(t, q4096Base64)),
			},
		}
		privateKey4096.Precompute()
		testCases = append(testCases, testCase{
			name:       fmt.Sprintf("4096-%s", hash),
			hash:       hash,
			publicKey:  publicKey4096,
			privateKey: privateKey4096,
		})
	}
	return testCases
}

func TestRSASSAPKCS1SignVerify(t *testing.T) {
	for _, tc := range testCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := internal.New_RSA_SSA_PKCS1_Signer(tc.hash, tc.privateKey)
			if err != nil {
				t.Fatalf("New_RSA_SSA_PKCS1_Signer() err = %v, want nil", err)
			}
			verifier, err := internal.New_RSA_SSA_PKCS1_Verifier(tc.hash, tc.publicKey)
			if err != nil {
				t.Fatalf("New_RSA_SSA_PKCS1_Verifier() err = %v, want nil", err)
			}
			data := random.GetRandomBytes(20)
			signature, err := signer.Sign(data)
			if err != nil {
				t.Fatalf("Sign() err = %v, want nil", err)
			}
			if err := verifier.Verify(signature, data); err != nil {
				t.Errorf("Verify() err = %v, want nil", err)
			}
		})
	}
}

func TestRSASSAPKCS1VerifyFails(t *testing.T) {
	for _, tc := range testCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := internal.New_RSA_SSA_PKCS1_Signer(tc.hash, tc.privateKey)
			if err != nil {
				t.Fatalf("New_RSA_SSA_PKCS1_Signer() err = %v, want nil", err)
			}
			verifier, err := internal.New_RSA_SSA_PKCS1_Verifier(tc.hash, tc.publicKey)
			if err != nil {
				t.Fatalf("New_RSA_SSA_PKCS1_Verifier() err = %v, want nil", err)
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

			// Append a byte to the signature.
			for j := 0; j < 8; j++ {
				appendedSignature := slices.Concat(signatureBytes, []byte{byte(j)})
				if err := verifier.Verify(appendedSignature, data); err == nil {
					t.Errorf("verifier.Verify(%x, data) err = nil, want error", appendedSignature)
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
		})
	}
}

func TestNewRSASSAPKCS1SignerVerifierInvalidInput(t *testing.T) {
	validPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(rand.Reader, 2048) err = %v, want nil", err)
	}
	rsaShortModulusKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("decoding rsa short modulus: %v", err)
	}
	testCases := []struct {
		name    string
		hash    string
		privKey *rsa.PrivateKey
	}{
		{
			name:    "weak signature hash algorithm",
			hash:    "SHA1",
			privKey: validPrivKey,
		},
		{
			name: "invalid public key exponent",
			hash: "SHA256",
			privKey: &rsa.PrivateKey{
				D:           validPrivKey.D,
				Primes:      validPrivKey.Primes,
				Precomputed: validPrivKey.Precomputed,
				PublicKey: rsa.PublicKey{
					N: validPrivKey.PublicKey.N,
					E: 3,
				},
			},
		},
		{
			name:    "small modulus size",
			hash:    "SHA256",
			privKey: rsaShortModulusKey,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := internal.New_RSA_SSA_PKCS1_Signer(tc.hash, tc.privKey); err == nil {
				t.Errorf("New_RSA_SSA_PKCS1_Signer() err = nil, want error")
			}
			if _, err := internal.New_RSA_SSA_PKCS1_Verifier(tc.hash, &tc.privKey.PublicKey); err == nil {
				t.Errorf("New_RSA_SSA_PKCS1_Verifier() err = nil, want error")
			}
		})
	}
}

type rsaSSAPKCS1Suite struct {
	wycheproof.Suite
	TestGroups []*rsaSSAPKCS1Group `json:"testGroups"`
}

type rsaSSAPKCS1Group struct {
	wycheproof.Group
	SHA       string                `json:"sha"`
	PublicKey *rsaSSAPKCS1PublicKey `json:"publicKey"`
	Tests     []*rsaSSAPKCS1Case    `json:"tests"`
}

type rsaSSAPKCS1Case struct {
	wycheproof.Case
	Message   testutil.HexBytes `json:"msg"`
	Signature testutil.HexBytes `json:"sig"`
}

type rsaSSAPKCS1PublicKey struct {
	PublicExponent testutil.HexBytes `json:"publicExponent"`
	Modulus        testutil.HexBytes `json:"modulus"`
}

func TestRSASSAPKCS1WycheproofCases(t *testing.T) {
	testsRan := 0
	for _, v := range []string{
		"rsa_signature_2048_sha256_test.json",
		"rsa_signature_3072_sha512_test.json",
		"rsa_signature_4096_sha512_test.json",
	} {
		suite := &rsaSSAPKCS1Suite{}
		wycheproof.PopulateSuiteV1(t, suite, v)

		for _, group := range suite.TestGroups {
			hash := subtle.ConvertHashName(group.SHA)
			if hash == "" {
				t.Fatalf("invalid hash name")
			}
			publicKey := &rsa.PublicKey{
				E: int(new(big.Int).SetBytes(group.PublicKey.PublicExponent).Uint64()),
				N: new(big.Int).SetBytes(group.PublicKey.Modulus),
			}
			if publicKey.E != 65537 {
				// golang "crypto/rsa" only supports 65537 as an exponent.
				if _, err := internal.New_RSA_SSA_PKCS1_Verifier(hash, publicKey); err == nil {
					t.Errorf("NewRSASSAPKCS1Verifier() err = nil, want error")
				}
				continue
			}
			verifier, err := internal.New_RSA_SSA_PKCS1_Verifier(hash, publicKey)
			if err != nil {
				t.Fatalf("NewRSASSAPKCS1Verifier() err = %v, want nil", err)
			}
			for _, test := range group.Tests {
				caseName := fmt.Sprintf("%s: %s-%s:Case-%d", v, group.Type, group.SHA, test.CaseID)
				t.Run(caseName, func(t *testing.T) {
					testsRan++
					err := verifier.Verify(test.Signature, test.Message)
					switch test.Result {
					case "valid":
						if err != nil {
							t.Errorf("Verify() err = %v, want nil", err)
						}
					case "invalid":
						if err == nil {
							t.Errorf("Verify() err = nil, want error")
						}
					case "acceptable":
						// TODO(b/230489047): Inspect flags to appropriately handle acceptable test cases.
					default:
						t.Errorf("unsupported test result: %q", test.Result)
					}
				})
			}
		}
	}
	if testsRan != 775 {
		t.Errorf("testsRan = %d, want = %d", testsRan, 775)
	}
}

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

package hpke_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/hybrid/hpke"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
)

type hybridEncryptTestVector struct {
	name        string
	privateKey  *hpke.PrivateKey
	plaintext   []byte
	contextInfo []byte
	ciphertext  []byte
}

// hybridTestVectors creates test vectors for HPKE.
//
// This are the same as
// https://github.com/tink-crypto/tink-cc/blob/v2.3.0/tink/hybrid/internal/testing/hpke_test_vectors.cc.
func hybridTestVectors(t *testing.T) []hybridEncryptTestVector {
	t.Helper()
	return []hybridEncryptTestVector{
		hybridEncryptTestVector{
			name: "DHKEM(P256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, No Prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 0, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantNoPrefix,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9ba742"+
				"34494b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c1"+
				"15cf17875f59b069dffc8427cfb7f277ed4e370ae78f916e22"),
		},
		hybridEncryptTestVector{
			name: "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, No Prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"),
				mustCreatePublicKey(t, mustHexDecode(t, "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"), 0, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantNoPrefix,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "c202f5f26a59c446531b9e4e880f8730ff0aed444699cb1cd69a2c60e"+
				"07aba42d77a29b62c7af6b2cfda9c1529bb8d23c8"),
		},
		hybridEncryptTestVector{
			name: "DHKEM(P256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, No Prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 0, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantNoPrefix,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "04b2de5915aa2bde7ad85745a632258caba46ed5be81297177dae45cd"+
				"cbcf49c92431ea80763f92f6b22115723a7d092994d40376f7618e9f2"+
				"ef82d5c44036e29eca440814ade6c8d5d9246abddaf5740331"),
		},
		hybridEncryptTestVector{
			name: "DHKEM(P256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, No Prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 0, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.ChaCha20Poly1305,
					Variant: hpke.VariantNoPrefix,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "04e0f41a312164058e2c36f1bc977e12a6fec8b13dc5fabc2441ec905"+
				"bc432145a0a5e50929815ec6944a3da1a186c0b9b428232086b218af0"+
				"61e9f814d8bd27808bce0bdb3c656d307f87ffe3bf13b0eb19"),
		},
		hybridEncryptTestVector{
			name: "DHKEM(P256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, Tink",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 0x886688aa, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "01886688aa04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9ba7423"+
				"4494b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c115cf17875f59"+
				"b069dffc8427cfb7f277ed4e370ae78f916e22"),
		},
		hybridEncryptTestVector{
			name: "DHKEM(P256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, Crunchy",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 0x886688aa, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantCrunchy,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "00886688aa04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9ba7423"+
				"4494b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c115cf17875f59"+
				"b069dffc8427cfb7f277ed4e370ae78f916e22"),
		},
	}
}

func TestEncryptDecrypt(t *testing.T) {
	for _, tc := range hybridTestVectors(t) {
		t.Run(tc.name, func(t *testing.T) {
			publicKey, err := tc.privateKey.PublicKey()
			if err != nil {
				t.Fatalf("tc.privateKey.PublicKey() err = %v, want nil", err)
			}
			encrypter, err := hpke.NewHybridEncrypt(publicKey.(*hpke.PublicKey), internalapi.Token{})
			if err != nil {
				t.Fatalf("hpke.NewHybridEncrypt() err = %v, want nil", err)
			}
			decrypter, err := hpke.NewHybridDecrypt(tc.privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("hpke.NewHybridDecrypt() err = %v, want nil", err)
			}
			// Decrypt the ciphertext generated by the encrypter.
			{
				gotCiphertext, err := encrypter.Encrypt(tc.plaintext, tc.contextInfo)
				if err != nil {
					t.Fatalf("encrypter.Encrypt() err = %v, want nil", err)
				}
				gotDecrypted, err := decrypter.Decrypt(gotCiphertext, tc.contextInfo)
				if err != nil {
					t.Fatalf("decrypter.Decrypt() err = %v, want nil", err)
				}
				if diff := cmp.Diff(gotDecrypted, tc.plaintext); diff != "" {
					t.Errorf("decrypter.Decrypt() returned unexpected diff (-want +got):\n%s", diff)
				}
			}
			// Decrypt the test case ciphertext.
			{
				gotDecrypted, err := decrypter.Decrypt(tc.ciphertext, tc.contextInfo)
				if err != nil {
					t.Fatalf("decrypter.Decrypt() err = %v, want nil", err)
				}
				if diff := cmp.Diff(gotDecrypted, tc.plaintext); diff != "" {
					t.Errorf("decrypter.Decrypt() returned unexpected diff (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func mustEncrypt(t *testing.T, publicKey *hpke.PublicKey, plaintext, contextInfo []byte) []byte {
	t.Helper()
	encrypter, err := hpke.NewHybridEncrypt(publicKey, internalapi.Token{})
	if err != nil {
		t.Fatalf("hpke.NewHybridEncrypt() err = %v, want nil", err)
	}
	ciphertext, err := encrypter.Encrypt(plaintext, contextInfo)
	if err != nil {
		t.Fatalf("encrypter.Encrypt() err = %v, want nil", err)
	}
	return ciphertext
}

func TestDecryptFails(t *testing.T) {
	data := []byte("plaintext")
	contextInfo := []byte("context")
	for _, tc := range []struct {
		name       string
		publicKey  *hpke.PublicKey
		privateKey *hpke.PrivateKey
		ciphertext []byte
	}{
		{
			name: "different prefix type",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				}))),
			ciphertext: mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123, mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES128GCM,
				Variant: hpke.VariantCrunchy,
			})), data, contextInfo),
		},
		{
			name: "missing prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				}))),
			ciphertext: mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 0, mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES128GCM,
				Variant: hpke.VariantNoPrefix,
			})), data, contextInfo),
		},
		{
			name: "mismatched key ID",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				}))),
			ciphertext: mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 456, mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES128GCM,
				Variant: hpke.VariantTink,
			})), data, contextInfo),
		},
		{
			name: "different DEM",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				}))),
			ciphertext: mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123, mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			})), data, contextInfo),
		},
		{
			name: "invalid ciphertext",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				}))),
			ciphertext: func() []byte {
				ciphertext := mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 456, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				})), data, contextInfo)
				ciphertext[5] ^= 1
				return ciphertext
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decrypter, err := hpke.NewHybridDecrypt(tc.privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("hpke.NewHybridDecrypt(%v) err = %v, want nil", tc.publicKey, err)
			}
			if _, err := decrypter.Decrypt(tc.ciphertext, contextInfo); err == nil {
				t.Errorf("decrypter.Decrypt(%v, %v) err = nil, want error", tc.ciphertext, contextInfo)
			}
		})
	}
}

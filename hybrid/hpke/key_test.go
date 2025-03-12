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
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/hybrid/hpke"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

type keyTestCase struct {
	name            string
	params          *hpke.Parameters
	publicKeyBytes  []byte
	privateKeyBytes secretdata.Bytes
	idRequirement   uint32

	wantOutputPrefix []byte
}

func mustCreateParameters(t *testing.T, opts hpke.ParametersOpts) *hpke.Parameters {
	t.Helper()
	params, err := hpke.NewParameters(opts)
	if err != nil {
		t.Fatalf("hpke.NewParameters() err = %v, want nil", err)
	}
	return params
}

func mustHexDecode(t *testing.T, hexString string) []byte {
	t.Helper()
	b, err := hex.DecodeString(hexString)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", hexString, err)
	}
	return b
}

var (
	// From https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.1
	x25519PublicKeyBytesHex  = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
	x25519PrivateKeyBytesHex = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"

	// From https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.3
	p256SHA256PublicKeyBytesHex = "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32" +
		"5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
	p256SHA256PrivateKeyBytesHex = "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb"

	// From https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.6
	p521SHA512PublicKeyBytesHex = "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8" +
		"900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731" +
		"ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0" +
		"692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0"
	p521SHA512PrivateKeyBytesHex = "014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d5354" +
		"15a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b"
)

func mustCreateKeyTestCases(t *testing.T) []keyTestCase {
	t.Helper()
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	x25519PrivateKeyBytes := mustHexDecode(t, x25519PrivateKeyBytesHex)

	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)
	p256SHA256PrivateKeyBytes := mustHexDecode(t, p256SHA256PrivateKeyBytesHex)

	p384Key, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.P384().GenerateKey() err = %v, want nil", err)
	}
	p384PublicKeyBytes := p384Key.PublicKey().Bytes()
	p384PrivateKeyBytes := p384Key.Bytes()

	p521SHA512PublicKeyBytes := mustHexDecode(t, p521SHA512PublicKeyBytesHex)
	p521SHA512PrivateKeyBytes := mustHexDecode(t, p521SHA512PrivateKeyBytesHex)

	testCases := []keyTestCase{
		keyTestCase{
			name: "DHKEM_X25519_HKDF_SHA256-AES256GCM-Tink",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
			publicKeyBytes:   x25519PublicKeyBytes,
			privateKeyBytes:  secretdata.NewBytesFromData(x25519PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "DHKEM_X25519_HKDF_SHA256-AES256GCM-NoPrefix",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
			publicKeyBytes:  x25519PublicKeyBytes,
			privateKeyBytes: secretdata.NewBytesFromData(x25519PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:   0,
		},
		keyTestCase{
			name: "DHKEM_P256_HKDF_SHA256-AES256GCM-Tink",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
			publicKeyBytes:   p256SHA256PublicKeyBytes,
			privateKeyBytes:  secretdata.NewBytesFromData(p256SHA256PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "DHKEM_P256_HKDF_SHA256-AES256GCM-NoPrefix",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
			publicKeyBytes:  p256SHA256PublicKeyBytes,
			privateKeyBytes: secretdata.NewBytesFromData(p256SHA256PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:   0,
		},
		keyTestCase{
			name: "DHKEM_P384_HKDF_SHA384-AES256GCM-Tink",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P384_HKDF_SHA384,
				KDFID:   hpke.HKDFSHA384,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
			publicKeyBytes:   p384PublicKeyBytes,
			privateKeyBytes:  secretdata.NewBytesFromData(p384PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "DHKEM_P384_HKDF_SHA384-AES256GCM-NoPrefix",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P384_HKDF_SHA384,
				KDFID:   hpke.HKDFSHA384,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
			publicKeyBytes:  p384PublicKeyBytes,
			privateKeyBytes: secretdata.NewBytesFromData(p384PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:   0,
		},
		keyTestCase{
			name: "DHKEM_P521_HKDF_SHA512-AES256GCM-Tink",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P521_HKDF_SHA512,
				KDFID:   hpke.HKDFSHA512,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
			publicKeyBytes:   p521SHA512PublicKeyBytes,
			privateKeyBytes:  secretdata.NewBytesFromData(p521SHA512PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "DHKEM_P521_HKDF_SHA512-AES256GCM-Crunchy",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P521_HKDF_SHA512,
				KDFID:   hpke.HKDFSHA512,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantCrunchy,
			}),
			publicKeyBytes:   p521SHA512PublicKeyBytes,
			privateKeyBytes:  secretdata.NewBytesFromData(p521SHA512PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "DHKEM_P521_HKDF_SHA512-AES256GCM-NoPrefix",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P521_HKDF_SHA512,
				KDFID:   hpke.HKDFSHA512,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
			publicKeyBytes:  p521SHA512PublicKeyBytes,
			privateKeyBytes: secretdata.NewBytesFromData(p521SHA512PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:   0,
		},
	}
	return testCases
}

func TestNewPublicKeyFailsWithInvalidValues(t *testing.T) {
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)

	for _, tc := range []struct {
		name           string
		params         *hpke.Parameters
		publicKeyBytes []byte
		idRequirement  uint32
	}{
		{
			name:           "invalid public key bytes",
			publicKeyBytes: []byte("invalid"),
			idRequirement:  0x123456,
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
		},
		{
			name: "corrupted public key bytes",
			publicKeyBytes: func() []byte {
				// Corrupt the last byte.
				key := slices.Clone(p256SHA256PublicKeyBytes)
				key[len(key)-1] ^= 1
				return key
			}(),
			idRequirement: 0x123456,
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
		},
		{
			name:           "incompatible public key bytes for X25519",
			publicKeyBytes: p256SHA256PublicKeyBytes,
			idRequirement:  0x123456,
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
		},
		{
			name:           "incompatible public key bytes for NIST P-256",
			publicKeyBytes: x25519PublicKeyBytes,
			idRequirement:  0x123456,
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hpke.NewPublicKey(tc.publicKeyBytes, tc.idRequirement, tc.params)
			if err == nil {
				t.Errorf("hpke.NewPublicKey(%v, %v, %v) err = nil, want non-nil", tc.publicKeyBytes, tc.idRequirement, tc.params)
			}
		})
	}
}

func TestNewPublicKey(t *testing.T) {
	testCases := mustCreateKeyTestCases(t)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := hpke.NewPublicKey(tc.publicKeyBytes, tc.idRequirement, tc.params)
			if err != nil {
				t.Fatalf("hpke.NewPublicKey(%v, %v, %v) err = %v, want nil", tc.publicKeyBytes, tc.idRequirement, tc.params, err)
			}
			if got, want := key.PublicKeyBytes(), tc.publicKeyBytes; !bytes.Equal(got, want) {
				t.Errorf("key.PublicKeyBytes() = %v, want %v", got, want)
			}
			if got, want := key.Parameters(), tc.params; !got.Equal(want) {
				t.Errorf("key.Parameters() = %v, want %v", got, want)
			}
			if got, want := key.OutputPrefix(), tc.wantOutputPrefix; !bytes.Equal(got, want) {
				t.Errorf("key.OutputPrefix() = %v, want %v", got, want)
			}
			gotIDRequirement, gotRequired := key.IDRequirement()
			if got, want := gotRequired, tc.params.HasIDRequirement(); got != want {
				t.Errorf("key.IDRequirement() = _, %v, want %v", got, want)
			}
			if got, want := gotIDRequirement, tc.idRequirement; got != want {
				t.Errorf("key.IDRequirement() = %v, _, want %v", got, want)
			}
			otherPubKey, err := hpke.NewPublicKey(tc.publicKeyBytes, tc.idRequirement, tc.params)
			if err != nil {
				t.Fatalf("hpke.NewPublicKey(%v, %v, %v) err = %v, want nil", tc.publicKeyBytes, tc.idRequirement, tc.params, err)
			}
			if !otherPubKey.Equal(key) {
				t.Errorf("otherPubKey.Equal(key) = false, want true")
			}
		})
	}
}

func TestPublicKeyNotEqual(t *testing.T) {
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	// From https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.2
	x25519PublicKeyBytes2 := mustHexDecode(t, "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)

	type keyTestCase struct {
		params         *hpke.Parameters
		publicKeyBytes []byte
		idRequirement  uint32
	}

	for _, tc := range []struct {
		name string
		key1 keyTestCase
		key2 keyTestCase
	}{
		{
			name: "Different HPKE parameters KDFID",
			key1: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
			key2: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA384,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
		},
		{
			name: "Different HPKE parameters variant",
			key1: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
			key2: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantCrunchy,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
		},
		{
			name: "Different ID requirement",
			key1: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				}),
				publicKeyBytes: p256SHA256PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
			key2: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				}),
				publicKeyBytes: p256SHA256PublicKeyBytes,
				idRequirement:  uint32(0x05060708),
			},
		},
		{
			name: "Different public key bytes",
			key1: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
			key2: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes2,
				idRequirement:  uint32(0x01020304),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicKey1, err := hpke.NewPublicKey(tc.key1.publicKeyBytes, tc.key1.idRequirement, tc.key1.params)
			if err != nil {
				t.Fatalf("hpke.NewPublicKey(%x, %v, %v) err = %v, want nil", tc.key1.publicKeyBytes, tc.key1.idRequirement, tc.key1.params, err)
			}
			publicKey2, err := hpke.NewPublicKey(tc.key2.publicKeyBytes, tc.key2.idRequirement, tc.key2.params)
			if err != nil {
				t.Fatalf("hpke.NewPublicKey(%x, %v, %v) err = %v, want nil", tc.key2.publicKeyBytes, tc.key2.idRequirement, tc.key2.params, err)
			}
			if publicKey1.Equal(publicKey2) {
				t.Errorf("publicKey1.Equal(publicKey2) = true, want false")
			}
		})
	}
}

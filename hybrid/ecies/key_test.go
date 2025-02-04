// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ecies_test

import (
	"bytes"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcmsiv"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/hybrid/ecies"
)

type keyTestCase struct {
	name           string
	params         *ecies.Parameters
	publicKeyBytes []byte
	idRequirement  uint32

	wantOutputPrefix []byte
}

func mustCreateParameters(t *testing.T, opts ecies.ParametersOpts) *ecies.Parameters {
	t.Helper()
	params, err := ecies.NewParameters(opts)
	if err != nil {
		t.Fatalf("ecies.NewParameters() err = %v, want nil", err)
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
	x25519PublicKeyBytesHex = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
	// From https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.3
	p256SHA256PublicKeyBytesHex = "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32" +
		"5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
	// From https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.4
	p256SHA512PublicKeyBytesHex = "0493ed86735bdfb978cc055c98b45695ad7ce61ce748f4dd63c525a3b8d53a" +
		"15565c6897888070070c1579db1f86aaa56deb8297e64db7e8924e72866f9a472580"
	// From https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.6
	p521SHA512PublicKeyBytesHex = "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8" +
		"900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731" +
		"ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0" +
		"692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0"
)

func mustCreatePublicKeyTestCases(t *testing.T) []keyTestCase {
	t.Helper()
	demParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}

	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)
	p256SHA512PublicKeyBytes := mustHexDecode(t, p256SHA512PublicKeyBytesHex)
	p521SHA512PublicKeyBytes := mustHexDecode(t, p521SHA512PublicKeyBytesHex)

	testCases := []keyTestCase{
		keyTestCase{
			name: "X25519-SHA256-Tink",
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.X25519,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantTink,
			}),
			publicKeyBytes:   x25519PublicKeyBytes,
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "X25519-SHA256-NoPrefix",
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.X25519,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantNoPrefix,
			}),
			publicKeyBytes: x25519PublicKeyBytes,
			idRequirement:  0,
		},
		keyTestCase{
			name: "NISTP256-SHA256-Tink",
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantTink,
			}),
			publicKeyBytes:   p256SHA256PublicKeyBytes,
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "NISTP256-SHA256-NoPrefix",
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UncompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantNoPrefix,
			}),
			publicKeyBytes: p256SHA256PublicKeyBytes,
			idRequirement:  0,
		},
		keyTestCase{
			name: "NISTP256-SHA512-Tink",
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA512,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantTink,
			}),
			publicKeyBytes:   p256SHA512PublicKeyBytes,
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "NISTP256-SHA512-NoPrefix",
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA512,
				NISTCurvePointFormat: ecies.UncompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantNoPrefix,
			}),
			publicKeyBytes: p256SHA512PublicKeyBytes,
			idRequirement:  0,
		},
		keyTestCase{
			name: "NISTP521-SHA512-Tink",
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP521,
				HashType:             ecies.SHA512,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantTink,
			}),
			publicKeyBytes:   p521SHA512PublicKeyBytes,
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "NISTP521-SHA512-Crunchy",
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP521,
				HashType:             ecies.SHA512,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantCrunchy,
			}),
			publicKeyBytes:   p521SHA512PublicKeyBytes,
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "NISTP521-SHA512-NoPrefix",
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP521,
				HashType:             ecies.SHA512,
				NISTCurvePointFormat: ecies.UncompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantNoPrefix,
			}),
			publicKeyBytes: p521SHA512PublicKeyBytes,
			idRequirement:  0,
		},
	}
	return testCases
}

func TestNewPublicKeyFailsWithInvalidValues(t *testing.T) {
	demParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}

	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)

	for _, tc := range []struct {
		name           string
		params         *ecies.Parameters
		publicKeyBytes []byte
		idRequirement  uint32
	}{
		{
			name:           "invalid public key bytes",
			publicKeyBytes: []byte("invalid"),
			idRequirement:  0x123456,
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.X25519,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantTink,
			}),
		},
		{
			name:           "invalid prefix variant",
			publicKeyBytes: x25519PublicKeyBytes,
			idRequirement:  0x123456,
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.X25519,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantNoPrefix,
			}),
		},
		{
			name:           "invalid public key bytes - too short",
			publicKeyBytes: []byte("invalid"),
			idRequirement:  0x123456,
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantTink,
			}),
		},
		{
			name: "invalid public key bytes",
			publicKeyBytes: func() []byte {
				// Corrupt the last byte.
				key := slices.Clone(p256SHA256PublicKeyBytes)
				key[len(key)-1] ^= 1
				return key
			}(),
			idRequirement: 0x123456,
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantTink,
			}),
		},
		{
			name:           "incompatible public key bytes for X25519",
			publicKeyBytes: p256SHA256PublicKeyBytes,
			idRequirement:  0x123456,
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.X25519,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantTink,
			}),
		},
		{
			name:           "incompatible public key bytes for NIST P-256",
			publicKeyBytes: x25519PublicKeyBytes,
			idRequirement:  0x123456,
			params: mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantTink,
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ecies.NewPublicKey(tc.publicKeyBytes, tc.idRequirement, tc.params)
			if err == nil {
				t.Errorf("ecies.NewPublicKey(%v, %v, %v) err = nil, want non-nil", tc.publicKeyBytes, tc.idRequirement, tc.params)
			}
		})
	}
}

func TestNewPublicKey(t *testing.T) {
	testCases := mustCreatePublicKeyTestCases(t)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecies.NewPublicKey(tc.publicKeyBytes, tc.idRequirement, tc.params)
			if err != nil {
				t.Fatalf("ecies.NewPublicKey(%v, %v, %v) err = %v, want nil", tc.publicKeyBytes, tc.idRequirement, tc.params, err)
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
			otherPubKey, err := ecies.NewPublicKey(tc.publicKeyBytes, tc.idRequirement, tc.params)
			if err != nil {
				t.Fatalf("ecies.NewPublicKey(%v, %v, %v) err = %v, want nil", tc.publicKeyBytes, tc.idRequirement, tc.params, err)
			}
			if !otherPubKey.Equal(key) {
				t.Errorf("otherPubKey.Equal(key) = false, want true")
			}

		})
	}
}

func TestPublicKeyNotEqual(t *testing.T) {
	aesGCMDEMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	aesGCMSIVDEMParams, err := aesgcmsiv.NewParameters(32, aesgcmsiv.VariantNoPrefix)
	if err != nil {
		t.Fatalf("aesgcmsiv.NewParameters() err = %v, want nil", err)
	}

	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	// From
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/x25519_test.json#L56
	x25519PublicKeyBytes2 := mustHexDecode(t, "0b8211a2b6049097f6871c6c052d3c5fc1ba17da9e32ae458403b05bb283092a")
	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)

	type keyTestCase struct {
		params         *ecies.Parameters
		publicKeyBytes []byte
		idRequirement  uint32
	}

	for _, tc := range []struct {
		name string
		key1 keyTestCase
		key2 keyTestCase
	}{
		{
			name: "Different ECIES parameters - DEM parameters",
			key1: keyTestCase{
				params: mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.X25519,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
					DEMParameters:        aesGCMDEMParams,
					Variant:              ecies.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
			key2: keyTestCase{
				params: mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.X25519,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
					DEMParameters:        aesGCMSIVDEMParams,
					Variant:              ecies.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
		},
		{
			name: "Different ECIES parameters - variant",
			key1: keyTestCase{
				params: mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.X25519,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
					DEMParameters:        aesGCMDEMParams,
					Variant:              ecies.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
			key2: keyTestCase{
				params: mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.X25519,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
					DEMParameters:        aesGCMDEMParams,
					Variant:              ecies.VariantCrunchy,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
		},
		{
			name: "Different ID requirement",
			key1: keyTestCase{
				params: mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.CompressedPointFormat,
					DEMParameters:        aesGCMDEMParams,
					Variant:              ecies.VariantTink,
				}),
				publicKeyBytes: p256SHA256PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
			key2: keyTestCase{
				params: mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.CompressedPointFormat,
					DEMParameters:        aesGCMDEMParams,
					Variant:              ecies.VariantTink,
				}),
				publicKeyBytes: p256SHA256PublicKeyBytes,
				idRequirement:  uint32(0x05060708),
			},
		},
		{
			name: "Different public key bytes",
			key1: keyTestCase{
				params: mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.X25519,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
					DEMParameters:        aesGCMDEMParams,
					Variant:              ecies.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
			key2: keyTestCase{
				params: mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.X25519,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
					DEMParameters:        aesGCMDEMParams,
					Variant:              ecies.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes2,
				idRequirement:  uint32(0x01020304),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicKey1, err := ecies.NewPublicKey(tc.key1.publicKeyBytes, tc.key1.idRequirement, tc.key1.params)
			if err != nil {
				t.Fatalf("ecies.NewPublicKey(%x, %v, %v) err = %v, want nil", tc.key1.publicKeyBytes, tc.key1.idRequirement, tc.key1.params, err)
			}
			publicKey2, err := ecies.NewPublicKey(tc.key2.publicKeyBytes, tc.key2.idRequirement, tc.key2.params)
			if err != nil {
				t.Fatalf("ecies.NewPublicKey(%x, %v, %v) err = %v, want nil", tc.key2.publicKeyBytes, tc.key2.idRequirement, tc.key2.params, err)
			}
			if publicKey1.Equal(publicKey2) {
				t.Errorf("publicKey1.Equal(publicKey2) = true, want false")
			}
		})
	}
}

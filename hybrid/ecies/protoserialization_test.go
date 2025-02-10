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

package ecies

import (
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	eciespb "github.com/tink-crypto/tink-go/v2/proto/ecies_aead_hkdf_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

type testParams struct{}

func (p *testParams) HasIDRequirement() bool { return true }

func (p *testParams) Equal(params key.Parameters) bool { return true }

type testKey struct{}

func (k *testKey) Parameters() key.Parameters { return &testParams{} }

func (k *testKey) Equal(other key.Key) bool { return true }

func (k *testKey) IDRequirement() (uint32, bool) { return 123, true }

func TestSerializePublicKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name      string
		publicKey key.Key
	}{
		{
			name:      "nil key",
			publicKey: nil,
		},
		{
			name:      "invalid public key",
			publicKey: &PublicKey{},
		},
		{
			name:      "incorrect key type",
			publicKey: &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &publicKeySerializer{}
			if _, err := s.SerializeKey(tc.publicKey); err == nil {
				t.Errorf("s.SerializeKey(%v) err = nil, want non-nil", tc.publicKey)
			}
		})
	}
}

func mustCreateKeySerialization(t *testing.T, url string, keyMaterialType tinkpb.KeyData_KeyMaterialType, keyMessage proto.Message, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	serializedKey, err := proto.Marshal(keyMessage)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", keyMessage, err)
	}
	keyData := &tinkpb.KeyData{
		TypeUrl:         url,
		Value:           serializedKey,
		KeyMaterialType: keyMaterialType,
	}
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

type testCase struct {
	name                   string
	publicKey              *PublicKey
	publicKeySerialization *protoserialization.KeySerialization
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

func mustHexDecode(t *testing.T, hexString string) []byte {
	t.Helper()
	b, err := hex.DecodeString(hexString)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", hexString, err)
	}
	return b
}

func mustCreatePublicKey(t *testing.T, publicKeyBytes []byte, idRequirement uint32, params *Parameters) *PublicKey {
	t.Helper()
	pk, err := NewPublicKey(publicKeyBytes, idRequirement, params)
	if err != nil {
		t.Fatalf("NewPublicKey() err = %v, want nil", err)
	}
	return pk
}

func mustCreateParameters(t *testing.T, opts ParametersOpts) *Parameters {
	t.Helper()
	params, err := NewParameters(opts)
	if err != nil {
		t.Fatalf("NewParameters() err = %v, want nil", err)
	}
	return params
}

func mustCreateTestCases(t *testing.T) []testCase {
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

	// Add a leading 0x00 byte to the coordinates for compatibility with other
	// Tink implementations (see b/264525021).
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)
	p256SHA256PublicKeyX := make([]byte, 33)
	p256SHA256PublicKeyY := make([]byte, 33)
	copy(p256SHA256PublicKeyX[1:], p256SHA256PublicKeyBytes[1:33])
	copy(p256SHA256PublicKeyY[1:], p256SHA256PublicKeyBytes[33:])

	p256SHA512PublicKeyBytes := mustHexDecode(t, p256SHA512PublicKeyBytesHex)
	p256SHA512PublicKeyX := make([]byte, 33)
	p256SHA512PublicKeyY := make([]byte, 33)
	copy(p256SHA512PublicKeyX[1:], p256SHA512PublicKeyBytes[1:33])
	copy(p256SHA512PublicKeyY[1:], p256SHA512PublicKeyBytes[33:])

	p521SHA512PublicKeyBytes := mustHexDecode(t, p521SHA512PublicKeyBytesHex)
	p521SHA512PublicKeyX := make([]byte, 67)
	p521SHA512PublicKeyY := make([]byte, 67)
	copy(p521SHA512PublicKeyX[1:], p521SHA512PublicKeyBytes[1:67])
	copy(p521SHA512PublicKeyY[1:], p521SHA512PublicKeyBytes[67:])

	testCases := []testCase{
		testCase{
			name: "X25519-SHA256-Tink",
			publicKey: mustCreatePublicKey(t, x25519PublicKeyBytes, uint32(0x01020304), mustCreateParameters(t, ParametersOpts{
				CurveType:            X25519,
				HashType:             SHA256,
				NISTCurvePointFormat: UnspecifiedPointFormat,
				DEMParameters:        demParams,
				Variant:              VariantTink,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, publicKeyTypeURL, tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Version: 0,
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_CURVE25519,
							HkdfHashType: commonpb.HashType_SHA256,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_COMPRESSED,
					},
					X: x25519PublicKeyBytes,
				}, tinkpb.OutputPrefixType_TINK, uint32(0x01020304)),
		},
		testCase{
			name: "X25519-SHA256-NoPrefix",
			publicKey: mustCreatePublicKey(t, x25519PublicKeyBytes, 0, mustCreateParameters(t, ParametersOpts{
				CurveType:            X25519,
				HashType:             SHA256,
				NISTCurvePointFormat: UnspecifiedPointFormat,
				DEMParameters:        demParams,
				Variant:              VariantNoPrefix,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, publicKeyTypeURL, tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Version: 0,
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_CURVE25519,
							HkdfHashType: commonpb.HashType_SHA256,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_COMPRESSED,
					},
					X: x25519PublicKeyBytes,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		testCase{
			name: "NISTP256-SHA256-Compressed-Tink",
			publicKey: mustCreatePublicKey(t, p256SHA256PublicKeyBytes, uint32(0x01020304), mustCreateParameters(t, ParametersOpts{
				CurveType:            NISTP256,
				HashType:             SHA256,
				NISTCurvePointFormat: CompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              VariantTink,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, publicKeyTypeURL, tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Version: 0,
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P256,
							HkdfHashType: commonpb.HashType_SHA256,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_COMPRESSED,
					},
					X: p256SHA256PublicKeyX,
					Y: p256SHA256PublicKeyY,
				}, tinkpb.OutputPrefixType_TINK, uint32(0x01020304)),
		},
		testCase{
			name: "NISTP256-SHA256-Uncompressed-NoPrefix",
			publicKey: mustCreatePublicKey(t, p256SHA256PublicKeyBytes, 0, mustCreateParameters(t, ParametersOpts{
				CurveType:            NISTP256,
				HashType:             SHA256,
				NISTCurvePointFormat: UncompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              VariantNoPrefix,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, publicKeyTypeURL, tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Version: 0,
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P256,
							HkdfHashType: commonpb.HashType_SHA256,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
					},
					X: p256SHA256PublicKeyX,
					Y: p256SHA256PublicKeyY,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		testCase{
			name: "NISTP256-SHA512-Compressed-Tink",
			publicKey: mustCreatePublicKey(t, p256SHA512PublicKeyBytes, uint32(0x01020304), mustCreateParameters(t, ParametersOpts{
				CurveType:            NISTP256,
				HashType:             SHA512,
				NISTCurvePointFormat: CompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              VariantTink,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, publicKeyTypeURL, tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Version: 0,
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P256,
							HkdfHashType: commonpb.HashType_SHA512,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_COMPRESSED,
					},
					X: p256SHA512PublicKeyX,
					Y: p256SHA512PublicKeyY,
				}, tinkpb.OutputPrefixType_TINK, uint32(0x01020304)),
		},
		testCase{
			name: "NISTP256-SHA512-Uncompressed-NoPrefix",
			publicKey: mustCreatePublicKey(t, p256SHA512PublicKeyBytes, 0, mustCreateParameters(t, ParametersOpts{
				CurveType:            NISTP256,
				HashType:             SHA512,
				NISTCurvePointFormat: UncompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              VariantNoPrefix,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, publicKeyTypeURL, tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Version: 0,
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P256,
							HkdfHashType: commonpb.HashType_SHA512,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
					},
					X: p256SHA512PublicKeyX,
					Y: p256SHA512PublicKeyY,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		testCase{
			name: "NISTP521-SHA512-Compressed-Tink",
			publicKey: mustCreatePublicKey(t, p521SHA512PublicKeyBytes, uint32(0x01020304), mustCreateParameters(t, ParametersOpts{
				CurveType:            NISTP521,
				HashType:             SHA512,
				NISTCurvePointFormat: CompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              VariantTink,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, publicKeyTypeURL, tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Version: 0,
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P521,
							HkdfHashType: commonpb.HashType_SHA512,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_COMPRESSED,
					},
					X: p521SHA512PublicKeyX,
					Y: p521SHA512PublicKeyY,
				}, tinkpb.OutputPrefixType_TINK, uint32(0x01020304)),
		},
		testCase{
			name: "NISTP521-SHA512-Uncompressed-NoPrefix",
			publicKey: mustCreatePublicKey(t, p521SHA512PublicKeyBytes, 0, mustCreateParameters(t, ParametersOpts{
				CurveType:            NISTP521,
				HashType:             SHA512,
				NISTCurvePointFormat: UncompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              VariantNoPrefix,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, publicKeyTypeURL, tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Version: 0,
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P521,
							HkdfHashType: commonpb.HashType_SHA512,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
					},
					X: p521SHA512PublicKeyX,
					Y: p521SHA512PublicKeyY,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
		testCase{
			name: "NISTP521-SHA512-Uncompressed-NoPrefix",
			publicKey: mustCreatePublicKey(t, p521SHA512PublicKeyBytes, 0, mustCreateParameters(t, ParametersOpts{
				CurveType:            NISTP521,
				HashType:             SHA512,
				NISTCurvePointFormat: UncompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              VariantNoPrefix,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, publicKeyTypeURL, tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				&eciespb.EciesAeadHkdfPublicKey{
					Version: 0,
					Params: &eciespb.EciesAeadHkdfParams{
						KemParams: &eciespb.EciesHkdfKemParams{
							CurveType:    commonpb.EllipticCurveType_NIST_P521,
							HkdfHashType: commonpb.HashType_SHA512,
							HkdfSalt:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
						},
						DemParams: &eciespb.EciesAeadDemParams{
							AeadDem: aead.AES256GCMNoPrefixKeyTemplate(),
						},
						EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
					},
					X: p521SHA512PublicKeyX,
					Y: p521SHA512PublicKeyY,
				}, tinkpb.OutputPrefixType_RAW, 0),
		},
	}
	return testCases
}

func TestSerializePublicKey(t *testing.T) {
	for _, tc := range mustCreateTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			s := &publicKeySerializer{}
			got, err := s.SerializeKey(tc.publicKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(%v) err = nil, want non-nil", tc.publicKey)
			}
			if diff := cmp.Diff(got, tc.publicKeySerialization, protocmp.Transform()); diff != "" {
				t.Errorf("s.SerializeKey(%v) returned unexpected diff (-want +got):\n%s", tc.publicKey, diff)
			}
		})
	}
}

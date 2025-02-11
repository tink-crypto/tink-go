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

package ecies_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/hybrid/ecies"
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
			publicKey: &ecies.PublicKey{},
		},
		{
			name:      "incorrect key type",
			publicKey: &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.SerializeKey(tc.publicKey); err == nil {
				t.Errorf("protoserialization.SerializeKey(%v) err = nil, want non-nil", tc.publicKey)
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

type protoSerializationTestCase struct {
	name                   string
	publicKey              *ecies.PublicKey
	publicKeySerialization *protoserialization.KeySerialization
}

func mustCreateTestCases(t *testing.T) []protoSerializationTestCase {
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

	testCases := []protoSerializationTestCase{
		protoSerializationTestCase{
			name: "X25519-SHA256-Tink",
			publicKey: mustCreatePublicKey(t, x25519PublicKeyBytes, uint32(0x01020304), mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.X25519,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantTink,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
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
		protoSerializationTestCase{
			name: "X25519-SHA256-NoPrefix",
			publicKey: mustCreatePublicKey(t, x25519PublicKeyBytes, 0, mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.X25519,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantNoPrefix,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
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
		protoSerializationTestCase{
			name: "NISTP256-SHA256-Compressed-Tink",
			publicKey: mustCreatePublicKey(t, p256SHA256PublicKeyBytes, uint32(0x01020304), mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantTink,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
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
		protoSerializationTestCase{
			name: "NISTP256-SHA256-Uncompressed-NoPrefix",
			publicKey: mustCreatePublicKey(t, p256SHA256PublicKeyBytes, 0, mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA256,
				NISTCurvePointFormat: ecies.UncompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantNoPrefix,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
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
		protoSerializationTestCase{
			name: "NISTP256-SHA512-Compressed-Tink",
			publicKey: mustCreatePublicKey(t, p256SHA512PublicKeyBytes, uint32(0x01020304), mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA512,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantTink,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
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
		protoSerializationTestCase{
			name: "NISTP256-SHA512-Uncompressed-NoPrefix",
			publicKey: mustCreatePublicKey(t, p256SHA512PublicKeyBytes, 0, mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP256,
				HashType:             ecies.SHA512,
				NISTCurvePointFormat: ecies.UncompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantNoPrefix,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
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
		protoSerializationTestCase{
			name: "NISTP521-SHA512-Compressed-Tink",
			publicKey: mustCreatePublicKey(t, p521SHA512PublicKeyBytes, uint32(0x01020304), mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP521,
				HashType:             ecies.SHA512,
				NISTCurvePointFormat: ecies.CompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantTink,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
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
		protoSerializationTestCase{
			name: "NISTP521-SHA512-Uncompressed-NoPrefix",
			publicKey: mustCreatePublicKey(t, p521SHA512PublicKeyBytes, 0, mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP521,
				HashType:             ecies.SHA512,
				NISTCurvePointFormat: ecies.UncompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantNoPrefix,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
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
		protoSerializationTestCase{
			name: "NISTP521-SHA512-Uncompressed-NoPrefix",
			publicKey: mustCreatePublicKey(t, p521SHA512PublicKeyBytes, 0, mustCreateParameters(t, ecies.ParametersOpts{
				CurveType:            ecies.NISTP521,
				HashType:             ecies.SHA512,
				NISTCurvePointFormat: ecies.UncompressedPointFormat,
				DEMParameters:        demParams,
				Variant:              ecies.VariantNoPrefix,
				Salt:                 []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			})),
			publicKeySerialization: mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
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
			got, err := protoserialization.SerializeKey(tc.publicKey)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", tc.publicKey, err)
			}
			if diff := cmp.Diff(got, tc.publicKeySerialization, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeKey(%v) returned unexpected diff (-want +got):\n%s", tc.publicKey, diff)
			}
		})
	}
}

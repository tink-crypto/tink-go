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

package ecdsa

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func mustCreateKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

const (
	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.5
	pubKeyXP256Hex      = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
	pubKeyYP256Hex      = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
	privKeyValueP256Hex = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
	uncompressedP256Hex = "04" + pubKeyXP256Hex + pubKeyYP256Hex

	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.6
	pubKeyXP384Hex      = "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13"
	pubKeyYP384Hex      = "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720"
	privKeyValueP384Hex = "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5"
	uncompressedP384Hex = "04" + pubKeyXP384Hex + pubKeyYP384Hex

	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.7
	pubKeyXP521Hex      = "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4"
	pubKeyYP521Hex      = "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5"
	privKeyValueP521Hex = "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"
	uncompressedP521Hex = "04" + pubKeyXP521Hex + pubKeyYP521Hex
)

func mustDecodeHex(t *testing.T, hexStr string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex.DecodeString(%v) err = %v, want nil", hexStr, err)
	}
	return decoded
}

func marshalKey(t *testing.T, message proto.Message) []byte {
	serializedProtoPubKey, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("proto.Marshal(message) err = %v, want nil", err)
	}
	return serializedProtoPubKey
}

type testParams struct{}

func (p *testParams) HasIDRequirement() bool { return true }

func (p *testParams) Equals(params key.Parameters) bool { return true }

type testKey struct{}

func (k *testKey) Parameters() key.Parameters { return &testParams{} }

func (k *testKey) Equals(other key.Key) bool { return true }

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

func TestSerializePublicKey(t *testing.T) {
	for _, tc := range testCases(t) {
		if !tc.hasLeadingZeros {
			// We expect coordinates to have a fixed size encoding:
			// 		 x' = 0x00 || x, y' = 0x00 || y
			// With: len(x') = len(y') = coordinateSizeForCurve(tc.publicKey.parameters.curveType) + 1.
			continue
		}
		name := fmt.Sprintf("curveType:%v_hashType:%v_encoding:%v_variant:%v_id:%d", tc.publicKey.parameters.curveType, tc.publicKey.parameters.hashType, tc.publicKey.parameters.signatureEncoding, tc.publicKey.parameters.variant, tc.publicKey.idRequirement)
		t.Run(name, func(t *testing.T) {
			s := &publicKeySerializer{}
			got, err := s.SerializeKey(tc.publicKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(%v) err = nil, want non-nil", tc.publicKey)
			}
			if !got.Equals(tc.publicKeySerialization) {
				t.Errorf("got = %v, want %v", got, tc.publicKeySerialization)
			}
		})
	}
}

func TestParsePublicKeyFails(t *testing.T) {
	xP256, yP256 := mustDecodeHex(t, pubKeyXP256Hex), mustDecodeHex(t, pubKeyYP256Hex)
	protoPublicKey := &ecdsapb.EcdsaPublicKey{
		X: xP256,
		Y: yP256,
		Params: &ecdsapb.EcdsaParams{
			Curve:    commonpb.EllipticCurveType_NIST_P256,
			HashType: commonpb.HashType_SHA256,
			Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
		},
		Version: verifierKeyVersion,
	}
	serializedProtoPublicKey := marshalKey(t, protoPublicKey)
	xP521, yP521 := mustDecodeHex(t, pubKeyXP521Hex), mustDecodeHex(t, pubKeyYP521Hex)

	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name:             "key data is nil",
			keySerialization: mustCreateKeySerialization(t, nil, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong type URL",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "invalid_type_url",
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong key material type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
					X: xP256,
					Y: yP256,
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_NIST_P256,
						HashType: commonpb.HashType_SHA256,
						Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
					},
					Version: verifierKeyVersion + 1,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "point not on curve",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
					X: xP256,
					Y: []byte("00000000000000000000000000000001"),
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_NIST_P256,
						HashType: commonpb.HashType_SHA256,
						Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
					},
					Version: verifierKeyVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "point coordinate after leading 0s removal too long",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
					X: append(xP256, 0x02),
					Y: yP256,
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_NIST_P256,
						HashType: commonpb.HashType_SHA256,
						Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
					},
					Version: verifierKeyVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid point",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
					X: []byte("0"),
					Y: []byte("0"),
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_NIST_P256,
						HashType: commonpb.HashType_SHA256,
						Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
					},
					Version: verifierKeyVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "point from another curve",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
					X: xP521,
					Y: yP521,
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_NIST_P256,
						HashType: commonpb.HashType_SHA256,
						Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
					},
					Version: verifierKeyVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "unknown curve type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
					X: xP256,
					Y: yP256,
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_UNKNOWN_CURVE,
						HashType: commonpb.HashType_SHA256,
						Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
					},
					Version: verifierKeyVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "unknown hash type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
					X: xP256,
					Y: yP256,
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_NIST_P256,
						HashType: commonpb.HashType_UNKNOWN_HASH,
						Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
					},
					Version: verifierKeyVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "unknown encoding",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
					X: xP256,
					Y: yP256,
					Params: &ecdsapb.EcdsaParams{
						Curve:    commonpb.EllipticCurveType_NIST_P256,
						HashType: commonpb.HashType_SHA256,
						Encoding: ecdsapb.EcdsaSignatureEncoding_UNKNOWN_ENCODING,
					},
					Version: verifierKeyVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &publicKeyParser{}
			if _, err := p.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want non-nil", tc.keySerialization)
			} else {
				t.Logf("p.ParseKey(%v) err = %v", tc.keySerialization, err)
			}
		})
	}
}

func mustCreatePublicKey(t *testing.T, uncompressedPoint []byte, idRequirement uint32, params *Parameters) *PublicKey {
	t.Helper()
	outputPrefix, err := calculateOutputPrefix(params.variant, idRequirement)
	if err != nil {
		t.Fatalf("calculateOutputPrefix(%v, %v) err = %v, want nil", params.variant, idRequirement, err)
	}
	return &PublicKey{
		publicPoint:   uncompressedPoint,
		idRequirement: idRequirement,
		outputPrefix:  outputPrefix,
		parameters:    params,
	}
}

func mustCreatePrivateKey(t *testing.T, privateKeyValue secretdata.Bytes, publicKey *PublicKey) *PrivateKey {
	t.Helper()
	privateKey, err := NewPrivateKeyFromPublicKey(publicKey, privateKeyValue)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromPublicKey(%v, %v) err = %v, want nil", publicKey, privateKeyValue, err)
	}
	return privateKey
}

type testCase struct {
	publicKey               *PublicKey
	publicKeySerialization  *protoserialization.KeySerialization
	privateKey              *PrivateKey
	privateKeySerialization *protoserialization.KeySerialization
	hasLeadingZeros         bool
}

func testCases(t *testing.T) []testCase {
	tc := []testCase{}
	for _, variantAndID := range []struct {
		protoPrefixType tinkpb.OutputPrefixType
		variant         Variant
		id              uint32
	}{
		{
			protoPrefixType: tinkpb.OutputPrefixType_TINK,
			variant:         VariantTink,
			id:              123,
		},
		{
			protoPrefixType: tinkpb.OutputPrefixType_LEGACY,
			variant:         VariantLegacy,
			id:              123,
		},
		{
			protoPrefixType: tinkpb.OutputPrefixType_RAW,
			variant:         VariantNoPrefix,
			id:              0,
		},
		{
			protoPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
			variant:         VariantCrunchy,
			id:              123,
		},
	} {
		for _, encoding := range []struct {
			protoEncoding ecdsapb.EcdsaSignatureEncoding
			encoding      SignatureEncoding
		}{
			{
				protoEncoding: ecdsapb.EcdsaSignatureEncoding_DER,
				encoding:      DER,
			},
			{
				protoEncoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
				encoding:      IEEEP1363,
			},
		} {
			for _, curveType := range []commonpb.EllipticCurveType{commonpb.EllipticCurveType_NIST_P256, commonpb.EllipticCurveType_NIST_P384, commonpb.EllipticCurveType_NIST_P521} {
				for _, hasLeadingZeros := range []bool{false, true} {
					token := insecuresecretdataaccess.Token{}
					switch curveType {
					case commonpb.EllipticCurveType_NIST_P256:
						{
							x, y, privateKeyValue := mustDecodeHex(t, pubKeyXP256Hex), mustDecodeHex(t, pubKeyYP256Hex), mustDecodeHex(t, privKeyValueP256Hex)
							uncompressedPoint := mustDecodeHex(t, uncompressedP256Hex)
							publicKey := mustCreatePublicKey(t, uncompressedPoint, variantAndID.id, &Parameters{
								curveType:         NistP256,
								hashType:          SHA256,
								signatureEncoding: encoding.encoding,
								variant:           variantAndID.variant,
							})
							privateKey := mustCreatePrivateKey(t, secretdata.NewBytesFromData(privateKeyValue, token), publicKey)
							var privateKeyValueForProto []byte
							if hasLeadingZeros {
								x = append([]byte{0x00}, x...)
								y = append([]byte{0x00}, y...)
								privateKeyValueForProto = append([]byte{0x00}, privateKeyValue...)
							} else {
								privateKeyValueForProto = privateKeyValue
							}
							protoPublicKey := &ecdsapb.EcdsaPublicKey{
								X: x,
								Y: y,
								Params: &ecdsapb.EcdsaParams{
									Curve:    curveType,
									HashType: commonpb.HashType_SHA256,
									Encoding: encoding.protoEncoding,
								},
								Version: verifierKeyVersion,
							}
							protoPrivateKey := &ecdsapb.EcdsaPrivateKey{
								Version:   signerKeyVersion,
								KeyValue:  privateKeyValueForProto,
								PublicKey: protoPublicKey,
							}
							tc = append(tc, testCase{
								publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         verifierTypeURL,
									Value:           marshalKey(t, protoPublicKey),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
								}, variantAndID.protoPrefixType, variantAndID.id),
								publicKey: publicKey,
								privateKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
									Value:           marshalKey(t, protoPrivateKey),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
								}, variantAndID.protoPrefixType, variantAndID.id),
								privateKey:      privateKey,
								hasLeadingZeros: hasLeadingZeros,
							})
						}
					case commonpb.EllipticCurveType_NIST_P384:
						{
							x, y, privateKeyValue := mustDecodeHex(t, pubKeyXP384Hex), mustDecodeHex(t, pubKeyYP384Hex), mustDecodeHex(t, privKeyValueP384Hex)
							uncompressedPoint := mustDecodeHex(t, uncompressedP384Hex)
							var privateKeyValueForProto []byte
							if hasLeadingZeros {
								x = append([]byte{0x00}, x...)
								y = append([]byte{0x00}, y...)
								privateKeyValueForProto = append([]byte{0x00}, privateKeyValue...)
							} else {
								privateKeyValueForProto = privateKeyValue
							}

							// hashType: SHA384.
							publicKeySHA384 := mustCreatePublicKey(t, uncompressedPoint, variantAndID.id, &Parameters{
								curveType:         NistP384,
								hashType:          SHA384,
								signatureEncoding: encoding.encoding,
								variant:           variantAndID.variant,
							})
							privateKeySHA384 := mustCreatePrivateKey(t, secretdata.NewBytesFromData(privateKeyValue, token), publicKeySHA384)

							protoPublicKeySHA384 := &ecdsapb.EcdsaPublicKey{
								X: x,
								Y: y,
								Params: &ecdsapb.EcdsaParams{
									Curve:    curveType,
									HashType: commonpb.HashType_SHA384,
									Encoding: encoding.protoEncoding,
								},
								Version: verifierKeyVersion,
							}
							protoPrivateKeySHA384 := &ecdsapb.EcdsaPrivateKey{
								Version:   signerKeyVersion,
								KeyValue:  privateKeyValueForProto,
								PublicKey: protoPublicKeySHA384,
							}

							tc = append(tc, testCase{
								publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         verifierTypeURL,
									Value:           marshalKey(t, protoPublicKeySHA384),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
								}, variantAndID.protoPrefixType, variantAndID.id),
								publicKey: publicKeySHA384,
								privateKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
									Value:           marshalKey(t, protoPrivateKeySHA384),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
								}, variantAndID.protoPrefixType, variantAndID.id),
								privateKey:      privateKeySHA384,
								hasLeadingZeros: hasLeadingZeros,
							})

							// hashType: SHA512.
							protoPublicKeySHA512 := &ecdsapb.EcdsaPublicKey{
								X: x,
								Y: y,
								Params: &ecdsapb.EcdsaParams{
									Curve:    curveType,
									HashType: commonpb.HashType_SHA512,
									Encoding: encoding.protoEncoding,
								},
								Version: verifierKeyVersion,
							}
							protoPrivateKeySHA512 := &ecdsapb.EcdsaPrivateKey{
								Version:   signerKeyVersion,
								KeyValue:  privateKeyValueForProto,
								PublicKey: protoPublicKeySHA512,
							}
							publicKeySHA512 := mustCreatePublicKey(t, uncompressedPoint, variantAndID.id, &Parameters{
								curveType:         NistP384,
								hashType:          SHA512,
								signatureEncoding: encoding.encoding,
								variant:           variantAndID.variant,
							})
							privateKeySHA512 := mustCreatePrivateKey(t, secretdata.NewBytesFromData(privateKeyValue, token), publicKeySHA512)

							tc = append(tc, testCase{
								publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         verifierTypeURL,
									Value:           marshalKey(t, protoPublicKeySHA512),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
								}, variantAndID.protoPrefixType, variantAndID.id),
								publicKey: publicKeySHA512,
								privateKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
									Value:           marshalKey(t, protoPrivateKeySHA512),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
								}, variantAndID.protoPrefixType, variantAndID.id),
								privateKey:      privateKeySHA512,
								hasLeadingZeros: hasLeadingZeros,
							})
						}
					case commonpb.EllipticCurveType_NIST_P521:
						{
							x, y, privateKeyValue := mustDecodeHex(t, pubKeyXP521Hex), mustDecodeHex(t, pubKeyYP521Hex), mustDecodeHex(t, privKeyValueP521Hex)
							var privateKeyValueForProto []byte
							if hasLeadingZeros {
								x = append([]byte{0x00}, x...)
								y = append([]byte{0x00}, y...)
								privateKeyValueForProto = append([]byte{0x00}, privateKeyValue...)
							} else {
								privateKeyValueForProto = privateKeyValue
							}
							uncompressedPoint := mustDecodeHex(t, uncompressedP521Hex)
							publicKey := mustCreatePublicKey(t, uncompressedPoint, variantAndID.id, &Parameters{
								curveType:         NistP521,
								hashType:          SHA512,
								signatureEncoding: encoding.encoding,
								variant:           variantAndID.variant,
							})
							protoPublicKey := &ecdsapb.EcdsaPublicKey{
								X: x,
								Y: y,
								Params: &ecdsapb.EcdsaParams{
									Curve:    curveType,
									HashType: commonpb.HashType_SHA512,
									Encoding: encoding.protoEncoding,
								},
								Version: verifierKeyVersion,
							}
							protoPrivateKey := &ecdsapb.EcdsaPrivateKey{
								Version:   signerKeyVersion,
								KeyValue:  privateKeyValueForProto,
								PublicKey: protoPublicKey,
							}

							tc = append(tc, testCase{
								publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         verifierTypeURL,
									Value:           marshalKey(t, protoPublicKey),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
								}, variantAndID.protoPrefixType, variantAndID.id),
								publicKey: publicKey,
								privateKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
									TypeUrl:         "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
									Value:           marshalKey(t, protoPrivateKey),
									KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
								}, variantAndID.protoPrefixType, variantAndID.id),
								privateKey:      mustCreatePrivateKey(t, secretdata.NewBytesFromData(privateKeyValue, token), publicKey),
								hasLeadingZeros: hasLeadingZeros,
							})
						}
					}
				}
			}
		}
	}
	return tc
}

func TestParsePublicKey(t *testing.T) {
	for _, tc := range testCases(t) {
		name := fmt.Sprintf("curveType:%v_hashType:%v_encoding:%v_variant:%v_id:%d_hasLeadingZeros:%v", tc.publicKey.parameters.curveType, tc.publicKey.parameters.hashType, tc.publicKey.parameters.signatureEncoding, tc.publicKey.parameters.variant, tc.publicKey.idRequirement, tc.hasLeadingZeros)
		t.Run(name, func(t *testing.T) {
			p := &publicKeyParser{}
			gotPublicKey, err := p.ParseKey(tc.publicKeySerialization)
			if err != nil {
				t.Fatalf("p.ParseKey(%v) err = %v, want non-nil", tc.publicKeySerialization, err)
			}
			if !gotPublicKey.Equals(tc.publicKey) {
				t.Errorf("%v.Equals(%v) = false, want true", gotPublicKey, tc.publicKey)
			}
		})
	}
	// P521 point with a Y coordinate of 65 bytes.
	// Taken from
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/ecdsa_secp521r1_sha3_512_test.json#L3093.
	pubKeyXP521Hex65Bytes := "01f974fbc98b55c4d39797fe6ff8891eab2aa541e8767a1b9e9eaef1f94895cdf6373c90ccb3643d1b2ef3154b126de937e4343f2409b191c262e3ac1e2577606e58"
	pubKeyYP521Hex65Bytes := "6ed880d925e876beba3102432752ce237b8682c65ceb59902fd6dc7b6f8c728e5078e8676912ae822fda39cb62023fa4fd85bab6d32f3857914aae2d0b7e04e958"
	pubKeyP521Hex65BytesCompressed := "0401f974fbc98b55c4d39797fe6ff8891eab2aa541e8767a1b9e9eaef1f94895cdf6373c90ccb3643d1b2ef3154b126de937e4343f2409b191c262e3ac1e2577606e58006ed880d925e876beba3102432752ce237b8682c65ceb59902fd6dc7b6f8c728e5078e8676912ae822fda39cb62023fa4fd85bab6d32f3857914aae2d0b7e04e958"
	x, y := mustDecodeHex(t, pubKeyXP521Hex65Bytes), mustDecodeHex(t, pubKeyYP521Hex65Bytes)
	uncompressedPoint := mustDecodeHex(t, pubKeyP521Hex65BytesCompressed)
	t.Run("curveType:NIST_P521_hashType:SHA512_encoding:DER_variant:TINK_id:123_YBytesLength:65", func(t *testing.T) {
		publicKeySerialization := mustCreateKeySerialization(t, &tinkpb.KeyData{
			TypeUrl: verifierTypeURL,
			Value: marshalKey(t, &ecdsapb.EcdsaPublicKey{
				X: x,
				Y: y,
				Params: &ecdsapb.EcdsaParams{
					Curve:    commonpb.EllipticCurveType_NIST_P521,
					HashType: commonpb.HashType_SHA512,
					Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
				},
				Version: verifierKeyVersion,
			}),
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
		}, tinkpb.OutputPrefixType_TINK, 123)
		publicKey :=
			mustCreatePublicKey(t, uncompressedPoint, 123, &Parameters{
				curveType:         NistP521,
				hashType:          SHA512,
				signatureEncoding: DER,
				variant:           VariantTink,
			})
		p := &publicKeyParser{}
		gotPublicKey, err := p.ParseKey(publicKeySerialization)
		if err != nil {
			t.Fatalf("p.ParseKey(%v) err = %v, want non-nil", publicKeySerialization, err)
		}
		if !gotPublicKey.Equals(publicKey) {
			t.Errorf("%v.Equals(%v) = false, want true", gotPublicKey, publicKey)
		}
	})
}

func TestParsePrivateKeyFails(t *testing.T) {
	xP256, yP256, privKeyBytesP256 := mustDecodeHex(t, pubKeyXP256Hex), mustDecodeHex(t, pubKeyYP256Hex), mustDecodeHex(t, privKeyValueP256Hex)
	protoPublicKey := &ecdsapb.EcdsaPublicKey{
		X: xP256,
		Y: yP256,
		Params: &ecdsapb.EcdsaParams{
			Curve:    commonpb.EllipticCurveType_NIST_P256,
			HashType: commonpb.HashType_SHA256,
			Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
		},
		Version: verifierKeyVersion,
	}
	protoPrivateKey := &ecdsapb.EcdsaPrivateKey{
		KeyValue:  privKeyBytesP256,
		PublicKey: protoPublicKey,
		Version:   signerKeyVersion,
	}
	serializedProtoPrivateKey, err := proto.Marshal(protoPrivateKey)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPrivateKey, err)
	}

	protoPrivateKeyWithWrongPrivateKeyVersion := &ecdsapb.EcdsaPrivateKey{
		KeyValue:  privKeyBytesP256,
		PublicKey: protoPublicKey,
		Version:   signerKeyVersion + 1,
	}
	serializedProtoPrivateKeyWithWrongPrivateKeyVersion, err := proto.Marshal(protoPrivateKeyWithWrongPrivateKeyVersion)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPrivateKeyWithWrongPrivateKeyVersion, err)
	}

	protoPrivateKeyWithWrongPublicKeyVersion := proto.Clone(protoPrivateKey).(*ecdsapb.EcdsaPrivateKey)
	protoPrivateKeyWithWrongPublicKeyVersion.PublicKey.Version = verifierKeyVersion + 1
	serializedProtoPrivateKeyWithWrongPublicKeyVersion, err := proto.Marshal(protoPrivateKeyWithWrongPublicKeyVersion)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPrivateKeyWithWrongPublicKeyVersion, err)
	}

	protoPrivateKeyWithWrongPublicKeyBytes := proto.Clone(protoPrivateKey).(*ecdsapb.EcdsaPrivateKey)
	protoPrivateKeyWithWrongPublicKeyBytes.PublicKey.X = []byte("12345678901234567890123456789012")
	serializedProtoPrivateKeyWithWrongPublicKeyBytes, err := proto.Marshal(protoPrivateKeyWithWrongPublicKeyBytes)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPrivateKeyWithWrongPublicKeyBytes, err)
	}

	protoPrivateKeyWithPublicKeyTooSmall := proto.Clone(protoPrivateKey).(*ecdsapb.EcdsaPrivateKey)
	protoPrivateKeyWithPublicKeyTooSmall.PublicKey.X = []byte("123")
	serializedProtoPrivateKeyWithPublicKeyTooSmall, err := proto.Marshal(protoPrivateKeyWithPublicKeyTooSmall)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPrivateKeyWithPublicKeyTooSmall, err)
	}

	protoPrivateKeyWithPrivateKeyWithInvalidPrefix := proto.Clone(protoPrivateKey).(*ecdsapb.EcdsaPrivateKey)
	protoPrivateKeyWithPrivateKeyWithInvalidPrefix.KeyValue = append([]byte{0x00, 0x00, 0x01, 0x00}, protoPrivateKeyWithPrivateKeyWithInvalidPrefix.KeyValue...)
	serializedProtoPrivateKeyWithPrivateKeyWithInvalidPrefix, err := proto.Marshal(protoPrivateKeyWithPrivateKeyWithInvalidPrefix)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPrivateKeyWithPrivateKeyWithInvalidPrefix, err)
	}

	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name:             "key data is nil",
			keySerialization: mustCreateKeySerialization(t, nil, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong type URL",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "invalid_type_url",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_UNKNOWN_PREFIX, 12345),
		},
		{
			name: "wrong private key material type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong private key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
				Value:           serializedProtoPrivateKeyWithWrongPrivateKeyVersion,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong private key prefix",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
				Value:           serializedProtoPrivateKeyWithPrivateKeyWithInvalidPrefix,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong public key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
				Value:           serializedProtoPrivateKeyWithWrongPublicKeyVersion,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong public key too small",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
				Value:           serializedProtoPrivateKeyWithPublicKeyTooSmall,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong public key",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
				Value:           serializedProtoPrivateKeyWithWrongPublicKeyBytes,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &privateKeyParser{}
			if _, err = p.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want non-nil", tc.keySerialization)
			}
		})
	}
}

func TestParsePrivateKey(t *testing.T) {
	for _, tc := range testCases(t) {
		name := fmt.Sprintf("curveType:%v_hashType:%v_encoding:%v_variant:%v_id:%d_hasLeadingZeros:%v", tc.publicKey.parameters.curveType, tc.publicKey.parameters.hashType, tc.publicKey.parameters.signatureEncoding, tc.publicKey.parameters.variant, tc.publicKey.idRequirement, tc.hasLeadingZeros)
		t.Run(name, func(t *testing.T) {
			p := &privateKeyParser{}
			gotPrivateKey, err := p.ParseKey(tc.privateKeySerialization)
			if err != nil {
				t.Fatalf("p.ParseKey(%v) err = %v, want non-nil", tc.privateKeySerialization, err)
			}
			if !gotPrivateKey.Equals(tc.privateKey) {
				t.Errorf("%v.Equals(%v) = false, want true", gotPrivateKey, tc.privateKey)
			}
		})
	}
	// Make sure we can parse private keys where the private key value size is
	// smaller than the coordinate size.
	t.Run("curveType:NIST_P521_hashType:SHA512_encoding:DER_variant:TINK_id:12345_hasLeadingZeros:true_PrivateKeyBytesLength:65", func(t *testing.T) {
		xP521, yP521, privKeyBytesP521 := mustDecodeHex(t, pubKeyXP521Hex), mustDecodeHex(t, pubKeyYP521Hex), mustDecodeHex(t, privKeyValueP521Hex)
		privKeyBytesP521NoLeadingZeros := bytes.TrimLeft(privKeyBytesP521, "\x00")
		if len(privKeyBytesP521NoLeadingZeros) != 65 {
			t.Fatalf("privKeyBytesP521NoLeadingZeros has length %v, want 65", len(privKeyBytesP521NoLeadingZeros))
		}
		protoPublicKey := &ecdsapb.EcdsaPublicKey{
			X: xP521,
			Y: yP521,
			Params: &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA512,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			},
			Version: verifierKeyVersion,
		}
		protoPrivateKey := &ecdsapb.EcdsaPrivateKey{
			KeyValue:  privKeyBytesP521NoLeadingZeros,
			PublicKey: protoPublicKey,
			Version:   signerKeyVersion,
		}
		serializedProtoPrivateKey, err := proto.Marshal(protoPrivateKey)
		if err != nil {
			t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPrivateKey, err)
		}
		keySerialization := mustCreateKeySerialization(t, &tinkpb.KeyData{
			TypeUrl:         "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
			Value:           serializedProtoPrivateKey,
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
		}, tinkpb.OutputPrefixType_TINK, 12345)
		want, err := NewPrivateKey(secretdata.NewBytesFromData(privKeyBytesP521, insecuresecretdataaccess.Token{}), 12345, &Parameters{
			curveType:         NistP521,
			hashType:          SHA512,
			signatureEncoding: DER,
			variant:           VariantTink,
		})
		if err != nil {
			t.Fatalf("NewPrivateKey(%v, %v, params) err = %v, want nil", privKeyBytesP521, 12345, err)
		}
		p := &privateKeyParser{}
		got, err := p.ParseKey(keySerialization)
		if err != nil {
			t.Fatalf("p.ParseKey(%v) err = %v, want non-nil", keySerialization, err)
		}
		if !got.Equals(want) {
			t.Errorf("%v.Equals(%v) = false, want true", got, want)
		}
	})
}

func TestSerializePrivateKey(t *testing.T) {
	for _, tc := range testCases(t) {
		if !tc.hasLeadingZeros {
			// We expect coordinates to have a fixed size encoding:
			// 		 Public key point: 	x' = 0x00 || x, y' = 0x00 || y
			//		 Private key: 			d' = 0x00 || d
			// With: len(x') = len(y') = len(d') = coordinateSizeForCurve(tc.publicKey.parameters.curveType) + 1.
			continue
		}
		name := fmt.Sprintf("curveType:%v_hashType:%v_encoding:%v_variant:%v_id:%d", tc.publicKey.parameters.curveType, tc.publicKey.parameters.hashType, tc.publicKey.parameters.signatureEncoding, tc.publicKey.parameters.variant, tc.publicKey.idRequirement)
		t.Run(name, func(t *testing.T) {
			s := &privateKeySerializer{}
			got, err := s.SerializeKey(tc.privateKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(%v) err = nil, want non-nil", tc.privateKey)
			}
			if !got.Equals(tc.privateKeySerialization) {
				t.Errorf("got = %v, want %v", got, tc.privateKeySerialization)
			}
		})
	}
}

func TestSerializePrivateKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name       string
		privateKey key.Key
	}{
		{
			name:       "nil private key",
			privateKey: nil,
		},
		{
			name:       "invalid private key",
			privateKey: &PrivateKey{},
		},
		{
			name:       "incorrect key type",
			privateKey: &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &privateKeySerializer{}
			if _, err := s.SerializeKey(tc.privateKey); err == nil {
				t.Errorf("s.SerializeKey(%v) err = nil, want non-nil", tc.privateKey)
			}
		})
	}
}

func TestSerializeParametersFailsWithWrongParameters(t *testing.T) {
	for _, tc := range []struct {
		name       string
		parameters key.Parameters
	}{
		{
			name:       "struct literal",
			parameters: &Parameters{},
		},
		{
			name:       "nil",
			parameters: nil,
		},
		{
			name:       "wrong type",
			parameters: &testParams{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializer := &parametersSerializer{}
			if _, err := serializer.Serialize(tc.parameters); err == nil {
				t.Errorf("serializer.Serialize(%v) err = nil, want error", tc.parameters)
			}
		})
	}
}

func mustCreateKeyTemplate(t *testing.T, outputPrefixType tinkpb.OutputPrefixType, protoParams *ecdsapb.EcdsaParams) *tinkpb.KeyTemplate {
	t.Helper()
	format := &ecdsapb.EcdsaKeyFormat{
		Params: protoParams,
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", format, err)
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
		OutputPrefixType: outputPrefixType,
		Value:            serializedFormat,
	}
}

func TestSerializeParameters(t *testing.T) {
	for _, tc := range []struct {
		name            string
		parameters      key.Parameters
		wantKeyTemplate *tinkpb.KeyTemplate
	}{
		{
			name: "curveType:NIST_P256_hashType:SHA256_encoding:DER_variant:VariantTink",
			parameters: &Parameters{
				curveType:         NistP256,
				hashType:          SHA256,
				signatureEncoding: DER,
				variant:           VariantTink,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P256,
				HashType: commonpb.HashType_SHA256,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P256_hashType:SHA256_encoding:IEEEP1363_variant:VariantTink",
			parameters: &Parameters{
				curveType:         NistP256,
				hashType:          SHA256,
				signatureEncoding: IEEEP1363,
				variant:           VariantTink,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P256,
				HashType: commonpb.HashType_SHA256,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P256_hashType:SHA256_encoding:DER_variant:VariantLegacy",
			parameters: &Parameters{
				curveType:         NistP256,
				hashType:          SHA256,
				signatureEncoding: DER,
				variant:           VariantLegacy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P256,
				HashType: commonpb.HashType_SHA256,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P256_hashType:SHA256_encoding:IEEEP1363_variant:VariantLegacy",
			parameters: &Parameters{
				curveType:         NistP256,
				hashType:          SHA256,
				signatureEncoding: IEEEP1363,
				variant:           VariantLegacy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P256,
				HashType: commonpb.HashType_SHA256,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P256_hashType:SHA256_encoding:DER_variant:VariantCrunchy",
			parameters: &Parameters{
				curveType:         NistP256,
				hashType:          SHA256,
				signatureEncoding: DER,
				variant:           VariantCrunchy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P256,
				HashType: commonpb.HashType_SHA256,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P256_hashType:SHA256_encoding:IEEEP1363_variant:VariantCrunchy",
			parameters: &Parameters{
				curveType:         NistP256,
				hashType:          SHA256,
				signatureEncoding: IEEEP1363,
				variant:           VariantCrunchy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P256,
				HashType: commonpb.HashType_SHA256,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P256_hashType:SHA256_encoding:DER_variant:VariantNoPrefix",
			parameters: &Parameters{
				curveType:         NistP256,
				hashType:          SHA256,
				signatureEncoding: DER,
				variant:           VariantNoPrefix,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P256,
				HashType: commonpb.HashType_SHA256,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P256_hashType:SHA256_encoding:IEEEP1363_variant:VariantNoPrefix",
			parameters: &Parameters{
				curveType:         NistP256,
				hashType:          SHA256,
				signatureEncoding: IEEEP1363,
				variant:           VariantNoPrefix,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P256,
				HashType: commonpb.HashType_SHA256,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P384_hashType:SHA384_encoding:DER_variant:VariantTink",
			parameters: &Parameters{
				curveType:         NistP384,
				hashType:          SHA384,
				signatureEncoding: DER,
				variant:           VariantTink,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P384,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P384_hashType:SHA384_encoding:IEEEP1363_variant:VariantTink",
			parameters: &Parameters{
				curveType:         NistP384,
				hashType:          SHA384,
				signatureEncoding: IEEEP1363,
				variant:           VariantTink,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P384,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P384_hashType:SHA384_encoding:DER_variant:VariantLegacy",
			parameters: &Parameters{
				curveType:         NistP384,
				hashType:          SHA384,
				signatureEncoding: DER,
				variant:           VariantLegacy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P384,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P384_hashType:SHA384_encoding:IEEEP1363_variant:VariantLegacy",
			parameters: &Parameters{
				curveType:         NistP384,
				hashType:          SHA384,
				signatureEncoding: IEEEP1363,
				variant:           VariantLegacy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P384,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P384_hashType:SHA384_encoding:DER_variant:VariantCrunchy",
			parameters: &Parameters{
				curveType:         NistP384,
				hashType:          SHA384,
				signatureEncoding: DER,
				variant:           VariantCrunchy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P384,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P384_hashType:SHA384_encoding:IEEEP1363_variant:VariantCrunchy",
			parameters: &Parameters{
				curveType:         NistP384,
				hashType:          SHA384,
				signatureEncoding: IEEEP1363,
				variant:           VariantCrunchy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P384,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P384_hashType:SHA384_encoding:DER_variant:VariantNoPrefix",
			parameters: &Parameters{
				curveType:         NistP384,
				hashType:          SHA384,
				signatureEncoding: DER,
				variant:           VariantNoPrefix,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P384,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P384_hashType:SHA384_encoding:IEEEP1363_variant:VariantNoPrefix",
			parameters: &Parameters{
				curveType:         NistP384,
				hashType:          SHA384,
				signatureEncoding: IEEEP1363,
				variant:           VariantNoPrefix,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P384,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA384_encoding:DER_variant:VariantTink",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA384,
				signatureEncoding: DER,
				variant:           VariantTink,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA384_encoding:IEEEP1363_variant:VariantTink",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA384,
				signatureEncoding: IEEEP1363,
				variant:           VariantTink,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA384_encoding:DER_variant:VariantLegacy",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA384,
				signatureEncoding: DER,
				variant:           VariantLegacy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA384_encoding:IEEEP1363_variant:VariantLegacy",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA384,
				signatureEncoding: IEEEP1363,
				variant:           VariantLegacy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA384_encoding:DER_variant:VariantCrunchy",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA384,
				signatureEncoding: DER,
				variant:           VariantCrunchy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA384_encoding:IEEEP1363_variant:VariantCrunchy",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA384,
				signatureEncoding: IEEEP1363,
				variant:           VariantCrunchy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA384_encoding:DER_variant:VariantNoPrefix",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA384,
				signatureEncoding: DER,
				variant:           VariantNoPrefix,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA384_encoding:IEEEP1363_variant:VariantNoPrefix",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA384,
				signatureEncoding: IEEEP1363,
				variant:           VariantNoPrefix,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA384,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA512_encoding:DER_variant:VariantTink",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA512,
				signatureEncoding: DER,
				variant:           VariantTink,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA512,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA512_encoding:IEEEP1363_variant:VariantTink",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA512,
				signatureEncoding: IEEEP1363,
				variant:           VariantTink,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA512,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA512_encoding:DER_variant:VariantLegacy",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA512,
				signatureEncoding: DER,
				variant:           VariantLegacy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA512,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA512_encoding:IEEEP1363_variant:VariantLegacy",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA512,
				signatureEncoding: IEEEP1363,
				variant:           VariantLegacy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA512,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA512_encoding:DER_variant:VariantCrunchy",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA512,
				signatureEncoding: DER,
				variant:           VariantCrunchy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA512,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA512_encoding:IEEEP1363_variant:VariantCrunchy",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA512,
				signatureEncoding: IEEEP1363,
				variant:           VariantCrunchy,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA512,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA512_encoding:DER_variant:VariantNoPrefix",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA512,
				signatureEncoding: DER,
				variant:           VariantNoPrefix,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA512,
				Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			}),
		},
		{
			name: "curveType:NIST_P521_hashType:SHA512_encoding:IEEEP1363_variant:VariantNoPrefix",
			parameters: &Parameters{
				curveType:         NistP521,
				hashType:          SHA512,
				signatureEncoding: IEEEP1363,
				variant:           VariantNoPrefix,
			},
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &ecdsapb.EcdsaParams{
				Curve:    commonpb.EllipticCurveType_NIST_P521,
				HashType: commonpb.HashType_SHA512,
				Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializer := &parametersSerializer{}
			gotKeyTemplate, err := serializer.Serialize(tc.parameters)
			if err != nil {
				t.Errorf("serializer.Serialize(%v) err = %v, want nil", tc.parameters, err)
			}
			if diff := cmp.Diff(tc.wantKeyTemplate, gotKeyTemplate, protocmp.Transform()); diff != "" {
				t.Errorf("serializer.Serialize(%v) returned unexpected diff (-want +got):\n%s", tc.parameters, diff)
			}
		})
	}
}

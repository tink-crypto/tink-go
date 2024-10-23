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

package rsassapkcs1

import (
	"encoding/base64"
	"math/big"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	rsassapkcs1pb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	// Taken from:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_2048_test.json#L13
	n2048Base64 = "s1EKK81M5kTFtZSuUFnhKy8FS2WNXaWVmi_fGHG4CLw98-Yo0nkuUarVwSS0O9pFPcpc3kvPKOe9Tv-6DLS3Qru21aATy2PRqjqJ4CYn71OYtSwM_ZfSCKvrjXybzgu-sBmobdtYm-sppbdL-GEHXGd8gdQw8DDCZSR6-dPJFAzLZTCdB-Ctwe_RXPF-ewVdfaOGjkZIzDoYDw7n-OHnsYCYozkbTOcWHpjVevipR-IBpGPi1rvKgFnlcG6d_tj0hWRl_6cS7RqhjoiNEtxqoJzpXs_Kg8xbCxXbCchkf11STA8udiCjQWuWI8rcDwl69XMmHJjIQAqhKvOOQ8rYTQ"

	// Taken from:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_3072_test.json#L21
	n3072Base64 = "3I94gGcvDPnWNheopYvdJxoQm63aD6gm-UuKeVUmtqSagFZMyrqKlJGpNaU-3q4dmntUY9ni7z7gznv_XUtsgUe1wHPC8iBRXVMdVaNmh6bePDR3XC8VGRrAp0LXNCIoyNkQ_mu8pDlTnEhd68vQ7g5LrjF1A7g87oEArHu0WHRny8Q3PEvaLu33xBYx5QkitYD1vOgdJLIIyrzS11_P6Z91tJPf_Fyb2ZD3_Dvy7-OS_srjbz5O9EVsG13pnMdFFzOpELaDS2HsKSdNmGvjdSw1CxOjJ9q8CN_PZWVJmtJuhTRGYz6tspcMqVvPa_Bf_bwqgEN412mFpx8G-Ql5-f73FsNqpiWkW17t9QglpT6dlDWyPKq55cZNOP06dn4YWtdyfW4V-em6svQYTWSHaV25ommMZysugjQQ2-8dk_5AydNX7p_Hf4Sd4RNj9YOvjM9Rgcoa65RMQiUWy0AelQkj5L2IFDn6EJPHdYK_4axZk2dHALZDQzngJFMV2G_L"

	// Taken from:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_4096_test.json#L21
	n4096Base64 = "9gG-DczQSqQLEvPxka4XwfnIwLaOenfhS-JcPHkHyx0zpu9BjvQYUvMsmDkrxcmu2RwaFQHFA-q4mz7m9PjrLg_PxBvQNgnPao6zqm8PviMYezPbTTS2bRKKiroKKr9Au50T2OJVRWmlerHYxhuMrS3IhZmuDaU0bhXazhuse_aXN8IvCDvptGu4seq1lXstp0AnXpbIcZW5b-EUUhWdr8_ZFs7l10mne8OQWl69OHrkRej-cPFumghmOXec7_v9QVV72Zrqajcaa0sWBhWhoSvGlY00vODIWty9g5L6EM7KUiCdVhlro9JzziKPHxERkqqS3ioDl5ihe87LTcYQDm-K6MJkPyrnaLIlXwgsl46VylUVVfEGCCMc-AA7v4B5af_x5RkUuajJuPRWRkW55dcF_60pZj9drj12ZStCLkPxPmwUkQkIBcLRJop0olEXdCfjOpqRF1w2cLkXRgCLzh_SMebk8q1wy0OspfB2AKbTHdApFSQ9_dlDoCFl2jZ6a35Nrh3S6Lg2kDCAeV0lhQdswcFd2ejS5eBHUmVpsb_TldlX65_eMl00LRRCbnHv3BiHUV5TzepYNJIfkoYp50ju0JesQCTivyVdcEEfhzc5SM-Oiqfv-isKtH1RZgkeGu3sYFaLFVvZwnvFXz7ONfg9Y2281av0hToFHblNUEU"
)

func base64Decode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(value)
	if err != nil {
		t.Fatalf("base64 decoding failed: %v", err)
	}
	return decoded
}

func newKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

func TestParsePublicKeyFails(t *testing.T) {
	protoPublicKey := rsassapkcs1pb.RsaSsaPkcs1PublicKey{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: commonpb.HashType_SHA256,
		},
		N:       base64Decode(t, n2048Base64),
		E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
		Version: publicKeyProtoVersion,
	}
	serializedProtoPublicKey, err := proto.Marshal(&protoPublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPublicKey) err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name:             "key data is nil",
			keySerialization: newKeySerialization(t, nil, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "wrong type URL",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "invalid_type_url",
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "wrong key material type",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "wrong key version",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: func() []byte {
					protoPublicKey := rsassapkcs1pb.RsaSsaPkcs1PublicKey{
						Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
							HashType: commonpb.HashType_SHA256,
						},
						N:       base64Decode(t, n2048Base64),
						E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
						Version: publicKeyProtoVersion + 1,
					}
					serializedProtoPublicKey, err := proto.Marshal(&protoPublicKey)
					if err != nil {
						t.Fatalf("proto.Marshal(protoPublicKey) err = %v, want nil", err)
					}
					return serializedProtoPublicKey
				}(),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "invalid modulus",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: func() []byte {
					protoPublicKey := rsassapkcs1pb.RsaSsaPkcs1PublicKey{
						Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
							HashType: commonpb.HashType_SHA256,
						},
						N:       base64Decode(t, n2048Base64[:255]),
						E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
						Version: publicKeyProtoVersion + 1,
					}
					serializedProtoPublicKey, err := proto.Marshal(&protoPublicKey)
					if err != nil {
						t.Fatalf("proto.Marshal(protoPublicKey) err = %v, want nil", err)
					}
					return serializedProtoPublicKey
				}(),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "invalid exponent",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: func() []byte {
					protoPublicKey := rsassapkcs1pb.RsaSsaPkcs1PublicKey{
						Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
							HashType: commonpb.HashType_SHA256,
						},
						N:       base64Decode(t, n2048Base64),
						E:       new(big.Int).Sub(new(big.Int).SetUint64(uint64(f4)), big.NewInt(1)).Bytes(),
						Version: publicKeyProtoVersion + 1,
					}
					serializedProtoPublicKey, err := proto.Marshal(&protoPublicKey)
					if err != nil {
						t.Fatalf("proto.Marshal(protoPublicKey) err = %v, want nil", err)
					}
					return serializedProtoPublicKey
				}(),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &publicKeyParser{}
			if _, err = p.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want non-nil", tc.keySerialization)
			}
		})
	}
}

func newParameters(t *testing.T, modulusSizeBits int, hashType HashType, publicExponent int, variant Variant) *Parameters {
	t.Helper()
	params, err := NewParameters(modulusSizeBits, hashType, publicExponent, variant)
	if err != nil {
		t.Fatalf("NewParameters(%v, %v, %v, %v) = %v, want nil", modulusSizeBits, hashType, publicExponent, variant, err)
	}
	return params
}

func newPublicKey(t *testing.T, modulus []byte, idRequirement uint32, parameters *Parameters) *PublicKey {
	t.Helper()
	key, err := NewPublicKey(modulus, idRequirement, parameters)
	if err != nil {
		t.Fatalf("NewPublicKey(%v, %d, %v) = %v, want nil", modulus, idRequirement, parameters, err)
	}
	return key
}

func TestParseAndSerializePublicKey(t *testing.T) {
	proto2048PublicKey := rsassapkcs1pb.RsaSsaPkcs1PublicKey{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: commonpb.HashType_SHA256,
		},
		N:       base64Decode(t, n2048Base64),
		E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
		Version: publicKeyProtoVersion,
	}
	serialized2048ProtoPublicKey, err := proto.Marshal(&proto2048PublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal(proto2048PublicKey) err = %v, want nil", err)
	}
	proto3072SHA384PublicKey := rsassapkcs1pb.RsaSsaPkcs1PublicKey{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: commonpb.HashType_SHA384,
		},
		N:       base64Decode(t, n3072Base64),
		E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
		Version: publicKeyProtoVersion,
	}
	serialized3072SHA384ProtoPublicKey, err := proto.Marshal(&proto3072SHA384PublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal(proto3072SHA384PublicKey) err = %v, want nil", err)
	}
	proto3072SHA512PublicKey := rsassapkcs1pb.RsaSsaPkcs1PublicKey{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: commonpb.HashType_SHA512,
		},
		N:       base64Decode(t, n3072Base64),
		E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
		Version: publicKeyProtoVersion,
	}
	serialized3072SHA512ProtoPublicKey, err := proto.Marshal(&proto3072SHA512PublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal(proto3072SHA512PublicKey) err = %v, want nil", err)
	}
	proto4096PublicKey := rsassapkcs1pb.RsaSsaPkcs1PublicKey{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: commonpb.HashType_SHA512,
		},
		N:       base64Decode(t, n4096Base64),
		E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
		Version: publicKeyProtoVersion,
	}
	serialized4096ProtoPublicKey, err := proto.Marshal(&proto4096PublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal(proto4096PublicKey) err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name                   string
		publicKeySerialization *protoserialization.KeySerialization
		publicKey              *PublicKey
	}{
		{
			name: "2048-SHA256-TINK",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized2048ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			publicKey: newPublicKey(t, base64Decode(t, n2048Base64), 123, newParameters(t, 2048, SHA256, f4, VariantTink)),
		},
		{
			name: "2048-SHA256-LEGACY",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized2048ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_LEGACY, 123),
			publicKey: newPublicKey(t, base64Decode(t, n2048Base64), 123, newParameters(t, 2048, SHA256, f4, VariantLegacy)),
		},
		{
			name: "2048-SHA256-CRUNCHY",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized2048ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 123),
			publicKey: newPublicKey(t, base64Decode(t, n2048Base64), 123, newParameters(t, 2048, SHA256, f4, VariantCrunchy)),
		},
		{
			name: "2048-SHA256-RAW",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized2048ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			publicKey: newPublicKey(t, base64Decode(t, n2048Base64), 0, newParameters(t, 2048, SHA256, f4, VariantNoPrefix)),
		},
		{
			name: "3072-SHA384-TINK",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA384ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			publicKey: newPublicKey(t, base64Decode(t, n3072Base64), 123, newParameters(t, 3072, SHA384, f4, VariantTink)),
		},
		{
			name: "3072-SHA384-LEGACY",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA384ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_LEGACY, 123),
			publicKey: newPublicKey(t, base64Decode(t, n3072Base64), 123, newParameters(t, 3072, SHA384, f4, VariantLegacy)),
		},
		{
			name: "3072-SHA384-CRUNCHY",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA384ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 123),
			publicKey: newPublicKey(t, base64Decode(t, n3072Base64), 123, newParameters(t, 3072, SHA384, f4, VariantCrunchy)),
		},
		{
			name: "3072-SHA384-RAW",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA384ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			publicKey: newPublicKey(t, base64Decode(t, n3072Base64), 0, newParameters(t, 3072, SHA384, f4, VariantNoPrefix)),
		},
		{
			name: "3072-SHA512-TINK",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA512ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			publicKey: newPublicKey(t, base64Decode(t, n3072Base64), 123, newParameters(t, 3072, SHA512, f4, VariantTink)),
		},
		{
			name: "3072-SHA512-LEGACY",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA512ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_LEGACY, 123),
			publicKey: newPublicKey(t, base64Decode(t, n3072Base64), 123, newParameters(t, 3072, SHA512, f4, VariantLegacy)),
		},
		{
			name: "3072-SHA512-CRUNCHY",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA512ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 123),
			publicKey: newPublicKey(t, base64Decode(t, n3072Base64), 123, newParameters(t, 3072, SHA512, f4, VariantCrunchy)),
		},
		{
			name: "3072-SHA512-RAW",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA512ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			publicKey: newPublicKey(t, base64Decode(t, n3072Base64), 0, newParameters(t, 3072, SHA512, f4, VariantNoPrefix)),
		},
		{
			name: "4096-SHA512-TINK",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized4096ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			publicKey: newPublicKey(t, base64Decode(t, n4096Base64), 123, newParameters(t, 4096, SHA512, f4, VariantTink)),
		},
		{
			name: "4096-SHA512-LEGACY",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized4096ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_LEGACY, 123),
			publicKey: newPublicKey(t, base64Decode(t, n4096Base64), 123, newParameters(t, 4096, SHA512, f4, VariantLegacy)),
		},
		{
			name: "4096-SHA512-CRUNCHY",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized4096ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 123),
			publicKey: newPublicKey(t, base64Decode(t, n4096Base64), 123, newParameters(t, 4096, SHA512, f4, VariantCrunchy)),
		},
		{
			name: "4096-SHA512-RAW",
			publicKeySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized4096ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			publicKey: newPublicKey(t, base64Decode(t, n4096Base64), 0, newParameters(t, 4096, SHA512, f4, VariantNoPrefix)),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &publicKeyParser{}
			gotKey, err := p.ParseKey(tc.publicKeySerialization)
			if err != nil {
				t.Fatalf("p.ParseKey(%v) err = %v, want non-nil", tc.publicKeySerialization, err)
			}
			if !gotKey.Equals(tc.publicKey) {
				t.Errorf("%v.Equals(%v) = false, want true", gotKey, tc.publicKey)
			}

			// Make sure we can serialize back the key serialization.
			s := &publicKeySerializer{}
			gotSerialization, err := s.SerializeKey(gotKey)
			if err != nil {
				t.Errorf("s.SerializeKey(%v) err = %v, want nil", tc.publicKeySerialization, err)
			}
			if !gotSerialization.Equals(tc.publicKeySerialization) {
				t.Errorf("gotSerialization.Equals(tc.publicKeySerialization) = false, want true")
			}
		})
	}
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
			name:      "nil public key",
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

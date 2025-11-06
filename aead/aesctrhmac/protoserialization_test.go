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

package aesctrhmac

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	aesctrpb "github.com/tink-crypto/tink-go/v2/proto/aes_ctr_go_proto"
	aesctrhmacpb "github.com/tink-crypto/tink-go/v2/proto/aes_ctr_hmac_aead_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestParseKeyFails(t *testing.T) {
	key := aesctrhmacpb.AesCtrHmacAeadKey{
		AesCtrKey: &aesctrpb.AesCtrKey{
			Params: &aesctrpb.AesCtrParams{
				IvSize: 12,
			},
			KeyValue: []byte("1234567890123456"),
		},
		HmacKey: &hmacpb.HmacKey{
			Params: &hmacpb.HmacParams{
				Hash:    commonpb.HashType_SHA256,
				TagSize: 16,
			},
			KeyValue: []byte("1234567890123456"),
		},
	}

	for _, tc := range []struct {
		name             string
		keyData          *tinkpb.KeyData
		outputPrefixType tinkpb.OutputPrefixType
		keyID            uint32
	}{
		{
			name:             "key data is nil",
			keyData:          nil,
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "wrong type URL",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "invalid_type_url",
				Value:           mustSerializeProto(t, &key),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid AES key size",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
				Value: mustSerializeProto(t, &aesctrhmacpb.AesCtrHmacAeadKey{
					AesCtrKey: &aesctrpb.AesCtrKey{
						Params: &aesctrpb.AesCtrParams{
							IvSize: 12,
						},
						KeyValue: []byte("123"),
					},
					HmacKey: &hmacpb.HmacKey{
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
						KeyValue: []byte("1234567890123456"),
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid HMAC key size",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
				Value: mustSerializeProto(t, &aesctrhmacpb.AesCtrHmacAeadKey{
					AesCtrKey: &aesctrpb.AesCtrKey{
						Params: &aesctrpb.AesCtrParams{
							IvSize: 12,
						},
						KeyValue: []byte("1234567890123456"),
					},
					HmacKey: &hmacpb.HmacKey{
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
						KeyValue: []byte("123"),
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid IV size",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
				Value: mustSerializeProto(t, &aesctrhmacpb.AesCtrHmacAeadKey{
					AesCtrKey: &aesctrpb.AesCtrKey{
						Params: &aesctrpb.AesCtrParams{
							IvSize: 1,
						},
						KeyValue: []byte("1234567890123456"),
					},
					HmacKey: &hmacpb.HmacKey{
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
						KeyValue: []byte("1234567890123456"),
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid tag size",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
				Value: mustSerializeProto(t, &aesctrhmacpb.AesCtrHmacAeadKey{
					AesCtrKey: &aesctrpb.AesCtrKey{
						Params: &aesctrpb.AesCtrParams{
							IvSize: 12,
						},
						KeyValue: []byte("1234567890123456"),
					},
					HmacKey: &hmacpb.HmacKey{
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 2,
						},
						KeyValue: []byte("1234567890123456"),
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid proto serialization",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
				Value:           []byte("invalid proto"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid key version",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
				Value: mustSerializeProto(t, &aesctrhmacpb.AesCtrHmacAeadKey{
					Version: 1,
					AesCtrKey: &aesctrpb.AesCtrKey{
						Params: &aesctrpb.AesCtrParams{
							IvSize: 12,
						},
						KeyValue: []byte("123"),
					},
					HmacKey: &hmacpb.HmacKey{
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
						KeyValue: []byte("1234567890123456"),
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid AesCtrKey version",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
				Value: mustSerializeProto(t, &aesctrhmacpb.AesCtrHmacAeadKey{
					AesCtrKey: &aesctrpb.AesCtrKey{
						Version: 1,
						Params: &aesctrpb.AesCtrParams{
							IvSize: 12,
						},
						KeyValue: []byte("123"),
					},
					HmacKey: &hmacpb.HmacKey{
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
						KeyValue: []byte("1234567890123456"),
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid HmacKey version",
			keyData: &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
				Value: mustSerializeProto(t, &aesctrhmacpb.AesCtrHmacAeadKey{
					AesCtrKey: &aesctrpb.AesCtrKey{
						Params: &aesctrpb.AesCtrParams{
							IvSize: 12,
						},
						KeyValue: []byte("123"),
					},
					HmacKey: &hmacpb.HmacKey{
						Version: 1,
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
						KeyValue: []byte("1234567890123456"),
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid key material type",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
				Value:           mustSerializeProto(t, &key),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid output prefix type",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
				Value:           mustSerializeProto(t, &key),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
			keyID:            12345,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &keyParser{}
			keySerialization, err := protoserialization.NewKeySerialization(tc.keyData, tc.outputPrefixType, tc.keyID)
			if err != nil {
				t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", tc.keyData, tc.outputPrefixType, tc.keyID, err)
			}
			if _, err := p.ParseKey(keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want non-nil", keySerialization)
			}
		})
	}
}

func mustCreateKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

func mustSerializeProto(t *testing.T, m proto.Message) []byte {
	t.Helper()
	serialized, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", m, err)
	}
	return serialized
}

type keyParsingTestCase struct {
	name             string
	keySerialization *protoserialization.KeySerialization
	key              *Key
}

func testCases(t *testing.T) []*keyParsingTestCase {
	// t.Helper()
	tcs := []*keyParsingTestCase{}

	aesKey := []byte("11111111111111111111111111111111")
	hmacKey := []byte("22222222222222222222222222222222")

	for _, aesKeySize := range []int{16, 32} {
		for _, hmacKeySize := range []int{16, 32} {
			for _, ivSize := range []int{12, 16} {
				// SHA1.
				protoKeyWithSHA1 := &aesctrhmacpb.AesCtrHmacAeadKey{
					AesCtrKey: &aesctrpb.AesCtrKey{
						Params: &aesctrpb.AesCtrParams{
							IvSize: uint32(ivSize),
						},
						KeyValue: aesKey[:aesKeySize],
					},
					HmacKey: &hmacpb.HmacKey{
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA1,
							TagSize: 16,
						},
						KeyValue: hmacKey[:hmacKeySize],
					},
				}
				paramsSHA1, err := NewParameters(ParametersOpts{
					AESKeySizeInBytes:  aesKeySize,
					HMACKeySizeInBytes: hmacKeySize,
					IVSizeInBytes:      ivSize,
					TagSizeInBytes:     16,
					HashType:           SHA1,
					Variant:            VariantNoPrefix,
				})
				if err != nil {
					t.Fatalf("NewParameters() err = %v, want nil", err)
				}
				keySHA1, err := NewKey(KeyOpts{
					AESKeyBytes:   secretdata.NewBytesFromData(aesKey[:aesKeySize], insecuresecretdataaccess.Token{}),
					HMACKeyBytes:  secretdata.NewBytesFromData(hmacKey[:hmacKeySize], insecuresecretdataaccess.Token{}),
					IDRequirement: 0,
					Parameters:    paramsSHA1,
				})
				if err != nil {
					t.Fatalf("NewKey() err = %v, want nil", err)
				}

				tcs = append(tcs, &keyParsingTestCase{
					name: fmt.Sprintf("AES%d_HMAC%d_IV%d_SHA1-NoPrefix", aesKeySize*8, hmacKeySize*8, ivSize),
					keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
						TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
						Value:           mustSerializeProto(t, protoKeyWithSHA1),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					}, tinkpb.OutputPrefixType_RAW, 0),
					key: keySHA1,
				})

				// SHA224.
				protoKeyWithSHA224 := &aesctrhmacpb.AesCtrHmacAeadKey{
					AesCtrKey: &aesctrpb.AesCtrKey{
						Params: &aesctrpb.AesCtrParams{
							IvSize: uint32(ivSize),
						},
						KeyValue: aesKey[:aesKeySize],
					},
					HmacKey: &hmacpb.HmacKey{
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA224,
							TagSize: 16,
						},
						KeyValue: hmacKey[:hmacKeySize],
					},
				}
				paramsSHA224, err := NewParameters(ParametersOpts{
					AESKeySizeInBytes:  aesKeySize,
					HMACKeySizeInBytes: hmacKeySize,
					IVSizeInBytes:      ivSize,
					TagSizeInBytes:     16,
					HashType:           SHA224,
					Variant:            VariantTink,
				})
				if err != nil {
					t.Fatalf("NewParameters() err = %v, want nil", err)
				}
				keySHA224, err := NewKey(KeyOpts{
					AESKeyBytes:   secretdata.NewBytesFromData(aesKey[:aesKeySize], insecuresecretdataaccess.Token{}),
					HMACKeyBytes:  secretdata.NewBytesFromData(hmacKey[:hmacKeySize], insecuresecretdataaccess.Token{}),
					IDRequirement: 0x22334455,
					Parameters:    paramsSHA224,
				})
				if err != nil {
					t.Fatalf("NewKey() err = %v, want nil", err)
				}
				tcs = append(tcs, &keyParsingTestCase{
					name: fmt.Sprintf("AES%d_HMAC%d_IV%d_SHA224-Tink", aesKeySize*8, hmacKeySize*8, ivSize),
					keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
						TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
						Value:           mustSerializeProto(t, protoKeyWithSHA224),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					}, tinkpb.OutputPrefixType_TINK, 0x22334455),
					key: keySHA224,
				})

				// SHA256.
				protoKeyWithSHA256 := &aesctrhmacpb.AesCtrHmacAeadKey{
					AesCtrKey: &aesctrpb.AesCtrKey{
						Params: &aesctrpb.AesCtrParams{
							IvSize: uint32(ivSize),
						},
						KeyValue: aesKey[:aesKeySize],
					},
					HmacKey: &hmacpb.HmacKey{
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
						KeyValue: hmacKey[:hmacKeySize],
					},
				}
				paramsSHA256, err := NewParameters(ParametersOpts{
					AESKeySizeInBytes:  aesKeySize,
					HMACKeySizeInBytes: hmacKeySize,
					IVSizeInBytes:      ivSize,
					TagSizeInBytes:     16,
					HashType:           SHA256,
					Variant:            VariantTink,
				})
				if err != nil {
					t.Fatalf("NewParameters() err = %v, want nil", err)
				}
				keySHA256, err := NewKey(KeyOpts{
					AESKeyBytes:   secretdata.NewBytesFromData(aesKey[:aesKeySize], insecuresecretdataaccess.Token{}),
					HMACKeyBytes:  secretdata.NewBytesFromData(hmacKey[:hmacKeySize], insecuresecretdataaccess.Token{}),
					IDRequirement: 0x22334455,
					Parameters:    paramsSHA256,
				})
				if err != nil {
					t.Fatalf("NewKey() err = %v, want nil", err)
				}
				tcs = append(tcs, &keyParsingTestCase{
					name: fmt.Sprintf("AES%d_HMAC%d_IV%d_SHA256-Tink", aesKeySize*8, hmacKeySize*8, ivSize),
					keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
						TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
						Value:           mustSerializeProto(t, protoKeyWithSHA256),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					}, tinkpb.OutputPrefixType_TINK, 0x22334455),
					key: keySHA256,
				})

				// SHA384.
				protoKeyWithSHA384 := &aesctrhmacpb.AesCtrHmacAeadKey{
					AesCtrKey: &aesctrpb.AesCtrKey{
						Params: &aesctrpb.AesCtrParams{
							IvSize: uint32(ivSize),
						},
						KeyValue: aesKey[:aesKeySize],
					},
					HmacKey: &hmacpb.HmacKey{
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA384,
							TagSize: 16,
						},
						KeyValue: hmacKey[:hmacKeySize],
					},
				}
				paramsSHA384, err := NewParameters(ParametersOpts{
					AESKeySizeInBytes:  aesKeySize,
					HMACKeySizeInBytes: hmacKeySize,
					IVSizeInBytes:      ivSize,
					TagSizeInBytes:     16,
					HashType:           SHA384,
					Variant:            VariantTink,
				})
				if err != nil {
					t.Fatalf("NewParameters() err = %v, want nil", err)
				}
				keySHA384, err := NewKey(KeyOpts{
					AESKeyBytes:   secretdata.NewBytesFromData(aesKey[:aesKeySize], insecuresecretdataaccess.Token{}),
					HMACKeyBytes:  secretdata.NewBytesFromData(hmacKey[:hmacKeySize], insecuresecretdataaccess.Token{}),
					IDRequirement: 0x22334455,
					Parameters:    paramsSHA384,
				})
				if err != nil {
					t.Fatalf("NewKey() err = %v, want nil", err)
				}
				tcs = append(tcs, &keyParsingTestCase{
					name: fmt.Sprintf("AES%d_HMAC%d_IV%d_SHA384-Tink", aesKeySize*8, hmacKeySize*8, ivSize),
					keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
						TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
						Value:           mustSerializeProto(t, protoKeyWithSHA384),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					}, tinkpb.OutputPrefixType_TINK, 0x22334455),
					key: keySHA384,
				})

				// SHA512.
				protoKeyWith512 := &aesctrhmacpb.AesCtrHmacAeadKey{
					AesCtrKey: &aesctrpb.AesCtrKey{
						Params: &aesctrpb.AesCtrParams{
							IvSize: uint32(ivSize),
						},
						KeyValue: aesKey[:aesKeySize],
					},
					HmacKey: &hmacpb.HmacKey{
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA512,
							TagSize: 16,
						},
						KeyValue: hmacKey[:hmacKeySize],
					},
				}
				paramsSHA512, err := NewParameters(ParametersOpts{
					AESKeySizeInBytes:  aesKeySize,
					HMACKeySizeInBytes: hmacKeySize,
					IVSizeInBytes:      ivSize,
					TagSizeInBytes:     16,
					HashType:           SHA512,
					Variant:            VariantCrunchy,
				})
				if err != nil {
					t.Fatalf("NewParameters() err = %v, want nil", err)
				}
				key512, err := NewKey(KeyOpts{
					AESKeyBytes:   secretdata.NewBytesFromData(aesKey[:aesKeySize], insecuresecretdataaccess.Token{}),
					HMACKeyBytes:  secretdata.NewBytesFromData(hmacKey[:hmacKeySize], insecuresecretdataaccess.Token{}),
					IDRequirement: 0x11223344,
					Parameters:    paramsSHA512,
				})
				if err != nil {
					t.Fatalf("NewKey() err = %v, want nil", err)
				}

				tcs = append(tcs, &keyParsingTestCase{
					name: fmt.Sprintf("AES%d_HMAC%d_IV%d_SHA512-Crunchy", aesKeySize*8, hmacKeySize*8, ivSize),
					keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
						TypeUrl:         "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
						Value:           mustSerializeProto(t, protoKeyWith512),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					}, tinkpb.OutputPrefixType_CRUNCHY, 0x11223344),
					key: key512,
				})
			}
		}
	}
	return tcs
}

func TestParseKey(t *testing.T) {
	for _, tc := range testCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			p := &keyParser{}
			got, err := p.ParseKey(tc.keySerialization)
			if err != nil {
				t.Errorf("p.ParseKey(%v) err = %v, want nil", tc.keySerialization, err)
			}
			if diff := cmp.Diff(got, tc.key); diff != "" {
				t.Errorf("s.ParseKey() diff (-want +got):\n%s", diff)
			}
		})
	}
}

type testParams struct {
	hasIDRequirement bool
}

func (p *testParams) HasIDRequirement() bool { return p.hasIDRequirement }

func (p *testParams) Equal(params key.Parameters) bool {
	_, ok := params.(*testParams)
	return ok && p.hasIDRequirement == params.HasIDRequirement()
}

type testKey struct {
	keyBytes []byte
	id       uint32
	params   testParams
}

func (k *testKey) Parameters() key.Parameters { return &k.params }

func (k *testKey) Equal(other key.Key) bool {
	fallbackProtoKey, ok := other.(*testKey)
	if !ok {
		return false
	}
	return k.params.Equal(fallbackProtoKey.Parameters())
}

func (k *testKey) IDRequirement() (uint32, bool) { return k.id, k.params.HasIDRequirement() }

func TestSerializeKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  key.Key
	}{
		{
			name: "key is nil",
			key:  nil,
		},
		{
			name: "key is not an AES GCM key",
			key:  &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			aesGCMSerializer := &keySerializer{}
			_, err := aesGCMSerializer.SerializeKey(tc.key)
			if err == nil {
				t.Errorf("protoserialization.SerializeKey(&testKey{}) err = nil, want non-nil")
			}
		})
	}
}

func TestSerializeKey(t *testing.T) {
	for _, tc := range testCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			s := &keySerializer{}
			got, err := s.SerializeKey(tc.key)
			if err != nil {
				t.Errorf("s.SerializeKey() err = %v, want nil", err)
			}
			if diff := cmp.Diff(got, tc.keySerialization); diff != "" {
				t.Errorf("s.SerializeKey() diff (-want +got):\n%s", diff)
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

func mustCreateKeyTemplate(t *testing.T, outputPrefixType tinkpb.OutputPrefixType, aesKeySizeInBytes, hmacKeySizeInBytes, ivSizeInBytes, tagSizeInBytes uint32, hashType commonpb.HashType) *tinkpb.KeyTemplate {
	t.Helper()
	format := &aesctrhmacpb.AesCtrHmacAeadKeyFormat{
		AesCtrKeyFormat: &aesctrpb.AesCtrKeyFormat{
			Params: &aesctrpb.AesCtrParams{
				IvSize: ivSizeInBytes,
			},
			KeySize: uint32(aesKeySizeInBytes),
		},
		HmacKeyFormat: &hmacpb.HmacKeyFormat{
			Params: &hmacpb.HmacParams{
				Hash:    hashType,
				TagSize: tagSizeInBytes,
			},
			KeySize: uint32(hmacKeySizeInBytes),
		},
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", format, err)
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
		OutputPrefixType: outputPrefixType,
		Value:            serializedFormat,
	}
}

type parametersSerializationTestCase struct {
	name        string
	parameters  *Parameters
	keyTemplate *tinkpb.KeyTemplate
}

func mustCreateParametersTestParameters(t *testing.T) []parametersSerializationTestCase {
	tcs := []parametersSerializationTestCase{}
	for _, aesKeySize := range []int{16, 24, 32} { // AES key can be 16, 24 or 32 bytes.
		for _, hmacKeySize := range []int{16, 32} { // HMAC key must be >= 16 bytes.
			for _, ivSize := range []int{12, 16} { // IV size must be 12 <= IV size <= 16.
				for _, variantAndPrefix := range []struct {
					variant          Variant
					outputPrefixType tinkpb.OutputPrefixType
				}{
					{
						variant:          VariantTink,
						outputPrefixType: tinkpb.OutputPrefixType_TINK,
					},
					{
						variant:          VariantNoPrefix,
						outputPrefixType: tinkpb.OutputPrefixType_RAW,
					},
					{
						variant:          VariantCrunchy,
						outputPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
					},
				} {
					for _, hashAndTagSize := range []struct {
						hashType      HashType
						protoHashType commonpb.HashType
						tagSize       int
					}{
						// Min tag size is 10 bytes.
						{
							hashType:      SHA1,
							protoHashType: commonpb.HashType_SHA1,
							tagSize:       10,
						},
						{
							hashType:      SHA224,
							protoHashType: commonpb.HashType_SHA224,
							tagSize:       10,
						},
						{
							hashType:      SHA256,
							protoHashType: commonpb.HashType_SHA256,
							tagSize:       10,
						},
						{
							hashType:      SHA384,
							protoHashType: commonpb.HashType_SHA384,
							tagSize:       10,
						},
						{
							hashType:      SHA512,
							protoHashType: commonpb.HashType_SHA512,
							tagSize:       10,
						},
						// Max tag size.
						{
							hashType:      SHA1,
							protoHashType: commonpb.HashType_SHA1,
							tagSize:       20,
						},
						{
							hashType:      SHA224,
							protoHashType: commonpb.HashType_SHA224,
							tagSize:       28,
						},
						{
							hashType:      SHA256,
							protoHashType: commonpb.HashType_SHA256,
							tagSize:       32,
						},
						{
							hashType:      SHA384,
							protoHashType: commonpb.HashType_SHA384,
							tagSize:       48,
						},
						{
							hashType:      SHA512,
							protoHashType: commonpb.HashType_SHA512,
							tagSize:       64,
						},
					} {
						tcs = append(tcs, parametersSerializationTestCase{
							name: fmt.Sprintf("AES%d-IV%d-HMAC%d-%v-%s-TagSize%d", aesKeySize, ivSize, hmacKeySize, hashAndTagSize.hashType, variantAndPrefix.variant, hashAndTagSize.tagSize),
							parameters: mustCreateParameters(t, ParametersOpts{
								AESKeySizeInBytes:  aesKeySize,
								HMACKeySizeInBytes: hmacKeySize,
								IVSizeInBytes:      ivSize,
								TagSizeInBytes:     hashAndTagSize.tagSize,
								HashType:           hashAndTagSize.hashType,
								Variant:            variantAndPrefix.variant,
							}),
							keyTemplate: mustCreateKeyTemplate(t, variantAndPrefix.outputPrefixType, uint32(aesKeySize), uint32(hmacKeySize), uint32(ivSize), uint32(hashAndTagSize.tagSize), hashAndTagSize.protoHashType),
						})
					}
				}
			}
		}
	}

	return tcs
}

func TestSerializeParameters(t *testing.T) {
	for _, tc := range mustCreateParametersTestParameters(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeParameters(tc.parameters)
			if err != nil {
				t.Fatalf("protoserialization.SerializeParameters() err = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.keyTemplate, got, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeParameters() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func mustCreateParameters(t *testing.T, parametersOpts ParametersOpts) *Parameters {
	t.Helper()
	params, err := NewParameters(parametersOpts)
	if err != nil {
		t.Fatalf("NewParameters(%v) err = %v, want nil", parametersOpts, err)
	}
	return params
}

func TestParseParameters(t *testing.T) {
	for _, tc := range mustCreateParametersTestParameters(t) {
		t.Run(tc.name, func(t *testing.T) {
			params, err := protoserialization.ParseParameters(tc.keyTemplate)
			if err != nil {
				t.Fatalf("protoserialization.ParseParameters(%v) err = %v, want nil", tc.keyTemplate, err)
			}
			if diff := cmp.Diff(tc.parameters, params); diff != "" {
				t.Errorf("protoserialization.ParseParameters(%v) returned unexpected diff (-want +got):\n%s", tc.keyTemplate, diff)
			}
		})
	}
}

func mustMarshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	serializedMessage, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", message, err)
	}
	return serializedMessage
}

func TestParseParametersFailsWithWrongKeyTemplate(t *testing.T) {
	for _, tc := range []struct {
		name         string
		keyTeamplate *tinkpb.KeyTemplate
	}{
		{
			name:         "empty",
			keyTeamplate: &tinkpb.KeyTemplate{},
		},
		{
			name: "wrong value",
			keyTeamplate: &tinkpb.KeyTemplate{
				TypeUrl:          typeURL,
				Value:            mustMarshal(t, &hmacpb.HmacKeyFormat{}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "empty AES key format",
			keyTeamplate: &tinkpb.KeyTemplate{
				TypeUrl: typeURL,
				Value: mustMarshal(t, &aesctrhmacpb.AesCtrHmacAeadKeyFormat{
					HmacKeyFormat: &hmacpb.HmacKeyFormat{
						KeySize: 16,
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "empty HMAC key format",
			keyTeamplate: &tinkpb.KeyTemplate{
				TypeUrl: typeURL,
				Value: mustMarshal(t, &aesctrhmacpb.AesCtrHmacAeadKeyFormat{
					AesCtrKeyFormat: &aesctrpb.AesCtrKeyFormat{
						KeySize: 16,
						Params: &aesctrpb.AesCtrParams{
							IvSize: 12,
						},
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "empty AES key format",
			keyTeamplate: &tinkpb.KeyTemplate{
				TypeUrl: typeURL,
				Value: mustMarshal(t, &aesctrhmacpb.AesCtrHmacAeadKeyFormat{
					HmacKeyFormat: &hmacpb.HmacKeyFormat{
						KeySize: 16,
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid type URL",
			keyTeamplate: &tinkpb.KeyTemplate{
				TypeUrl: "invalid",
				Value: mustMarshal(t, &aesctrhmacpb.AesCtrHmacAeadKeyFormat{
					AesCtrKeyFormat: &aesctrpb.AesCtrKeyFormat{
						KeySize: 16,
						Params: &aesctrpb.AesCtrParams{
							IvSize: 12,
						},
					},
					HmacKeyFormat: &hmacpb.HmacKeyFormat{
						KeySize: 16,
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid AES key size",
			keyTeamplate: &tinkpb.KeyTemplate{
				TypeUrl: typeURL,
				Value: mustMarshal(t, &aesctrhmacpb.AesCtrHmacAeadKeyFormat{
					AesCtrKeyFormat: &aesctrpb.AesCtrKeyFormat{
						KeySize: 11,
						Params: &aesctrpb.AesCtrParams{
							IvSize: 12,
						},
					},
					HmacKeyFormat: &hmacpb.HmacKeyFormat{
						KeySize: 16,
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid IV size",
			keyTeamplate: &tinkpb.KeyTemplate{
				TypeUrl: typeURL,
				Value: mustMarshal(t, &aesctrhmacpb.AesCtrHmacAeadKeyFormat{
					AesCtrKeyFormat: &aesctrpb.AesCtrKeyFormat{
						KeySize: 16,
						Params: &aesctrpb.AesCtrParams{
							IvSize: 11,
						},
					},
					HmacKeyFormat: &hmacpb.HmacKeyFormat{
						KeySize: 16,
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid hash function",
			keyTeamplate: &tinkpb.KeyTemplate{
				TypeUrl: typeURL,
				Value: mustMarshal(t, &aesctrhmacpb.AesCtrHmacAeadKeyFormat{
					AesCtrKeyFormat: &aesctrpb.AesCtrKeyFormat{
						KeySize: 16,
						Params: &aesctrpb.AesCtrParams{
							IvSize: 12,
						},
					},
					HmacKeyFormat: &hmacpb.HmacKeyFormat{
						KeySize: 16,
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_UNKNOWN_HASH,
							TagSize: 16,
						},
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid hmac key size",
			keyTeamplate: &tinkpb.KeyTemplate{
				TypeUrl: typeURL,
				Value: mustMarshal(t, &aesctrhmacpb.AesCtrHmacAeadKeyFormat{
					AesCtrKeyFormat: &aesctrpb.AesCtrKeyFormat{
						KeySize: 16,
						Params: &aesctrpb.AesCtrParams{
							IvSize: 12,
						},
					},
					HmacKeyFormat: &hmacpb.HmacKeyFormat{
						KeySize: 11,
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid tag size",
			keyTeamplate: &tinkpb.KeyTemplate{
				TypeUrl: typeURL,
				Value: mustMarshal(t, &aesctrhmacpb.AesCtrHmacAeadKeyFormat{
					AesCtrKeyFormat: &aesctrpb.AesCtrKeyFormat{
						KeySize: 16,
						Params: &aesctrpb.AesCtrParams{
							IvSize: 12,
						},
					},
					HmacKeyFormat: &hmacpb.HmacKeyFormat{
						KeySize: 11,
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 100,
						},
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid output prefix type",
			keyTeamplate: &tinkpb.KeyTemplate{
				TypeUrl: typeURL,
				Value: mustMarshal(t, &aesctrhmacpb.AesCtrHmacAeadKeyFormat{
					AesCtrKeyFormat: &aesctrpb.AesCtrKeyFormat{
						KeySize: 16,
						Params: &aesctrpb.AesCtrParams{
							IvSize: 12,
						},
					},
					HmacKeyFormat: &hmacpb.HmacKeyFormat{
						KeySize: 16,
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
			},
		},
		{
			name: "invalid version",
			keyTeamplate: &tinkpb.KeyTemplate{
				TypeUrl: typeURL,
				Value: mustMarshal(t, &aesctrhmacpb.AesCtrHmacAeadKeyFormat{
					AesCtrKeyFormat: &aesctrpb.AesCtrKeyFormat{
						KeySize: 16,
						Params: &aesctrpb.AesCtrParams{
							IvSize: 12,
						},
					},
					HmacKeyFormat: &hmacpb.HmacKeyFormat{
						KeySize: 16,
						Params: &hmacpb.HmacParams{
							Hash:    commonpb.HashType_SHA256,
							TagSize: 16,
						},
						Version: 1,
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseParameters(tc.keyTeamplate); err == nil {
				t.Errorf("protoserialization.ParseParameters(%v) err = nil, want error", tc.keyTeamplate)
			}
		})
	}
}

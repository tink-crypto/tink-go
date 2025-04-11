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

package hkdfprf_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hkdfprfpb "github.com/tink-crypto/tink-go/v2/proto/hkdf_prf_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func mustMarshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	serializedMessage, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", message, err)
	}
	return serializedMessage
}

func mustCreateKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

func TestParseKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name: "invalid key size",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
				Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKey{
					Version:  0,
					KeyValue: []byte("0123"),
					Params: &hkdfprfpb.HkdfPrfParams{
						Hash: commonpb.HashType_SHA256,
						Salt: []byte("1234567890123456"),
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid key proto serialization",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
				Value:           []byte("invalid proto"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
				Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKey{
					Version:  1,
					KeyValue: []byte("1234567890123456"),
					Params: &hkdfprfpb.HkdfPrfParams{
						Hash: commonpb.HashType_SHA256,
						Salt: []byte("1234567890123456"),
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name: "invalid output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
				Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKey{
					Version:  0,
					KeyValue: []byte("1234567890123456"),
					Params: &hkdfprfpb.HkdfPrfParams{
						Hash: commonpb.HashType_SHA256,
						Salt: []byte("1234567890123456"),
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "unknown output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
				Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKey{
					Version:  0,
					KeyValue: []byte("1234567890123456"),
					Params: &hkdfprfpb.HkdfPrfParams{
						Hash: commonpb.HashType_SHA256,
						Salt: []byte("1234567890123456"),
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_UNKNOWN_PREFIX, 0),
		},
		{
			name: "invalid hash type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
				Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKey{
					Version:  0,
					KeyValue: []byte("1234567890123456"),
					Params: &hkdfprfpb.HkdfPrfParams{
						Hash: commonpb.HashType_UNKNOWN_HASH,
						Salt: []byte("1234567890123456"),
					},
				}),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want error", tc.keySerialization)
			}
		})
	}
}

type hkdfPRFSerializationTestCase struct {
	name             string
	key              *hkdfprf.Key
	keySerialization *protoserialization.KeySerialization
}

func hkdfPRFSerializationTestCases(t *testing.T) []hkdfPRFSerializationTestCase {
	var tcs []hkdfPRFSerializationTestCase = nil

	for _, hashType := range []struct {
		enum  hkdfprf.HashType
		proto commonpb.HashType
	}{
		{enum: hkdfprf.SHA1, proto: commonpb.HashType_SHA1},
		{enum: hkdfprf.SHA224, proto: commonpb.HashType_SHA224},
		{enum: hkdfprf.SHA256, proto: commonpb.HashType_SHA256},
		{enum: hkdfprf.SHA384, proto: commonpb.HashType_SHA384},
		{enum: hkdfprf.SHA512, proto: commonpb.HashType_SHA512},
	} {
		for _, salt := range [][]byte{nil, []byte("salt")} {
			key, err := hkdfprf.NewKey(secretdata.NewBytesFromData([]byte("1234567890123456"), insecuresecretdataaccess.Token{}), mustCreateParameters(t, 16, hashType.enum, salt))
			if err != nil {
				t.Fatalf("hkdfprf.NewKey() err = %v, want nil", err)
			}
			tcs = append(tcs, hkdfPRFSerializationTestCase{
				name: fmt.Sprintf("HKDF-PRF,hashType=%v,salt=%v", hashType.enum, salt),
				key:  key,
				keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
					TypeUrl: "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
					Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKey{
						Version:  0,
						KeyValue: []byte("1234567890123456"),
						Params: &hkdfprfpb.HkdfPrfParams{
							Hash: hashType.proto,
							Salt: salt,
						},
					}),
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				}, tinkpb.OutputPrefixType_RAW, 0),
			})
		}
	}
	return tcs
}

func TestParseKey(t *testing.T) {
	for _, tc := range hkdfPRFSerializationTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, err := protoserialization.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey(%v) err = %v, want nil", tc.keySerialization, err)
			}
			if !gotKey.Equal(tc.key) {
				t.Errorf("key.Equal(wantKey) = false, want true")
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
			name: "key is not an AES key",
			key:  &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.SerializeKey(tc.key); err == nil {
				t.Errorf("protoserialization.SerializeKey() err = nil, want error")
			}
		})
	}
}

func TestSerializeKey(t *testing.T) {
	for _, tc := range hkdfPRFSerializationTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeKey(tc.key)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", tc.key, err)
			}
			if !got.Equal(tc.keySerialization) {
				t.Errorf("got.Equal(tc.wantKeySerialization) = false, want true")
			}
		})
	}
}

func mustCreateKeyTemplate(t *testing.T, keySizeInBytes uint32, hashType commonpb.HashType, salt []byte) *tinkpb.KeyTemplate {
	t.Helper()
	return &tinkpb.KeyTemplate{
		TypeUrl:          "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKeyFormat{
			KeySize: keySizeInBytes,
			Version: 0,
			Params: &hkdfprfpb.HkdfPrfParams{
				Hash: hashType,
				Salt: salt,
			},
		}),
	}
}

type parametersSerializationTestCase struct {
	name        string
	parameters  *hkdfprf.Parameters
	keyTemplate *tinkpb.KeyTemplate
}

func mustCreateParametersTestParameters(t *testing.T) []parametersSerializationTestCase {
	var tcs []parametersSerializationTestCase

	for _, hashType := range []struct {
		enum  hkdfprf.HashType
		proto commonpb.HashType
	}{
		{enum: hkdfprf.SHA1, proto: commonpb.HashType_SHA1},
		{enum: hkdfprf.SHA224, proto: commonpb.HashType_SHA224},
		{enum: hkdfprf.SHA256, proto: commonpb.HashType_SHA256},
		{enum: hkdfprf.SHA384, proto: commonpb.HashType_SHA384},
		{enum: hkdfprf.SHA512, proto: commonpb.HashType_SHA512},
	} {
		for _, salt := range [][]byte{nil, []byte("salt")} {
			for _, keySize := range []int{16, 32} {
				tcs = append(tcs, parametersSerializationTestCase{
					name:        fmt.Sprintf("HKDF-PRF,hashType=%v,salt=%v", hashType.enum, salt),
					parameters:  mustCreateParameters(t, keySize, hashType.enum, salt),
					keyTemplate: mustCreateKeyTemplate(t, uint32(keySize), hashType.proto, salt),
				})
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
				t.Fatalf("protoserialization.SerializeParameters(%v) err = %v, want nil", tc.parameters, err)
			}
			if diff := cmp.Diff(tc.keyTemplate, got, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeParameters(%v) returned unexpected diff (-want +got):\n%s", tc.parameters, diff)
			}
		})
	}
}

func TestParseParameters(t *testing.T) {
	for _, tc := range mustCreateParametersTestParameters(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseParameters(tc.keyTemplate)
			if err != nil {
				t.Fatalf("protoserialization.ParseParameters(%v) err = %v, want nil", tc.keyTemplate, err)
			}
			if diff := cmp.Diff(tc.parameters, got); diff != "" {
				t.Errorf("protoserialization.ParseParameters(%v) returned unexpected diff (-want +got):\n%s", tc.keyTemplate, diff)
			}
		})
	}
}

func TestParseParametersFailsWithWrongKeyTemplate(t *testing.T) {
	for _, tc := range []struct {
		name        string
		keyTemplate *tinkpb.KeyTemplate
	}{
		{
			name:        "empty",
			keyTemplate: &tinkpb.KeyTemplate{},
		},
		{
			name: "empty format",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
				Value:            mustMarshal(t, &hkdfprfpb.HkdfPrfKeyFormat{}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			name: "invalid format value",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
				Value:            []byte("invalid format"),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			name: "invalid key size",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
				Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKeyFormat{
					KeySize: 10,
					Version: 0,
					Params: &hkdfprfpb.HkdfPrfParams{
						Hash: commonpb.HashType_SHA256,
						Salt: []byte("1234567890123456"),
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			name: "invalid hash type",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
				Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKeyFormat{
					KeySize: 16,
					Version: 0,
					Params: &hkdfprfpb.HkdfPrfParams{
						Hash: commonpb.HashType_UNKNOWN_HASH,
						Salt: []byte("1234567890123456"),
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			name: "invalid output prefix",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
				Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKeyFormat{
					KeySize: 16,
					Version: 0,
					Params: &hkdfprfpb.HkdfPrfParams{
						Hash: commonpb.HashType_SHA256,
						Salt: []byte("1234567890123456"),
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "unknown output prefix type",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
				Value: mustMarshal(t, &hkdfprfpb.HkdfPrfKeyFormat{
					KeySize: 16,
					Version: 0,
					Params: &hkdfprfpb.HkdfPrfParams{
						Hash: commonpb.HashType_SHA256,
						Salt: []byte("1234567890123456"),
					},
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseParameters(tc.keyTemplate); err == nil {
				t.Errorf("protoserialization.ParseParameters(%v) err = nil, want error", tc.keyTemplate)
			}
		})
	}
}

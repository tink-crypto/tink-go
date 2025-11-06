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

package aessiv_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/daead/aessiv"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
	aessivpb "github.com/tink-crypto/tink-go/v2/proto/aes_siv_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestParseKeyFails(t *testing.T) {
	key := aessivpb.AesSivKey{
		Version:  0,
		KeyValue: []byte("1234567890123456"),
	}
	serializedKey, err := proto.Marshal(&key)
	if err != nil {
		t.Fatalf("proto.Marshal(key) err = %v, want nil", err)
	}
	keyWithInvalidSize := aessivpb.AesSivKey{
		Version:  0,
		KeyValue: []byte("0123"),
	}
	serializedKeyWithInvalidSize, err := proto.Marshal(&keyWithInvalidSize)
	if err != nil {
		t.Fatalf("proto.Marshal(keyWithInvalidSize) err = %v, want nil", err)
	}
	keyWithInvalidVersion := aessivpb.AesSivKey{
		Version:  1,
		KeyValue: []byte("1234567890123456"),
	}
	serializedKeyWithInvalidVersion, err := proto.Marshal(&keyWithInvalidVersion)
	if err != nil {
		t.Fatalf("proto.Marshal(keyWithInvalidVersion) err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name             string
		keyData          *tinkpb.KeyData
		outputPrefixType tinkpb.OutputPrefixType
		keyID            uint32
	}{
		{
			name: "invalid key size",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value:           serializedKeyWithInvalidSize,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid key proto serialization",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value:           []byte("invalid proto"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid key version",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value:           serializedKeyWithInvalidVersion,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid key material type",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid output prefix type",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
			keyID:            12345,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keySerialization, err := protoserialization.NewKeySerialization(tc.keyData, tc.outputPrefixType, tc.keyID)
			if err != nil {
				t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", tc.keyData, tc.outputPrefixType, tc.keyID, err)
			}
			if _, err := protoserialization.ParseKey(keySerialization); err == nil {
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

func TestParseKey(t *testing.T) {
	protoKey := aessivpb.AesSivKey{
		Version:  0,
		KeyValue: []byte("12345678901234561234567890123456"),
	}
	serializedKey, err := proto.Marshal(&protoKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoKey) err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
		wantVariant      aessiv.Variant
	}{
		{
			name: "TINK",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
			wantVariant: aessiv.VariantTink,
		},
		{
			name: "CRUNCHY",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 12345),
			wantVariant: aessiv.VariantCrunchy,
		},
		{
			name: "RAW",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			wantVariant: aessiv.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keySizeInBytes := len(protoKey.GetKeyValue())
			wantParams, err := aessiv.NewParameters(keySizeInBytes, tc.wantVariant)
			if err != nil {
				t.Fatalf("aessiv.NewParameters(%v, %v) err = %v, want nil", keySizeInBytes, tc.wantVariant, err)
			}
			keyMaterial := secretdata.NewBytesFromData(protoKey.GetKeyValue(), testonlyinsecuresecretdataaccess.Token())
			keyID := uint32(0)
			if tc.wantVariant != aessiv.VariantNoPrefix {
				keyID = 12345
			}
			wantKey, err := aessiv.NewKey(keyMaterial, keyID, wantParams)
			if err != nil {
				t.Fatalf("aessiv.NewKey(keyMaterial, %v, wantParams) err = %v, want nil", keyID, err)
			}
			gotKey, err := protoserialization.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey(%v) err = %v, want nil", tc.keySerialization, err)
			}
			if !gotKey.Equal(wantKey) {
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

type protoSerializationTestKey struct {
	keyBytes []byte
	id       uint32
	params   testParams
}

func (k *protoSerializationTestKey) Parameters() key.Parameters { return &k.params }

func (k *protoSerializationTestKey) Equal(other key.Key) bool {
	fallbackProtoKey, ok := other.(*protoSerializationTestKey)
	if !ok {
		return false
	}
	return k.params.Equal(fallbackProtoKey.Parameters())
}

func (k *protoSerializationTestKey) IDRequirement() (uint32, bool) {
	return k.id, k.params.HasIDRequirement()
}

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
			name: "key is not an AES-SIV key",
			key:  &protoSerializationTestKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := protoserialization.SerializeKey(tc.key)
			if err == nil {
				t.Errorf("protoserialization.SerializeKey(&protoSerializationTestKey{}) err = nil, want non-nil")
			}
		})
	}
}

func TestSerializeKey(t *testing.T) {
	protoKey := aessivpb.AesSivKey{
		Version:  0,
		KeyValue: []byte("12345678901234561234567890123456"),
	}
	serializedProtoKey, err := proto.Marshal(&protoKey)
	if err != nil {
		t.Fatalf("proto.Marshal(&protoKey) err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name                 string
		variant              aessiv.Variant
		wantKeySerialization *protoserialization.KeySerialization
	}{
		{
			name:    "key with TINK output prefix type",
			variant: aessiv.VariantTink,
			wantKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value:           serializedProtoKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name:    "key with CRUNCHY output prefix type",
			variant: aessiv.VariantCrunchy,
			wantKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value:           serializedProtoKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 12345),
		},
		{
			// No key ID is set for keys with no prefix.
			name:    "key with RAW output prefix type",
			variant: aessiv.VariantNoPrefix,
			wantKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value:           serializedProtoKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := aessiv.NewParameters(32, tc.variant)
			if err != nil {
				t.Fatalf("aessiv.NewParameters(32, %v) err = %v, want nil", tc.variant, err)
			}
			secretKey := secretdata.NewBytesFromData([]byte("12345678901234561234567890123456"), testonlyinsecuresecretdataaccess.Token())
			keyID := uint32(0)
			if tc.variant != aessiv.VariantNoPrefix {
				keyID = 12345
			}
			key, err := aessiv.NewKey(secretKey, keyID, params)
			if err != nil {
				t.Fatalf("aessiv.NewKey(secretKey, %v, params) err = %v, want nil", keyID, err)
			}
			got, err := protoserialization.SerializeKey(key)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(&protoSerializationTestKey{}) err = %v, want nil", err)
			}
			if !got.Equal(tc.wantKeySerialization) {
				t.Errorf("got.Equal(tc.wantKeySerialization) = false, want true")
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
			parameters: &aessiv.Parameters{},
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
			if _, err := protoserialization.SerializeParameters(tc.parameters); err == nil {
				t.Errorf("protoserialization.SerializeParameters(%v) err = nil, want error", tc.parameters)
			}
		})
	}
}

func mustCreateKeyTemplate(t *testing.T, outputPrefixType tinkpb.OutputPrefixType, keySizeInBytes uint32) *tinkpb.KeyTemplate {
	t.Helper()
	format := &aessivpb.AesSivKeyFormat{
		KeySize: keySizeInBytes,
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", format, err)
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          "type.googleapis.com/google.crypto.tink.AesSivKey",
		OutputPrefixType: outputPrefixType,
		Value:            serializedFormat,
	}
}

type parametersSerializationTestCase struct {
	name        string
	parameters  *aessiv.Parameters
	keyTemplate *tinkpb.KeyTemplate
}

func mustCreateParametersTestParameters(t *testing.T) []parametersSerializationTestCase {
	tcs := []parametersSerializationTestCase{}
	for _, keySize := range []int{32, 48, 64} {
		for _, variantAndPrefix := range []struct {
			variant          aessiv.Variant
			outputPrefixType tinkpb.OutputPrefixType
		}{
			{variant: aessiv.VariantTink, outputPrefixType: tinkpb.OutputPrefixType_TINK},
			{variant: aessiv.VariantCrunchy, outputPrefixType: tinkpb.OutputPrefixType_CRUNCHY},
			{variant: aessiv.VariantNoPrefix, outputPrefixType: tinkpb.OutputPrefixType_RAW},
		} {
			params, err := aessiv.NewParameters(keySize, variantAndPrefix.variant)
			if err != nil {
				t.Fatalf("aessiv.NewParameters(%v, %v) err = %v, want nil", keySize, variantAndPrefix.variant, err)
			}
			tcs = append(tcs, parametersSerializationTestCase{
				name:        fmt.Sprintf("AES%d-SIV-%s", keySize*8, variantAndPrefix.variant),
				parameters:  params,
				keyTemplate: mustCreateKeyTemplate(t, variantAndPrefix.outputPrefixType, uint32(keySize)),
			})
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
		name        string
		keyTemplate *tinkpb.KeyTemplate
	}{
		{
			name:        "empty",
			keyTemplate: &tinkpb.KeyTemplate{},
		},
		{
			name: "nil value",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value:            nil,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "empty format",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value:            mustMarshal(t, &aessivpb.AesSivKeyFormat{}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid format type",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value:            []byte("invalid format"),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid version",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value: mustMarshal(t, &aessivpb.AesSivKeyFormat{
					KeySize: 16,
					Version: 1,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "invalid key size",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value: mustMarshal(t, &aessivpb.AesSivKeyFormat{
					KeySize: 10,
				}),
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
		},
		{
			name: "unknown output prefix type",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl: "type.googleapis.com/google.crypto.tink.AesSivKey",
				Value: mustMarshal(t, &aessivpb.AesSivKeyFormat{
					KeySize: 16,
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

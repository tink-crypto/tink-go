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

package aesgcmsiv

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	aesgcmsivpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_siv_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestParseKeyFails(t *testing.T) {
	key := aesgcmsivpb.AesGcmSivKey{
		Version:  0,
		KeyValue: []byte("1234567890123456"),
	}
	serializedKey, err := proto.Marshal(&key)
	if err != nil {
		t.Fatalf("proto.Marshal(key) err = %v, want nil", err)
	}
	keyWithInvalidSize := aesgcmsivpb.AesGcmSivKey{
		Version:  0,
		KeyValue: []byte("0123"),
	}
	serializedKeyWithInvalidSize, err := proto.Marshal(&keyWithInvalidSize)
	if err != nil {
		t.Fatalf("proto.Marshal(keyWithInvalidSize) err = %v, want nil", err)
	}
	keyWithInvalidVersion := aesgcmsivpb.AesGcmSivKey{
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
			name:             "key data is nil",
			keyData:          nil,
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "wrong type URL",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "invalid_type_url",
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid AES-GCM-SIV key size",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
				Value:           serializedKeyWithInvalidSize,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid AES-GCM-SIV key proto serialization",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
				Value:           []byte("invalid proto"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid AES-GCM-SIV key version",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
				Value:           serializedKeyWithInvalidVersion,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid key material type",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			},
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			keyID:            12345,
		},
		{
			name: "invalid output prefix type",
			keyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
				Value:           serializedKey,
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

func TestParseKey(t *testing.T) {
	protoKey := aesgcmsivpb.AesGcmSivKey{
		Version:  0,
		KeyValue: []byte("1234567890123456"),
	}
	serializedKey, err := proto.Marshal(&protoKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoKey) err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
		wantVariant      Variant
	}{
		{
			name: "key with TINK output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
			wantVariant: VariantTink,
		},
		{
			name: "key with CRUNCHY output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 12345),
			wantVariant: VariantCrunchy,
		},
		{
			name: "key with RAW output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			wantVariant: VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keySizeInBytes := len(protoKey.GetKeyValue())
			wantParams, err := NewParameters(keySizeInBytes, tc.wantVariant)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v) err = %v, want nil", keySizeInBytes, tc.wantVariant, err)
			}
			keyMaterial := secretdata.NewBytesFromData(protoKey.GetKeyValue(), insecuresecretdataaccess.Token{})
			keyID := uint32(0)
			if tc.wantVariant != VariantNoPrefix {
				keyID = 12345
			}
			wantKey, err := NewKey(keyMaterial, keyID, wantParams)
			if err != nil {
				t.Fatalf("NewKey(keyMaterial, %v, wantParams) err = %v, want nil", keyID, err)
			}
			p := &keyParser{}
			gotKey, err := p.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("protoserialization.ParseKey(%v) err = %v, want nil", tc.keySerialization, err)
			}
			if !gotKey.Equals(wantKey) {
				t.Errorf("key.Equals(wantKey) = false, want true")
			}
		})
	}
}

type testParams struct {
	hasIDRequirement bool
}

func (p *testParams) HasIDRequirement() bool { return p.hasIDRequirement }

func (p *testParams) Equals(params key.Parameters) bool {
	_, ok := params.(*testParams)
	return ok && p.hasIDRequirement == params.HasIDRequirement()
}

type testKey struct {
	keyBytes []byte
	id       uint32
	params   testParams
}

func (k *testKey) Parameters() key.Parameters { return &k.params }

func (k *testKey) Equals(other key.Key) bool {
	fallbackProtoKey, ok := other.(*testKey)
	if !ok {
		return false
	}
	return k.params.Equals(fallbackProtoKey.Parameters())
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
			name: "key is not an AES-GCM-SIV key",
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
	protoKey := aesgcmsivpb.AesGcmSivKey{
		Version:  0,
		KeyValue: []byte("1234567890123456"),
	}
	serializedProtoKey, err := proto.Marshal(&protoKey)
	if err != nil {
		t.Fatalf("proto.Marshal(&protoKey) err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name                 string
		variant              Variant
		wantKeySerialization *protoserialization.KeySerialization
	}{
		{
			name:    "key with TINK output prefix type",
			variant: VariantTink,
			wantKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
				Value:           serializedProtoKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name:    "key with CRUNCHY output prefix type",
			variant: VariantCrunchy,
			wantKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
				Value:           serializedProtoKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 12345),
		},
		{
			// No key ID is set for keys with no prefix.
			name:    "key with RAW output prefix type",
			variant: VariantNoPrefix,
			wantKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
				Value:           serializedProtoKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := NewParameters(16, tc.variant)
			if err != nil {
				t.Fatalf("NewParameters(16, %v) err = %v, want nil", tc.variant, err)
			}
			secretKey := secretdata.NewBytesFromData([]byte("1234567890123456"), insecuresecretdataaccess.Token{})
			keyID := uint32(0)
			if tc.variant != VariantNoPrefix {
				keyID = 12345
			}
			key, err := NewKey(secretKey, keyID, params)
			if err != nil {
				t.Fatalf("NewKey(secretKey, %v, params) err = %v, want nil", keyID, err)
			}
			aesGCMSerializer := &keySerializer{}
			got, err := aesGCMSerializer.SerializeKey(key)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(&testKey{}) err = %v, want nil", err)
			}
			if !got.Equals(tc.wantKeySerialization) {
				t.Errorf("got.Equals(tc.wantKeySerialization) = false, want true")
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

func mustCreateKeyTemplate(t *testing.T, outputPrefixType tinkpb.OutputPrefixType, keySizeInBytes uint32) *tinkpb.KeyTemplate {
	t.Helper()
	format := &aesgcmsivpb.AesGcmSivKeyFormat{
		KeySize: keySizeInBytes,
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", format, err)
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
		OutputPrefixType: outputPrefixType,
		Value:            serializedFormat,
	}
}

func TestSerializeParameters(t *testing.T) {
	for _, tc := range []struct {
		name            string
		keySizeInBytes  int
		variant         Variant
		wantKeyTemplate *tinkpb.KeyTemplate
	}{
		{
			name:            "AES128-GCM-SIV TINK output prefix type",
			keySizeInBytes:  16,
			variant:         VariantTink,
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, 16),
		},
		{
			name:            "AES256-GCM-SIV TINK output prefix type",
			keySizeInBytes:  32,
			variant:         VariantTink,
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, 32),
		},
		{
			name:            "AES128-GCM-SIV RAW output prefix type",
			keySizeInBytes:  16,
			variant:         VariantNoPrefix,
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, 16),
		},
		{
			name:            "AES256-GCM-SIV RAW output prefix type",
			keySizeInBytes:  32,
			variant:         VariantNoPrefix,
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, 32),
		},
		{
			name:            "AES128-GCM-SIV CRUNCHY output prefix type",
			keySizeInBytes:  16,
			variant:         VariantCrunchy,
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, 16),
		},
		{
			name:            "AES256-GCM-SIV CRUNCHY output prefix type",
			keySizeInBytes:  32,
			variant:         VariantCrunchy,
			wantKeyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, 32),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := NewParameters(tc.keySizeInBytes, tc.variant)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v) err = %v, want nil", tc.keySizeInBytes, tc.variant, err)
			}
			serializer := &parametersSerializer{}
			gotKeyTemplate, err := serializer.Serialize(params)
			if err != nil {
				t.Fatalf("serializer.Serialize(%v) err = %v, want nil", params, err)
			}
			if diff := cmp.Diff(tc.wantKeyTemplate, gotKeyTemplate, protocmp.Transform()); diff != "" {
				t.Errorf("serializer.Serialize(%v) returned unexpected diff (-want +got):\n%s", params, diff)
			}
		})
	}
}
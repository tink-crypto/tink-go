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

package aesgcm

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	aesgcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestParseKeyFails(t *testing.T) {
	key := aesgcmpb.AesGcmKey{
		Version:  0,
		KeyValue: []byte("1234567890123456"),
	}
	serializedKey, err := proto.Marshal(&key)
	if err != nil {
		t.Fatalf("proto.Marshal(key) err = %v, want nil", err)
	}
	keyWithInvalidSize := aesgcmpb.AesGcmKey{
		Version:  0,
		KeyValue: []byte("0123"),
	}
	serializedKeyWithInvalidSize, err := proto.Marshal(&keyWithInvalidSize)
	if err != nil {
		t.Fatalf("proto.Marshal(keyWithInvalidSize) err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name      string
		keysetKey *tinkpb.Keyset_Key
	}{
		{
			name:      "keyset key is nil",
			keysetKey: nil,
		},
		{
			name: "key data is nil",
			keysetKey: &tinkpb.Keyset_Key{
				KeyData:          nil,
				Status:           tinkpb.KeyStatusType_ENABLED,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				KeyId:            12345,
			},
		},
		{
			name: "wrong type URL",
			keysetKey: &tinkpb.Keyset_Key{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         "invalid_type_url",
					Value:           serializedKey,
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				},
				Status:           tinkpb.KeyStatusType_ENABLED,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				KeyId:            12345,
			},
		},
		{
			name: "invalid AES GCM key size",
			keysetKey: &tinkpb.Keyset_Key{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         typeURL,
					Value:           serializedKeyWithInvalidSize,
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				},
				Status:           tinkpb.KeyStatusType_ENABLED,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				KeyId:            12345,
			},
		},
		{
			name: "invalid AES GCM key proto serialization",
			keysetKey: &tinkpb.Keyset_Key{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         typeURL,
					Value:           []byte("invalid proto"),
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				},
				Status:           tinkpb.KeyStatusType_ENABLED,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				KeyId:            12345,
			},
		},
		{
			name: "invalid key material type",
			keysetKey: &tinkpb.Keyset_Key{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         typeURL,
					Value:           serializedKey,
					KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
				},
				Status:           tinkpb.KeyStatusType_ENABLED,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				KeyId:            12345,
			},
		},
		{
			name: "invalid output prefix type",
			keysetKey: &tinkpb.Keyset_Key{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         typeURL,
					Value:           serializedKey,
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				},
				Status:           tinkpb.KeyStatusType_ENABLED,
				OutputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
				KeyId:            12345,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &parser{}
			if _, err := p.ParseKey(tc.keysetKey); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want non-nil", tc.keysetKey)
			}
		})
	}
}

func TestParseKey(t *testing.T) {
	protoKey := aesgcmpb.AesGcmKey{
		Version:  0,
		KeyValue: []byte("1234567890123456"),
	}
	serializedKey, err := proto.Marshal(&protoKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoKey) err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name        string
		keysetKey   *tinkpb.Keyset_Key
		wantVariant Variant
	}{
		{
			name: "key with TINK output prefix type",
			keysetKey: &tinkpb.Keyset_Key{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         typeURL,
					Value:           serializedKey,
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				},
				Status:           tinkpb.KeyStatusType_ENABLED,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				KeyId:            12345,
			},
			wantVariant: VariantTink,
		},
		{
			name: "key with CRUNCHY output prefix type",
			keysetKey: &tinkpb.Keyset_Key{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         typeURL,
					Value:           serializedKey,
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				},
				Status:           tinkpb.KeyStatusType_ENABLED,
				OutputPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
				KeyId:            12345,
			},
			wantVariant: VariantCrunchy,
		},
		{
			name: "key with RAW output prefix type",
			keysetKey: &tinkpb.Keyset_Key{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         typeURL,
					Value:           serializedKey,
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				},
				Status:           tinkpb.KeyStatusType_ENABLED,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				KeyId:            12345,
			},
			wantVariant: VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := ParametersOpts{
				KeySizeInBytes: len(protoKey.GetKeyValue()),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        tc.wantVariant,
			}
			wantParams, err := NewParameters(opts)
			if err != nil {
				t.Fatalf("NewParameters(%v) err = %v, want nil", opts, err)
			}
			keyMaterial := secretdata.NewBytesFromData(protoKey.GetKeyValue(), insecuresecretdataaccess.Token{})
			keyID := uint32(0)
			if tc.wantVariant != VariantNoPrefix {
				keyID = 12345
			}
			wantKey, err := NewKey(*keyMaterial, keyID, wantParams)
			if err != nil {
				t.Fatalf("NewKey(keyMaterial, %v, wantParams) err = %v, want nil", keyID, err)
			}
			p := &parser{}
			gotKey, err := p.ParseKey(tc.keysetKey)
			if err != nil {
				t.Errorf("protoserialization.ParseKey(%v) err = %v, want nil", tc.keysetKey, err)
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
			name: "key is not an AES GCM key",
			key:  &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			aesGCMSerializer := &serializer{}
			_, err := aesGCMSerializer.SerializeKey(tc.key)
			if err == nil {
				t.Errorf("protoserialization.SerializeKey(&testKey{}) err = nil, want non-nil")
			}
		})
	}
}

func TestSerializeKey(t *testing.T) {
	protoKey := aesgcmpb.AesGcmKey{
		Version:  0,
		KeyValue: []byte("1234567890123456"),
	}
	serializedProtoKey, err := proto.Marshal(&protoKey)
	if err != nil {
		t.Fatalf("proto.Marshal(&protoKey) err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name         string
		variant      Variant
		wantProtoKey *tinkpb.Keyset_Key
	}{
		{
			name:    "key with TINK output prefix type",
			variant: VariantTink,
			wantProtoKey: &tinkpb.Keyset_Key{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         typeURL,
					Value:           serializedProtoKey,
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				},
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				KeyId:            12345,
			},
		},
		{
			name:    "key with CRUNCHY output prefix type",
			variant: VariantCrunchy,
			wantProtoKey: &tinkpb.Keyset_Key{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         typeURL,
					Value:           serializedProtoKey,
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				},
				OutputPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
				KeyId:            12345,
			},
		},
		{
			// No key ID is set for keys with no prefix.
			name:    "key with RAW output prefix type",
			variant: VariantNoPrefix,
			wantProtoKey: &tinkpb.Keyset_Key{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         typeURL,
					Value:           serializedProtoKey,
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				},
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := ParametersOpts{
				KeySizeInBytes: 16,
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        tc.variant,
			}
			params, err := NewParameters(opts)
			if err != nil {
				t.Fatalf("NewParameters(%v) err = %v, want nil", opts, err)
			}
			secretKey := secretdata.NewBytesFromData([]byte("1234567890123456"), insecuresecretdataaccess.Token{})
			keyID := uint32(0)
			if tc.variant != VariantNoPrefix {
				keyID = 12345
			}
			key, err := NewKey(*secretKey, keyID, params)
			if err != nil {
				t.Fatalf("NewKey(secretKey, %v, params) err = %v, want nil", keyID, err)
			}
			aesGCMSerializer := &serializer{}
			got, err := aesGCMSerializer.SerializeKey(key)
			if err != nil {
				t.Errorf("protoserialization.SerializeKey(&testKey{}) err = %v, want nil", err)
			}
			if diff := cmp.Diff(got, tc.wantProtoKey, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeKey(&testKey{}) = %v, want %v, diff %v", got, tc.wantProtoKey, diff)
			}
		})
	}
}
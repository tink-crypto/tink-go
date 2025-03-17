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

package hmac_test

import (
	"fmt"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/mac/hmac"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
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
	serializedKey := mustMarshal(t, &hmacpb.HmacKey{
		Version:  0,
		KeyValue: []byte("1234567890123456"),
		Params: &hmacpb.HmacParams{
			TagSize: 16,
			Hash:    commonpb.HashType_SHA256,
		},
	})
	serializedKeyWithInvalidKeyBytes := mustMarshal(t, &hmacpb.HmacKey{
		Version:  0,
		KeyValue: []byte("0123"),
		Params: &hmacpb.HmacParams{
			TagSize: 16,
			Hash:    commonpb.HashType_SHA256,
		},
	})
	serializedKeyWithInvalidTagSize := mustMarshal(t, &hmacpb.HmacKey{
		Version:  0,
		KeyValue: []byte("1234567890123456"),
		Params: &hmacpb.HmacParams{
			TagSize: 2,
			Hash:    commonpb.HashType_SHA256,
		},
	})
	serializedKeyWithInvalidVersion := mustMarshal(t, &hmacpb.HmacKey{
		Version:  1,
		KeyValue: []byte("1234567890123456"),
		Params: &hmacpb.HmacParams{
			TagSize: 16,
			Hash:    commonpb.HashType_SHA256,
		},
	})
	serializedKeyWithInvalidHashType := mustMarshal(t, &hmacpb.HmacKey{
		Version:  0,
		KeyValue: []byte("1234567890123456"),
		Params: &hmacpb.HmacParams{
			TagSize: 16,
			Hash:    commonpb.HashType_UNKNOWN_HASH,
		},
	})
	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name: "invalid HMAC key size",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.HmacKey",
				Value:           serializedKeyWithInvalidKeyBytes,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid TAG size",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.HmacKey",
				Value:           serializedKeyWithInvalidTagSize,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid Hash type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.HmacKey",
				Value:           serializedKeyWithInvalidHashType,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid TAG size",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.HmacKey",
				Value:           serializedKeyWithInvalidTagSize,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid key proto serialization",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.HmacKey",
				Value:           []byte("invalid proto"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.HmacKey",
				Value:           serializedKeyWithInvalidVersion,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.HmacKey",
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_UNKNOWN_PREFIX, 12345),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want error", tc.keySerialization)
			}
		})
	}
}

type aesCMACSerializationTestCase struct {
	name             string
	key              *hmac.Key
	keySerialization *protoserialization.KeySerialization
}

func aesCMACSerializationTestCases(t *testing.T) []aesCMACSerializationTestCase {
	tcs := []aesCMACSerializationTestCase{}
	for _, keySize := range []int{16, 32} {
		for _, hash := range []struct {
			hashType          hmac.HashType
			protoHashType     commonpb.HashType
			maxTagSizeInBytes int
		}{
			{hmac.SHA1, commonpb.HashType_SHA1, 20},
			{hmac.SHA224, commonpb.HashType_SHA224, 28},
			{hmac.SHA256, commonpb.HashType_SHA256, 32},
			{hmac.SHA384, commonpb.HashType_SHA384, 48},
			{hmac.SHA512, commonpb.HashType_SHA512, 64},
		} {
			for _, variantAndPrefix := range []struct {
				variant          hmac.Variant
				outputPrefixType tinkpb.OutputPrefixType
			}{
				{variant: hmac.VariantTink, outputPrefixType: tinkpb.OutputPrefixType_TINK},
				{variant: hmac.VariantCrunchy, outputPrefixType: tinkpb.OutputPrefixType_CRUNCHY},
				{variant: hmac.VariantLegacy, outputPrefixType: tinkpb.OutputPrefixType_LEGACY},
				{variant: hmac.VariantNoPrefix, outputPrefixType: tinkpb.OutputPrefixType_RAW},
			} {
				idRequirement := uint32(0)
				if variantAndPrefix.variant != hmac.VariantNoPrefix {
					idRequirement = 0x01020304
				}
				keyBytes := slices.Repeat([]byte{0x01}, keySize)
				tcs = append(tcs, aesCMACSerializationTestCase{
					name: fmt.Sprintf("keySize=%d,hashType=%s,variant=%s", keySize, hash.hashType, variantAndPrefix.variant),
					key: mustCreateKey(t, secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}), mustCreateParameters(t, hmac.ParametersOpts{
						KeySizeInBytes: keySize,
						TagSizeInBytes: hash.maxTagSizeInBytes,
						HashType:       hash.hashType,
						Variant:        variantAndPrefix.variant}), idRequirement),
					keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
						TypeUrl: "type.googleapis.com/google.crypto.tink.HmacKey",
						Value: mustMarshal(t, &hmacpb.HmacKey{
							Version:  0,
							KeyValue: keyBytes,
							Params: &hmacpb.HmacParams{
								TagSize: uint32(hash.maxTagSizeInBytes),
								Hash:    hash.protoHashType,
							},
						}),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					}, variantAndPrefix.outputPrefixType, idRequirement),
				})
			}
		}
	}
	return tcs
}

func TestParseKey(t *testing.T) {
	for _, tc := range aesCMACSerializationTestCases(t) {
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
			name: "key is not an HMAC key",
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
	for _, tc := range aesCMACSerializationTestCases(t) {
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

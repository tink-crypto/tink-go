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

package protoserialization_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/testutil"

	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	testKeyURL  = "test-key-url"
	testKeyURL2 = "test-key-url-2"
)

var (
	ErrKeyParsing             = errors.New("key parsing failed")
	ErrKeySerialization       = errors.New("key serialization failed")
	ErrParamtersSerialization = errors.New("parameters serialization failed")
)

func TestNewKeySerializationFailsIfIDRequirementIsSetButOutputPrefixTypeIsRAW(t *testing.T) {
	keyData := &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	if _, err := protoserialization.NewKeySerialization(keyData, tinkpb.OutputPrefixType_RAW, 123); err == nil {
		t.Errorf("protoserialization.NewKeySerialization(%v, tinkpb.OutputPrefixType_RAW, 123) err = nil, want error", keyData)
	}
}

func newKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

func TestNewKeySerialization(t *testing.T) {
	keyData := &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	for _, tc := range []struct {
		name             string
		outputPrefixType tinkpb.OutputPrefixType
		idRequirement    uint32
		idRequired       bool
	}{
		{
			name:             "TINK output prefix type",
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			idRequirement:    123,
			idRequired:       true,
		},
		{
			name:             "CRUNCHY output prefix type",
			outputPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
			idRequirement:    123,
			idRequired:       true,
		},
		{
			name:             "LEGACY output prefix type",
			outputPrefixType: tinkpb.OutputPrefixType_LEGACY,
			idRequirement:    123,
			idRequired:       true,
		},
		{
			name:             "RAW output prefix type",
			outputPrefixType: tinkpb.OutputPrefixType_RAW,
			idRequirement:    0,
			idRequired:       false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keySerialization, err := protoserialization.NewKeySerialization(keyData, tc.outputPrefixType, tc.idRequirement)
			if err != nil {
				t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, tc.outputPrefixType, tc.idRequirement, err)
			}
			if diff := cmp.Diff(keySerialization.KeyData(), keyData, protocmp.Transform()); diff != "" {
				t.Errorf("keySerialization.KeyData() diff (-want +got):\n%s", diff)
			}
			if got, want := keySerialization.OutputPrefixType(), tc.outputPrefixType; got != want {
				t.Errorf("keySerialization.OutputPrefixType() = %v, want %v", got, want)
			}
			gotIDRequirement, gotIDRequired := keySerialization.IDRequirement()
			if gotIDRequirement != tc.idRequirement {
				t.Errorf("keySerialization.IDRequirement() = %v, want %v", gotIDRequirement, tc.idRequirement)
			}
			if gotIDRequired != tc.idRequired {
				t.Errorf("gotIDRequired = %v, want %v", gotIDRequired, tc.idRequired)
			}
		})
	}
}

func TestKeySerializationEqual(t *testing.T) {
	for _, tc := range []struct {
		name string
		ks1  *protoserialization.KeySerialization
		ks2  *protoserialization.KeySerialization
		want bool
	}{
		{
			name: "equal",
			ks1: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         testKeyURL,
				Value:           []byte("123"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			ks2: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         testKeyURL,
				Value:           []byte("123"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			want: true,
		},
		{
			name: "different key data value",
			ks1: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         testKeyURL,
				Value:           []byte("123"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			ks2: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         testKeyURL,
				Value:           []byte("345"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			want: false,
		},
		{
			name: "different key data type URL",
			ks1: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         testKeyURL,
				Value:           []byte("123"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			ks2: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         testKeyURL2,
				Value:           []byte("123"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			want: false,
		},
		{
			name: "different key data key material type",
			ks1: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         testKeyURL,
				Value:           []byte("123"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			ks2: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         testKeyURL,
				Value:           []byte("123"),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 123),
			want: false,
		},
		{
			name: "different key ID",
			ks1: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         testKeyURL,
				Value:           []byte("123"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			ks2: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         testKeyURL,
				Value:           []byte("123"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 345),
			want: false,
		},
		{
			name: "different output prefix type",
			ks1: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         testKeyURL,
				Value:           []byte("123"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			ks2: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         testKeyURL,
				Value:           []byte("123"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 123),
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ks1.Equal(tc.ks2); got != tc.want {
				t.Errorf("ks1.Equal(ks2) = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFallbackKeyEqual(t *testing.T) {
	keyData1 := &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	keyData2 := &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("456"),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	tests := []struct {
		name string
		key1 key.Key
		key2 key.Key
		want bool
	}{
		{
			name: "equal keys",
			key1: protoserialization.NewFallbackProtoKey(newKeySerialization(t, keyData1, tinkpb.OutputPrefixType_TINK, 1)),
			key2: protoserialization.NewFallbackProtoKey(newKeySerialization(t, keyData1, tinkpb.OutputPrefixType_TINK, 1)),
			want: true,
		},
		{
			name: "keys with different key IDs",
			key1: protoserialization.NewFallbackProtoKey(newKeySerialization(t, keyData1, tinkpb.OutputPrefixType_TINK, 0)),
			key2: protoserialization.NewFallbackProtoKey(newKeySerialization(t, keyData1, tinkpb.OutputPrefixType_TINK, 1)),
			want: false,
		},
		{
			name: "different key data",
			key1: protoserialization.NewFallbackProtoKey(newKeySerialization(t, keyData1, tinkpb.OutputPrefixType_TINK, 1)),
			key2: protoserialization.NewFallbackProtoKey(newKeySerialization(t, keyData2, tinkpb.OutputPrefixType_TINK, 1)),
			want: false,
		},
		{
			name: "different output prefix",
			key1: protoserialization.NewFallbackProtoKey(newKeySerialization(t, keyData1, tinkpb.OutputPrefixType_CRUNCHY, 1)),
			key2: protoserialization.NewFallbackProtoKey(newKeySerialization(t, keyData1, tinkpb.OutputPrefixType_TINK, 1)),
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.key1.Equal(tc.key2); got != tc.want {
				t.Errorf("key1.Equal(key2) = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFallbackKeyParametersEqual(t *testing.T) {
	keyData := &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	tests := []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name:             "with ID requirement",
			keySerialization: newKeySerialization(t, keyData, tinkpb.OutputPrefixType_TINK, 1),
		},
		{
			name:             "without ID requirement",
			keySerialization: newKeySerialization(t, keyData, tinkpb.OutputPrefixType_RAW, 0),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := protoserialization.NewFallbackProtoKey(tc.keySerialization)
			params := key.Parameters()
			if params == nil {
				t.Errorf("key.Parameters() = nil, want not nil")
			}
			otherParameters := protoserialization.NewFallbackProtoKey(tc.keySerialization).Parameters()
			if otherParameters == nil {
				t.Errorf("protoserialization.NewFallbackProtoKey(protoKey).Parameters() = nil, want not nil")
			}
			if !params.Equal(otherParameters) {
				t.Errorf("parameters.Equal(otherParameters) = false, want true")
			}
		})
	}
}

func TestFallbackKeyParametersNotEqual(t *testing.T) {
	keyData := &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	key1 := protoserialization.NewFallbackProtoKey(newKeySerialization(t, keyData, tinkpb.OutputPrefixType_RAW, 0))
	key2 := protoserialization.NewFallbackProtoKey(newKeySerialization(t, keyData, tinkpb.OutputPrefixType_TINK, 123))
	if key1.Parameters().Equal(key2.Parameters()) {
		t.Errorf("parameters.Equal(otherParameters) = true, want false")
	}
}

func TestFallbackKeyIDRequirement(t *testing.T) {
	keyData := &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	for _, tc := range []struct {
		name                 string
		ks                   *protoserialization.KeySerialization
		wantHasIDRequirement bool
		wantIDRequirement    uint32
	}{
		{
			name:                 "with ID requirement",
			ks:                   newKeySerialization(t, keyData, tinkpb.OutputPrefixType_TINK, 123),
			wantHasIDRequirement: true,
			wantIDRequirement:    123,
		},
		{
			name:                 "without ID requirement",
			ks:                   newKeySerialization(t, keyData, tinkpb.OutputPrefixType_RAW, 0),
			wantHasIDRequirement: false,
			wantIDRequirement:    0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := protoserialization.NewFallbackProtoKey(tc.ks)
			idRequirement, hasIDRequirement := key.IDRequirement()
			if hasIDRequirement != tc.wantHasIDRequirement || idRequirement != tc.wantIDRequirement {
				t.Errorf("key.IDRequirement() = (%v, %v), want (%v, %v)", hasIDRequirement, idRequirement, tc.wantHasIDRequirement, tc.wantIDRequirement)
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
	keyData *tinkpb.KeyData
	id      uint32
	params  testParams
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

type testParser struct{}

func (p *testParser) ParseKey(keysetKey *protoserialization.KeySerialization) (key.Key, error) {
	return &testKey{keyData: keysetKey.KeyData()}, nil
}

var _ protoserialization.KeyParser = (*testParser)(nil)

type testKeySerializer struct{}

func (s *testKeySerializer) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	actualKey, ok := key.(*testKey)
	if !ok {
		return nil, fmt.Errorf("type mismatch: got %T, want *testKey", key)
	}
	idReq, _ := actualKey.IDRequirement()
	return protoserialization.NewKeySerialization(actualKey.keyData, tinkpb.OutputPrefixType_TINK, idReq)
}

var _ protoserialization.KeySerializer = (*testKeySerializer)(nil)

type testParamsSerializer struct{}

func (s *testParamsSerializer) Serialize(params key.Parameters) (*tinkpb.KeyTemplate, error) {
	_, ok := params.(*testParams)
	if !ok {
		return nil, fmt.Errorf("type mismatch: got %T, want *testParams", params)
	}
	return &tinkpb.KeyTemplate{
		TypeUrl: testKeyURL,
	}, nil
}

var _ protoserialization.ParametersSerializer = (*testParamsSerializer)(nil)

func TestRegisterKeyParserFailsIfAlreadyRegistered(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(testKeyURL)
	err := protoserialization.RegisterKeyParser(testKeyURL, &testParser{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser(%s) err = %v, want nil", testKeyURL, err)
	}
	if protoserialization.RegisterKeyParser(testKeyURL, &testParser{}) == nil {
		t.Errorf("protoserialization.RegisterKeyParser(%s) err = nil, want error", testKeyURL)
	}
}

func TestParseKey(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(testKeyURL)
	err := protoserialization.RegisterKeyParser(testKeyURL, &testParser{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser(%s) err = %v, want nil", testKeyURL, err)
	}
	keySerialization := newKeySerialization(t, &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, tinkpb.OutputPrefixType_TINK, 123)
	key, err := protoserialization.ParseKey(keySerialization)
	if err != nil {
		t.Fatalf("protoserialization.ParseKey(%s) err = %v, want nil", testKeyURL, err)
	}

	gotKey, ok := key.(*testKey)
	if !ok {
		t.Fatalf("type mismatch: got %T, want *testKey", key)
	}
	wantKey := &testKey{keyData: &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}}
	if diff := cmp.Diff(gotKey.keyData, wantKey.keyData, protocmp.Transform()); diff != "" {
		t.Errorf("testKey.KeyData() diff (-want +got):\n%s", diff)
	}
}

func TestParseKeyReturnsFallbackIfNoParsersRegistered(t *testing.T) {
	// Empty parser map.
	keySerialization := newKeySerialization(t, &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, tinkpb.OutputPrefixType_TINK, 123)
	key, err := protoserialization.ParseKey(keySerialization)
	if err != nil {
		t.Fatalf("protoserialization.ParseKey(%s) err = %v, want nil", testKeyURL, err)
	}
	fallbackProtoKey, ok := key.(*protoserialization.FallbackProtoKey)
	if !ok {
		t.Errorf("type mismatch: got %T, want *protoserialization.FallbackProtoKey", key)
	}
	keyID, hasIDRequirement := fallbackProtoKey.IDRequirement()
	if !hasIDRequirement {
		t.Errorf("hasIDRequirement = false, want true")
	}
	if hasIDRequirement != fallbackProtoKey.Parameters().HasIDRequirement() {
		t.Errorf("hasIDRequirement != fallbackProtoKey.Parameters().HasIDRequirement(), want equal")
	}
	if keyID != 123 {
		t.Errorf("keyID = %d, want 123", keyID)
	}
}

func TestParseKeyReturnsFallbackIfDifferentParserRegistered(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(testKeyURL2)
	// Register a parser for a different key type URL.
	err := protoserialization.RegisterKeyParser(testKeyURL2, &testParser{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser(%s) err = %v, want nil", testKeyURL2, err)
	}
	keySerialization := newKeySerialization(t, &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, tinkpb.OutputPrefixType_TINK, 123)
	key, err := protoserialization.ParseKey(keySerialization)
	if err != nil {
		t.Fatalf("protoserialization.ParseKey(%s) err = %v, want nil", testKeyURL, err)
	}
	_, ok := key.(*protoserialization.FallbackProtoKey)
	if !ok {
		t.Errorf("type mismatch: got %T, want *protoserialization.FallbackProtoKey", key)
	}
}

type alwaysFailingKeyParser struct{}

func (p *alwaysFailingKeyParser) ParseKey(keysetKey *protoserialization.KeySerialization) (key.Key, error) {
	return nil, ErrKeyParsing
}

var _ protoserialization.KeyParser = (*alwaysFailingKeyParser)(nil)

func TestParseKeyFailsIfParserFails(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(testKeyURL)
	err := protoserialization.RegisterKeyParser(testKeyURL, &alwaysFailingKeyParser{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser(%s) err = %v, want nil", testKeyURL, err)
	}
	keySerialization := newKeySerialization(t, &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, tinkpb.OutputPrefixType_TINK, 123)
	_, err = protoserialization.ParseKey(keySerialization)
	if err == nil {
		t.Errorf("protoserialization.ParseKey(%s) err = nil, want error", testKeyURL)
	}
	if !errors.Is(err, ErrKeyParsing) {
		t.Errorf("protoserialization.ParseKey(%s) err = %v, want %v", testKeyURL, err, ErrKeyParsing)
	}
}

func TestRegisterKeySerializerAndSerializeKey(t *testing.T) {
	defer protoserialization.UnregisterKeySerializer[*testKey]()
	err := protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{}) err = %v, want nil", err)
	}

	key := &testKey{
		keyData: &tinkpb.KeyData{
			TypeUrl:         testKeyURL,
			Value:           []byte("123"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
	}
	gotKeySerialization, err := protoserialization.SerializeKey(key)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey(key) err = %v, want nil", err)
	}
	if diff := cmp.Diff(gotKeySerialization.KeyData(), key.keyData, protocmp.Transform()); diff != "" {
		t.Errorf("testKey.KeyData() diff (-want +got):\n%s", diff)
	}
}

func TestRegisterKeySerializerFailsIfAlreadyRegistered(t *testing.T) {
	defer protoserialization.UnregisterKeySerializer[*testKey]()
	err := protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{}) err = %v, want nil", err)
	}
	if protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{}) == nil {
		t.Errorf("protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{}) err = nil, want error")
	}
}

func TestSerializeKeyFailsIfNoSerializersRegistered(t *testing.T) {
	key := &testKey{
		keyData: &tinkpb.KeyData{
			TypeUrl:         testKeyURL,
			Value:           []byte("123"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
	}
	if _, err := protoserialization.SerializeKey(key); err == nil {
		t.Errorf("protoserialization.SerializeKey(key) err = nil, want error")
	}
}

func TestSerializeKeyWithFallbackKey(t *testing.T) {
	keyData := &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	keySerialization := newKeySerialization(t, keyData, tinkpb.OutputPrefixType_TINK, 123)
	key := protoserialization.NewFallbackProtoKey(keySerialization)
	gotKeySerialization, err := protoserialization.SerializeKey(key)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey(key) err = %v, want nil", err)
	}
	if !gotKeySerialization.Equal(keySerialization) {
		t.Errorf("gotKeySerialization.Equal(keySerialization) = false, want true")
	}
	gotKeySerialization.KeyData().Value = []byte("456")
	if gotKeySerialization.Equal(keySerialization) {
		t.Errorf("gotKeySerialization.Equal(keySerialization) = true, want false")
	}
}

func TestSerializeKeyWithFallbackPrivateKey(t *testing.T) {
	keyData := &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}
	keySerialization := newKeySerialization(t, keyData, tinkpb.OutputPrefixType_TINK, 123)
	key, err := protoserialization.NewFallbackProtoPrivateKey(keySerialization)
	if err != nil {
		t.Fatalf("protoserialization.NewFallbackProtoPrivateKey(wantProtoKey) err = %v, want nil", err)
	}
	gotProtoSerialization, err := protoserialization.SerializeKey(key)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey(key) err = %v, want nil", err)
	}
	if !gotProtoSerialization.Equal(keySerialization) {
		t.Errorf("gotProtoSerialization.Equal(keySerialization) = false, want true")
	}
}

func TestNewFallbackProtoPrivateKeyFailsIfNotAsymmetricPrivate(t *testing.T) {
	keyData := &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	keySerialization := newKeySerialization(t, keyData, tinkpb.OutputPrefixType_TINK, 123)
	if _, err := protoserialization.NewFallbackProtoPrivateKey(keySerialization); err == nil {
		t.Errorf("protoserialization.NewFallbackProtoPrivateKey(protoKey) err = nil, want error")
	}
}

func TestPublicKeyFailsIfUnsupportedKey(t *testing.T) {
	keyData := &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}
	keySerialization := newKeySerialization(t, keyData, tinkpb.OutputPrefixType_TINK, 123)
	fallbackPrivateKey, err := protoserialization.NewFallbackProtoPrivateKey(keySerialization)
	if err != nil {
		t.Errorf("protoserialization.NewFallbackProtoPrivateKey(protoKey) err = %v, want nil", err)
	}
	_, err = fallbackPrivateKey.PublicKey()
	if err == nil {
		t.Errorf("fallbackPrivateKey.PublicKey() err = nil, want error")
	}
}

func TestPublicKeyFailsIfNotPrivateKeyManager(t *testing.T) {
	registry.RegisterKeyManager(testutil.NewTestKeyManager([]byte(""), "some-test-key-URL"))
	keyData := &tinkpb.KeyData{
		TypeUrl:         testKeyURL,
		Value:           []byte("123"),
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}
	keySerialization := newKeySerialization(t, keyData, tinkpb.OutputPrefixType_TINK, 123)
	fallbackPrivateKey, err := protoserialization.NewFallbackProtoPrivateKey(keySerialization)
	if err != nil {
		t.Errorf("protoserialization.NewFallbackProtoPrivateKey(keySerialization) err = %v, want nil", err)
	}
	_, err = fallbackPrivateKey.PublicKey()
	fmt.Println(err)
	if err == nil {
		t.Errorf("fallbackPrivateKey.PublicKey() err = nil, want error")
	}
}

func TestPublicKey(t *testing.T) {
	// Tink prepends an extra 0x00 byte to the coordinates (b/264525021).
	x, err := hex.DecodeString("0029578c7ab6ce0d11493c95d5ea05d299d536801ca9cbd50e9924e43b733b83ab")
	if err != nil {
		t.Fatalf("hex.DecodeString(x) err = %v, want nil", err)
	}
	y, err := hex.DecodeString("0008c8049879c6278b2273348474158515accaa38344106ef96803c5a05adc4800")
	if err != nil {
		t.Fatalf("hex.DecodeString(y) err = %v, want nil", err)
	}
	d, err := hex.DecodeString("708309a7449e156b0db70e5b52e606c7e094ed676ce8953bf6c14757c826f590")
	if err != nil {
		t.Fatalf("hex.DecodeString(d) err = %v, want nil", err)
	}

	protoPublicKey := &ecdsapb.EcdsaPublicKey{
		Version: 0,
		Params: &ecdsapb.EcdsaParams{
			Curve:    commonpb.EllipticCurveType_NIST_P256,
			HashType: commonpb.HashType_SHA256,
			Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
		},
		X: x,
		Y: y,
	}
	protoPrivateKey := &ecdsapb.EcdsaPrivateKey{
		Version:   0,
		PublicKey: protoPublicKey,
		KeyValue:  d,
	}

	serializedPrivateProtoKey, err := proto.Marshal(protoPrivateKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPrivateKey) err = %v, want nil", err)
	}

	keySerialization, err := protoserialization.NewKeySerialization(&tinkpb.KeyData{
		TypeUrl:         signature.ECDSAP256KeyTemplate().GetTypeUrl(),
		Value:           serializedPrivateProtoKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, tinkpb.OutputPrefixType_TINK, 123)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(protoPrivateKey, tinkpb.OutputPrefixType_TINK, 123) err = %v, want nil", err)
	}

	fallbackPrivateKey, err := protoserialization.NewFallbackProtoPrivateKey(keySerialization)
	if err != nil {
		t.Fatalf("protoserialization.NewFallbackProtoPrivateKey(keySerialization) err = %v, want nil", err)
	}

	publicKey, err := fallbackPrivateKey.PublicKey()
	if err != nil {
		t.Fatalf("fallbackPrivateKey.PublicKey() err = %v, want nil", err)
	}

	if !publicKey.Parameters().HasIDRequirement() {
		t.Errorf("fallbackPublicKey.Parameters().HasIDRequirement() = false, want true")
	}
	// Check that the contents are as expected.
	serializedProtoPublicKey, err := proto.Marshal(protoPublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPublicKey) err = %v, want nil", err)
	}
	wantPublicKeyData := &tinkpb.KeyData{
		TypeUrl:         testutil.ECDSAVerifierTypeURL,
		Value:           serializedProtoPublicKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}
	publicKeyProtoSerialization, err := protoserialization.SerializeKey(publicKey)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey(publicKey) err = %v, want nil", err)
	}
	if diff := cmp.Diff(publicKeyProtoSerialization.KeyData(), wantPublicKeyData, protocmp.Transform()); diff != "" {
		t.Errorf("fpublicKeyProtoSerialization.KeyData() diff (-want +got):\n%s", diff)
	}
	if got, want := publicKeyProtoSerialization.OutputPrefixType(), keySerialization.OutputPrefixType(); got != want {
		t.Errorf("publicKeyProtoSerialization.OutputPrefixType() = %v, want %v", got, want)
	}
	if idRequirement, required := publicKeyProtoSerialization.IDRequirement(); !required || idRequirement != 123 {
		t.Errorf("publicKeyProtoSerialization.IDRequirement() = (%v, %v), want (true, 123)", idRequirement, required)
	}
}

type alwaysFailingKeySerializer struct{}

func (s *alwaysFailingKeySerializer) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	return nil, ErrKeySerialization
}

var _ protoserialization.KeySerializer = (*alwaysFailingKeySerializer)(nil)

func TestSerializeKeyFailsIfSerializeFails(t *testing.T) {
	defer protoserialization.UnregisterKeySerializer[*testKey]()
	err := protoserialization.RegisterKeySerializer[*testKey](&alwaysFailingKeySerializer{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer[*testKey](&alwaysFailingKeySerializer{}) err = %v, want nil", err)
	}
	key := &testKey{
		keyData: &tinkpb.KeyData{
			TypeUrl:         testKeyURL,
			Value:           []byte("123"),
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
		},
	}
	_, err = protoserialization.SerializeKey(key)
	if err == nil {
		t.Errorf("protoserialization.SerializeKey(key) err = nil, want error")
	}
	if !errors.Is(err, ErrKeySerialization) {
		t.Errorf("protoserialization.SerializeKey(key) err = %v, want %v", err, ErrKeyParsing)
	}
}

func TestRegisterParametersSerializerAndSerializeParameters(t *testing.T) {
	defer protoserialization.ClearParametersSerializers()
	err := protoserialization.RegisterParametersSerializer[*testParams](&testParamsSerializer{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterParametersSerializer[*testParams](&testParamsSerializer{}) err = %v, want nil", err)
	}

	params := &testParams{
		hasIDRequirement: true,
	}

	keyTemplate, err := protoserialization.SerializeParameters(params)
	if err != nil {
		t.Fatalf("protoserialization.SerializeParameters(params) err = %v, want nil", err)
	}
	if keyTemplate.GetTypeUrl() != testKeyURL {
		t.Errorf("keyTemplate.GetTypeUrl() = %s, want %s", keyTemplate.GetTypeUrl(), testKeyURL)
	}
}

func TestRegisterParametersSerializerFailsIfAlreadyRegistered(t *testing.T) {
	defer protoserialization.ClearParametersSerializers()
	err := protoserialization.RegisterParametersSerializer[*testParams](&testParamsSerializer{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterParametersSerializer[*testParams](&testParamsSerializer{}) err = %v, want nil", err)
	}
	if protoserialization.RegisterParametersSerializer[*testParams](&testParamsSerializer{}) == nil {
		t.Errorf("protoserialization.RegisterParametersSerializer[*testParams](&testParamsSerializer{}) err = nil, want error")
	}
}

func TestSerializeParametersFailsIfNoSerializersRegistered(t *testing.T) {
	defer protoserialization.ClearParametersSerializers()
	params := &testParams{
		hasIDRequirement: true,
	}
	if _, err := protoserialization.SerializeParameters(params); err == nil {
		t.Errorf("protoserialization.SerializeParameters(params) err = nil, want error")
	}
}

func TestSerializeParametersFailsIfNilParameters(t *testing.T) {
	defer protoserialization.ClearParametersSerializers()
	if _, err := protoserialization.SerializeParameters(nil); err == nil {
		t.Errorf("protoserialization.SerializeParameters(nil) err = nil, want error")
	}
}

type alwaysFailingParametersSerializer struct{}

func (s *alwaysFailingParametersSerializer) Serialize(params key.Parameters) (*tinkpb.KeyTemplate, error) {
	return nil, ErrParamtersSerialization
}

var _ protoserialization.ParametersSerializer = (*alwaysFailingParametersSerializer)(nil)

func TestSerializeParametersFailsIfParserFails(t *testing.T) {
	defer protoserialization.ClearParametersSerializers()
	err := protoserialization.RegisterParametersSerializer[*testParams](&alwaysFailingParametersSerializer{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterParametersSerializer[*testParams](&alwaysFailingParametersSerializer{}) err = %v, want nil", err)
	}
	params := &testParams{
		hasIDRequirement: true,
	}
	_, err = protoserialization.SerializeParameters(params)
	if err == nil {
		t.Errorf("protoserialization.SerializeParameters(params) err = nil, want error")
	}
	if !errors.Is(err, ErrParamtersSerialization) {
		t.Errorf("protoserialization.SerializeParameters(params) err = %v, want %v", err, ErrKeyParsing)
	}
}

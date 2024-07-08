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
	"bytes"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var (
	testKeyURL  = "test-key-url"
	testKeyURL2 = "test-key-url-2"

	ErrKeyParsing             = errors.New("key parsing failed")
	ErrKeySerialization       = errors.New("key serialization failed")
	ErrParamtersSerialization = errors.New("parameters serialization failed")
)

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

type testParser struct{}

func (p *testParser) ParseKey(keysetKey *tinkpb.Keyset_Key) (key.Key, error) {
	return &testKey{
		keyBytes: keysetKey.GetKeyData().GetValue(),
	}, nil
}

var _ protoserialization.KeyParser = (*testParser)(nil)

type testKeySerializer struct{}

func (s *testKeySerializer) SerializeKey(key key.Key) (*tinkpb.Keyset_Key, error) {
	actualKey, ok := key.(*testKey)
	if !ok {
		return nil, fmt.Errorf("type mismatch: got %T, want *testKey", key)
	}
	return &tinkpb.Keyset_Key{
		KeyData: &tinkpb.KeyData{
			TypeUrl:         testKeyURL,
			Value:           actualKey.keyBytes,
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
		Status:           tinkpb.KeyStatusType_ENABLED,
		KeyId:            actualKey.id,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}, nil
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
	defer protoserialization.ClearKeyParsers()
	err := protoserialization.RegisterKeyParser(testKeyURL, &testParser{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser(%s) err = %v, want nil", testKeyURL, err)
	}
	if protoserialization.RegisterKeyParser(testKeyURL, &testParser{}) == nil {
		t.Errorf("protoserialization.RegisterKeyParser(%s) err = nil, want error", testKeyURL)
	}
}

func TestParseKey(t *testing.T) {
	defer protoserialization.ClearKeyParsers()
	err := protoserialization.RegisterKeyParser(testKeyURL, &testParser{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser(%s) err = %v, want nil", testKeyURL, err)
	}
	protoKeysetKey := &tinkpb.Keyset_Key{
		KeyData: &tinkpb.KeyData{
			TypeUrl:         testKeyURL,
			Value:           []byte("123"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
		Status:           tinkpb.KeyStatusType_ENABLED,
		KeyId:            123,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
	key, err := protoserialization.ParseKey(protoKeysetKey)
	if err != nil {
		t.Fatalf("protoserialization.ParseKey(%s) err = %v, want nil", testKeyURL, err)
	}

	gotKey, ok := key.(*testKey)
	if !ok {
		t.Fatalf("type mismatch: got %T, want *testKey", key)
	}
	wantKey := &testKey{
		keyBytes: []byte("123"),
	}
	if !bytes.Equal(gotKey.keyBytes, wantKey.keyBytes) {
		t.Errorf("bytes.Equal(%v, %v) = false, want true", gotKey.keyBytes, wantKey.keyBytes)
	}
}

func TestParseKeyReturnsFallbackIfNoParsersRegistered(t *testing.T) {
	defer protoserialization.ClearKeyParsers()
	// Empty parser map.
	key, err := protoserialization.ParseKey(&tinkpb.Keyset_Key{
		KeyData: &tinkpb.KeyData{
			TypeUrl:         testKeyURL,
			Value:           []byte("123"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
		Status:           tinkpb.KeyStatusType_ENABLED,
		KeyId:            123,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	})
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
	defer protoserialization.ClearKeyParsers()
	// Register a parser for a different key type URL.
	err := protoserialization.RegisterKeyParser(testKeyURL2, &testParser{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser(%s) err = %v, want nil", testKeyURL2, err)
	}
	key, err := protoserialization.ParseKey(&tinkpb.Keyset_Key{
		KeyData: &tinkpb.KeyData{
			TypeUrl:         testKeyURL,
			Value:           []byte("123"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
		Status:           tinkpb.KeyStatusType_ENABLED,
		KeyId:            123,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	})
	if err != nil {
		t.Fatalf("protoserialization.ParseKey(%s) err = %v, want nil", testKeyURL, err)
	}
	_, ok := key.(*protoserialization.FallbackProtoKey)
	if !ok {
		t.Errorf("type mismatch: got %T, want *protoserialization.FallbackProtoKey", key)
	}
}

type alwaysFailingKeyParser struct{}

func (p *alwaysFailingKeyParser) ParseKey(keysetKey *tinkpb.Keyset_Key) (key.Key, error) {
	return nil, ErrKeyParsing
}

var _ protoserialization.KeyParser = (*alwaysFailingKeyParser)(nil)

func TestParseKeyFailsIfParserFails(t *testing.T) {
	defer protoserialization.ClearKeyParsers()
	err := protoserialization.RegisterKeyParser(testKeyURL, &alwaysFailingKeyParser{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser(%s) err = %v, want nil", testKeyURL, err)
	}
	_, err = protoserialization.ParseKey(&tinkpb.Keyset_Key{
		KeyData: &tinkpb.KeyData{
			TypeUrl:         testKeyURL,
			Value:           []byte("123"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
		Status:           tinkpb.KeyStatusType_ENABLED,
		KeyId:            123,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	})
	if err == nil {
		t.Errorf("protoserialization.ParseKey(%s) err = nil, want error", testKeyURL)
	}
	if !errors.Is(err, ErrKeyParsing) {
		t.Errorf("protoserialization.ParseKey(%s) err = %v, want %v", testKeyURL, err, ErrKeyParsing)
	}
}

func TestRegisterKeySerializerAndSerializeKey(t *testing.T) {
	defer protoserialization.ReinitializeKeySerializers()
	err := protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{}) err = %v, want nil", err)
	}

	key := &testKey{
		keyBytes: []byte("123"),
	}
	gotKeysetKey, err := protoserialization.SerializeKey(key)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey(key) err = %v, want nil", err)
	}
	if !bytes.Equal(gotKeysetKey.GetKeyData().GetValue(), key.keyBytes) {
		t.Errorf("bytes.Equal(%v, %v) = false, want true", gotKeysetKey.GetKeyData().GetValue(), key.keyBytes)
	}
}

func TestRegisterKeySerializerFailsIfAlreadyRegistered(t *testing.T) {
	defer protoserialization.ReinitializeKeySerializers()
	err := protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{}) err = %v, want nil", err)
	}
	if protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{}) == nil {
		t.Errorf("protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{}) err = nil, want error")
	}
}

func TestSerializeKeyFailsIfNoSerializersRegistered(t *testing.T) {
	defer protoserialization.ReinitializeKeySerializers()
	key := &testKey{
		keyBytes: []byte("123"),
	}
	if _, err := protoserialization.SerializeKey(key); err == nil {
		t.Errorf("protoserialization.SerializeKey(key) err = nil, want error")
	}
}

func TestSerializeKeyWithFallbackKey(t *testing.T) {
	defer protoserialization.ReinitializeKeySerializers()
	wantProtoKey := &tinkpb.Keyset_Key{
		KeyData: &tinkpb.KeyData{
			TypeUrl:         testKeyURL,
			Value:           []byte("123"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
		Status:           tinkpb.KeyStatusType_ENABLED,
		KeyId:            123,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
	key := protoserialization.NewFallbackProtoKey(wantProtoKey)
	gotProtoKey, err := protoserialization.SerializeKey(key)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey(key) err = %v, want nil", err)
	}
	if !proto.Equal(gotProtoKey, wantProtoKey) {
		t.Errorf("proto.Equal(%v, %v) = false, want true", gotProtoKey, wantProtoKey)
	}
}

type alwaysFailingKeySerializer struct{}

func (s *alwaysFailingKeySerializer) SerializeKey(key key.Key) (*tinkpb.Keyset_Key, error) {
	return nil, ErrKeySerialization
}

var _ protoserialization.KeySerializer = (*alwaysFailingKeySerializer)(nil)

func TestSerializeKeyFailsIfSerializeFails(t *testing.T) {
	defer protoserialization.ReinitializeKeySerializers()
	err := protoserialization.RegisterKeySerializer[*testKey](&alwaysFailingKeySerializer{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer[*testKey](&alwaysFailingKeySerializer{}) err = %v, want nil", err)
	}
	key := &testKey{
		keyBytes: []byte("123"),
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

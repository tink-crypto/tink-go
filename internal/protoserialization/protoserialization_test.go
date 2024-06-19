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
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var (
	testKeyURL  = "test-key-url"
	testKeyURL2 = "test-key-url-2"

	ErrKeyParsing       = errors.New("key parsing failed")
	ErrKeySerialization = errors.New("key serialization failed")
)

type testKey struct {
	keyBytes []byte
}

type testParser struct{}

func (p *testParser) ParseKey(keysetKey *tinkpb.Keyset_Key) (any, error) {
	return &testKey{
		keyBytes: keysetKey.GetKeyData().GetValue(),
	}, nil
}

var _ protoserialization.KeyParser = (*testParser)(nil)

type testSerializer struct{}

func (s *testSerializer) SerializeKey(key any) (*tinkpb.Keyset_Key, error) {
	actualKey, ok := key.(*testKey)
	if !ok {
		return nil, fmt.Errorf("type mismatch: got %T, want *testKey", key)
	}
	return &tinkpb.Keyset_Key{
		KeyData: &tinkpb.KeyData{
			Value: actualKey.keyBytes,
		},
	}, nil
}

var _ protoserialization.KeySerializer = (*testSerializer)(nil)

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
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		KeyId:            123,
		KeyData: &tinkpb.KeyData{
			TypeUrl: testKeyURL,
			Value:   []byte("123"),
		},
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
			TypeUrl: testKeyURL,
		},
	})
	if err != nil {
		t.Fatalf("protoserialization.ParseKey(%s) err = %v, want nil", testKeyURL, err)
	}
	_, ok := key.(*protoserialization.FallbackProtoKey)
	if !ok {
		t.Errorf("type mismatch: got %T, want *protoserialization.FallbackProtoKey", key)
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
			TypeUrl: testKeyURL,
		},
	})
	if err != nil {
		t.Fatalf("protoserialization.ParseKey(%s) err = %v, want nil", testKeyURL, err)
	}
	_, ok := key.(*protoserialization.FallbackProtoKey)
	if !ok {
		t.Errorf("type mismatch: got %T, want *protoserialization.FallbackProtoKey", key)
	}
}

type failingParser struct{}

func (p *failingParser) ParseKey(keysetKey *tinkpb.Keyset_Key) (any, error) {
	return nil, ErrKeyParsing
}

var _ protoserialization.KeyParser = (*failingParser)(nil)

func TestParseKeyFailsIfParserFails(t *testing.T) {
	defer protoserialization.ClearKeyParsers()
	err := protoserialization.RegisterKeyParser(testKeyURL, &failingParser{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser(%s) err = %v, want nil", testKeyURL, err)
	}
	_, err = protoserialization.ParseKey(&tinkpb.Keyset_Key{
		KeyData: &tinkpb.KeyData{
			TypeUrl: testKeyURL,
		},
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
	err := protoserialization.RegisterKeySerializer[*testKey](&testSerializer{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer[*testKey](&testSerializer{}) err = %v, want nil", err)
	}

	key := &testKey{
		keyBytes: []byte("123"),
	}
	gotKeysetKey, err := protoserialization.SerializeKey(key)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", key, err)
	}
	if !bytes.Equal(gotKeysetKey.GetKeyData().GetValue(), key.keyBytes) {
		t.Errorf("bytes.Equal(%v, %v) = false, want true", gotKeysetKey.GetKeyData().GetValue(), key.keyBytes)
	}
}

func TestRegisterKeySerializerFailsIfAlreadyRegistered(t *testing.T) {
	defer protoserialization.ReinitializeKeySerializers()
	err := protoserialization.RegisterKeySerializer[*testKey](&testSerializer{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer[*testKey](&testSerializer{}) err = %v, want nil", err)
	}
	if protoserialization.RegisterKeySerializer[*testKey](&testSerializer{}) == nil {
		t.Errorf("protoserialization.RegisterKeySerializer[*testKey](&testSerializer{}) err = nil, want error")
	}
}

func TestSerializeKeyFailsIfNoSerializersRegistered(t *testing.T) {
	defer protoserialization.ReinitializeKeySerializers()
	key := &testKey{
		keyBytes: []byte("123"),
	}
	if _, err := protoserialization.SerializeKey(key); err == nil {
		t.Errorf("protoserialization.SerializeKey(%v) err = nil, want error", key)
	}
}

func TestSerializeKeyWithFallbackKey(t *testing.T) {
	defer protoserialization.ReinitializeKeySerializers()
	wantProtoKey := &tinkpb.Keyset_Key{
		KeyData: &tinkpb.KeyData{
			TypeUrl: testKeyURL,
			Value:   []byte("123"),
		},
	}
	key := protoserialization.NewFallbackProtoKey(wantProtoKey)
	gotProtoKey, err := protoserialization.SerializeKey(key)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", key, err)
	}
	if !proto.Equal(gotProtoKey, wantProtoKey) {
		t.Errorf("proto.Equal(%v, %v) = false, want true", gotProtoKey, wantProtoKey)
	}
}

type alwaysFailingSerializer struct{}

func (s *alwaysFailingSerializer) SerializeKey(key any) (*tinkpb.Keyset_Key, error) {
	return nil, ErrKeySerialization
}

var _ protoserialization.KeySerializer = (*alwaysFailingSerializer)(nil)

func TestSerializeKeyFailsIfSerializeFails(t *testing.T) {
	defer protoserialization.ReinitializeKeySerializers()
	err := protoserialization.RegisterKeySerializer[*testKey](&alwaysFailingSerializer{})
	if err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer[*testKey](&alwaysFailingSerializer{}) err = %v, want nil", err)
	}
	key := &testKey{
		keyBytes: []byte("123"),
	}
	_, err = protoserialization.SerializeKey(key)
	if err == nil {
		t.Errorf("protoserialization.SerializeKey(%v) err = nil, want error", key)
	}
	if !errors.Is(err, ErrKeySerialization) {
		t.Errorf("protoserialization.SerializeKey(%v) err = %v, want %v", key, err, ErrKeyParsing)
	}
}

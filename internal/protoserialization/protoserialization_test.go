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
	"testing"

	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var (
	testKeyURL  = "test-key-url"
	testKeyURL2 = "test-key-url-2"

	ErrKeyParsing = errors.New("key parsing failed")
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

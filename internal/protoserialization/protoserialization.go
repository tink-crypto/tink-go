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

// Package protoserialization defines interfaces for proto key to key objects parsers, and provides
// a global registry that maps key type URLs to key parsers. The package also provides a fallback
// proto key struct that wraps a proto keyset key.
package protoserialization

import (
	"fmt"
	"sync"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var (
	keyParsersMu sync.RWMutex
	keyParsers   = make(map[string]KeyParser) // TypeURL -> KeyParser
)

// FallbackProtoKey is a key that wraps a proto keyset key.
//
// This is a fallback key type that is used to wrap individual keyset keys when no concrete key type
// is available; it is purposely internal an does not expose any "getter" to avoid premature use of
// this type.
type FallbackProtoKey struct {
	protoKeysetKey *tinkpb.Keyset_Key
}

// NewFallbackProtoKey creates a new FallbackProtoKey.
func NewFallbackProtoKey(protoKeysetKey *tinkpb.Keyset_Key) *FallbackProtoKey {
	return &FallbackProtoKey{protoKeysetKey: protoKeysetKey}
}

// ProtoKeysetKey returns the proto keyset key wrapped in fallbackProtoKey.
func ProtoKeysetKey(fallbackProtoKey *FallbackProtoKey) *tinkpb.Keyset_Key {
	return fallbackProtoKey.protoKeysetKey
}

// KeyParser is an interface for parsing a proto keyset key into a key.
type KeyParser interface {
	// ParseKey parses the given keyset key into a key and returns (any, nil) if successful, or
	// (nil, err) otherwise.
	ParseKey(keysetKey *tinkpb.Keyset_Key) (any, error)
}

// RegisterKeyParser registers the given key parser to the global registry.
//
// It doesn't allow replacing existing parsers.
func RegisterKeyParser(keyTypeURL string, keyParser KeyParser) error {
	keyParsersMu.Lock()
	defer keyParsersMu.Unlock()
	if _, found := keyParsers[keyTypeURL]; found {
		return fmt.Errorf("protoserialization.RegisterKeyParser: type %s already registered", keyTypeURL)
	}
	keyParsers[keyTypeURL] = keyParser
	return nil
}

// ParseKey parses the given keyset key into a key and returns (any, nil) if successful, or
// (nil, err) otherwise. If no parser is registered for the given type URL, a fallback key is
// returned.
func ParseKey(keysetKey *tinkpb.Keyset_Key) (any, error) {
	parser, found := keyParsers[keysetKey.GetKeyData().GetTypeUrl()]
	if !found {
		return &FallbackProtoKey{protoKeysetKey: keysetKey}, nil
	}
	return parser.ParseKey(keysetKey)
}

// ClearKeyParsers clears the global parsers registry.
//
// This function is intended to be used in tests only.
func ClearKeyParsers() {
	keyParsersMu.Lock()
	defer keyParsersMu.Unlock()
	keyParsers = make(map[string]KeyParser)
}

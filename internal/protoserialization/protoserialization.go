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
	"reflect"
	"sync"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var (
	keyParsersMu     sync.RWMutex
	keyParsers       = make(map[string]KeyParser) // TypeURL -> KeyParser
	keySerializersMu sync.RWMutex
	keySerializers   = make(map[reflect.Type]KeySerializer) // KeyType -> KeySerializer
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

// KeySerializer is an interface for serializing a key into a proto keyset key.
type KeySerializer interface {
	// SerializeKey serializes the given key into a proto keyset key.
	SerializeKey(key any) (*tinkpb.Keyset_Key, error)
}

// RegisterKeySerializer registers the given key serializer for keys of type K.
//
// It doesn't allow replacing existing serializers.
func RegisterKeySerializer[K any](keySerializer KeySerializer) error {
	keySerializersMu.Lock()
	defer keySerializersMu.Unlock()
	keyType := reflect.TypeOf((*K)(nil)).Elem()
	if _, found := keySerializers[keyType]; found {
		return fmt.Errorf("serialization.RegisterKeySerializer: type %v already registered", keyType)
	}
	keySerializers[keyType] = keySerializer
	return nil
}

// SerializeKey serializes the given key into a proto keyset key.
func SerializeKey(key any) (*tinkpb.Keyset_Key, error) {
	keyType := reflect.TypeOf(key)
	serializer, ok := keySerializers[keyType]
	if !ok {
		return nil, fmt.Errorf("serialization.SerializeKey: no serializer for type %v", keyType)
	}
	return serializer.SerializeKey(key)
}

// RegisterKeyParser registers the given key parser.
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

type fallbackProtoKeySerializer struct{}

func (s *fallbackProtoKeySerializer) SerializeKey(key any) (*tinkpb.Keyset_Key, error) {
	fallbackKey, ok := key.(*FallbackProtoKey)
	if !ok {
		return nil, fmt.Errorf("serialization.fallbackProtoKeySerializer.SerializeKey: key is not a FallbackProtoKey")
	}
	return fallbackKey.protoKeysetKey, nil
}

// ClearKeyParsers clears the global key parsers registry.
//
// This function is intended to be used in tests only.
func ClearKeyParsers() {
	keyParsersMu.Lock()
	defer keyParsersMu.Unlock()
	clear(keyParsers)
}

// ReinitializeKeySerializers clears the global key serializers registry and registers
// fallbackProtoKeySerializer.
//
// This function is intended to be used in tests only.
func ReinitializeKeySerializers() {
	keySerializersMu.Lock()
	defer keySerializersMu.Unlock()
	clear(keySerializers)
	// Always register the fallback serializer.
	keySerializers[reflect.TypeOf((*FallbackProtoKey)(nil))] = &fallbackProtoKeySerializer{}
}

func init() {
	RegisterKeySerializer[*FallbackProtoKey](&fallbackProtoKeySerializer{})
}

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

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/key"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var (
	keyParsersMu            sync.RWMutex
	keyParsers              = make(map[string]KeyParser) // TypeURL -> KeyParser
	keySerializersMu        sync.RWMutex
	keySerializers          = make(map[reflect.Type]KeySerializer) // KeyType -> KeySerializer
	parametersSerializersMu sync.RWMutex
	parameterSerializers    = make(map[reflect.Type]ParametersSerializer) // ParameterType -> ParametersSerializer
)

type fallbackProtoKeyParams struct {
	hasIDRequirement bool
}

func (p *fallbackProtoKeyParams) HasIDRequirement() bool { return p.hasIDRequirement }

func (p *fallbackProtoKeyParams) Equals(parameters key.Parameters) bool {
	_, ok := parameters.(*fallbackProtoKeyParams)
	return ok && p.hasIDRequirement == parameters.HasIDRequirement()
}

// FallbackProtoKey is a key that wraps a proto keyset key.
//
// This is a fallback key type that is used to wrap individual keyset keys when no concrete key type
// is available; it is purposely internal and does not allow accessing the internal proto
// representation to avoid premature use of this type.
type FallbackProtoKey struct {
	protoKeysetKey *tinkpb.Keyset_Key
	parameters     *fallbackProtoKeyParams
}

// Parameters returns the parameters of this key.
func (k *FallbackProtoKey) Parameters() key.Parameters { return k.parameters }

// Equals reports whether k is equal to other.
func (k *FallbackProtoKey) Equals(other key.Key) bool {
	otherFallbackProtoKey, ok := other.(*FallbackProtoKey)
	if !ok {
		return false
	}
	return k.parameters.Equals(other.Parameters()) &&
		proto.Equal(k.protoKeysetKey, otherFallbackProtoKey.protoKeysetKey)
}

// IDRequirement returns the key ID and whether it is required.
func (k *FallbackProtoKey) IDRequirement() (uint32, bool) {
	return k.protoKeysetKey.GetKeyId(), k.parameters.HasIDRequirement()
}

// NewFallbackProtoKey creates a new FallbackProtoKey.
func NewFallbackProtoKey(protoKeysetKey *tinkpb.Keyset_Key) *FallbackProtoKey {
	return &FallbackProtoKey{
		protoKeysetKey: protoKeysetKey,
		parameters: &fallbackProtoKeyParams{
			hasIDRequirement: protoKeysetKey.GetOutputPrefixType() != tinkpb.OutputPrefixType_RAW,
		},
	}
}

// ProtoKeysetKey returns the proto keyset key wrapped in fallbackProtoKey.
func ProtoKeysetKey(fallbackProtoKey *FallbackProtoKey) *tinkpb.Keyset_Key {
	return fallbackProtoKey.protoKeysetKey
}

// KeyParser is an interface for parsing a proto keyset key into a key.
type KeyParser interface {
	// ParseKey parses the given keyset key into a key.
	ParseKey(keysetKey *tinkpb.Keyset_Key) (key.Key, error)
}

// KeySerializer is an interface for serializing a key into a proto keyset key.
type KeySerializer interface {
	// SerializeKey serializes the given key into a proto keyset key.
	SerializeKey(key key.Key) (*tinkpb.Keyset_Key, error)
}

// ParametersSerializer is an interface for serializing parameters into a proto key template.
type ParametersSerializer interface {
	// Serialize serializes the given parameters into a proto key template.
	Serialize(parameters key.Parameters) (*tinkpb.KeyTemplate, error)
}

// RegisterKeySerializer registers the given key serializer for keys of type K.
//
// It doesn't allow replacing existing serializers.
func RegisterKeySerializer[K key.Key](keySerializer KeySerializer) error {
	keySerializersMu.Lock()
	defer keySerializersMu.Unlock()
	keyType := reflect.TypeOf((*K)(nil)).Elem()
	if _, found := keySerializers[keyType]; found {
		return fmt.Errorf("serialization.RegisterKeySerializer: type %v already registered", keyType)
	}
	keySerializers[keyType] = keySerializer
	return nil
}

// RegisterParametersSerializer registers the given parameter serializer for parameters of type P.
//
// It doesn't allow replacing existing serializers.
func RegisterParametersSerializer[P key.Parameters](parameterSerializer ParametersSerializer) error {
	parametersSerializersMu.Lock()
	defer parametersSerializersMu.Unlock()
	parameterType := reflect.TypeOf((*P)(nil)).Elem()
	if _, found := parameterSerializers[parameterType]; found {
		return fmt.Errorf("serialization.RegisterParametersSerializer: type %v already registered", parameterType)
	}
	parameterSerializers[parameterType] = parameterSerializer
	return nil
}

// SerializeKey serializes the given key into a proto keyset key.
func SerializeKey(key key.Key) (*tinkpb.Keyset_Key, error) {
	keyType := reflect.TypeOf(key)
	serializer, ok := keySerializers[keyType]
	if !ok {
		return nil, fmt.Errorf("serialization.SerializeKey: no serializer for type %v", keyType)
	}
	return serializer.SerializeKey(key)
}

// SerializeParameters serializes the given parameters into a proto key template.
func SerializeParameters(parameters key.Parameters) (*tinkpb.KeyTemplate, error) {
	if parameters == nil {
		return nil, fmt.Errorf("serialization.SerializeParameters: parameters is nil")
	}
	parametersType := reflect.TypeOf(parameters)
	serializer, ok := parameterSerializers[parametersType]
	if !ok {
		return nil, fmt.Errorf("serialization.SerializeParameters: no serializer for type %v", parametersType)
	}
	return serializer.Serialize(parameters)
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

// ParseKey parses the given keyset key into a key.
//
// If no parser is registered for the given type URL, a fallback key is returned.
func ParseKey(keysetKey *tinkpb.Keyset_Key) (key.Key, error) {
	parser, found := keyParsers[keysetKey.GetKeyData().GetTypeUrl()]
	if !found {
		return NewFallbackProtoKey(keysetKey), nil
	}
	return parser.ParseKey(keysetKey)
}

type fallbackProtoKeySerializer struct{}

func (s *fallbackProtoKeySerializer) SerializeKey(key key.Key) (*tinkpb.Keyset_Key, error) {
	fallbackKey, ok := key.(*FallbackProtoKey)
	if !ok {
		return nil, fmt.Errorf("serialization.fallbackProtoKeySerializer.SerializeKey: key is not a FallbackProtoKey")
	}
	return proto.Clone(fallbackKey.protoKeysetKey).(*tinkpb.Keyset_Key), nil
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

// ClearParametersSerializers clears the global parameters serializers registry.
//
// This function is intended to be used in tests only.
func ClearParametersSerializers() {
	parametersSerializersMu.Lock()
	defer parametersSerializersMu.Unlock()
	clear(parameterSerializers)
}

func init() {
	RegisterKeySerializer[*FallbackProtoKey](&fallbackProtoKeySerializer{})
}

// Copyright 2019 Google LLC
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

// Package primitiveset provides a container for a set of cryptographic
// primitives.
//
// It provides also additional properties for the primitives it holds. In
// particular, one of the primitives in the set can be distinguished as "the
// primary" one.
package primitiveset

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// Entry represents a single entry in the keyset. In addition to the actual
// primitive, it holds the identifier and status of the primitive.
type Entry[T any] struct {
	KeyID         uint32
	Primitive     T
	FullPrimitive T
	Prefix        string
	PrefixType    tinkpb.OutputPrefixType
	Status        tinkpb.KeyStatusType
	TypeURL       string
}

// PrimitiveSet is used for supporting key rotation: primitives in a set
// correspond to keys in a keyset. Users will usually work with primitive
// instances, which essentially wrap primitive sets. For example an instance of
// an AEAD-primitive for a given keyset holds a set of AEAD-primitives
// corresponding to the keys in the keyset, and uses the set members to do the
// actual crypto operations: to encrypt data the primary AEAD-primitive from
// the set is used, and upon decryption the ciphertext's prefix determines the
// id of the primitive from the set.
type PrimitiveSet[T any] struct {
	// Primary entry.
	Primary *Entry[T]

	// The primitives are stored in a map of (ciphertext prefix, list of
	// primitives sharing the prefix). This allows quickly retrieving the
	// primitives sharing some particular prefix.
	Entries map[string][]*Entry[T]
	// Stores entries in the original keyset key order.
	EntriesInKeysetOrder []*Entry[T]

	Annotations map[string]string
}

// New returns an empty instance of PrimitiveSet.
func New[T any]() *PrimitiveSet[T] {
	return &PrimitiveSet[T]{
		Primary:              nil,
		Entries:              make(map[string][]*Entry[T]),
		EntriesInKeysetOrder: make([]*Entry[T], 0),
		Annotations:          nil,
	}
}

// RawEntries returns all primitives in the set that have RAW prefix.
func (ps *PrimitiveSet[T]) RawEntries() ([]*Entry[T], error) {
	return ps.EntriesForPrefix(cryptofmt.RawPrefix)
}

// EntriesForPrefix returns all primitives in the set that have the given prefix.
func (ps *PrimitiveSet[T]) EntriesForPrefix(prefix string) ([]*Entry[T], error) {
	result, found := ps.Entries[prefix]
	if !found {
		return []*Entry[T]{}, nil
	}
	return result, nil
}

func (ps *PrimitiveSet[T]) add(primitive T, key *tinkpb.Keyset_Key, isFullPrimitive bool) (*Entry[T], error) {
	if key == nil {
		return nil, fmt.Errorf("primitive_set: key must not be nil")
	}
	if key.GetKeyData() == nil {
		return nil, fmt.Errorf("primitive_set: keyData must not be nil")
	}
	if key.GetStatus() != tinkpb.KeyStatusType_ENABLED {
		return nil, fmt.Errorf("primitive_set: The key must be ENABLED")
	}
	prefix, err := cryptofmt.OutputPrefix(key)
	if err != nil {
		return nil, fmt.Errorf("primitive_set: %s", err)
	}
	e := &Entry[T]{
		KeyID:      key.GetKeyId(),
		Prefix:     prefix,
		Status:     key.GetStatus(),
		PrefixType: key.GetOutputPrefixType(),
		TypeURL:    key.GetKeyData().GetTypeUrl(),
	}
	if isFullPrimitive {
		e.FullPrimitive = primitive
	} else {
		e.Primitive = primitive
	}
	ps.Entries[prefix] = append(ps.Entries[prefix], e)
	ps.EntriesInKeysetOrder = append(ps.EntriesInKeysetOrder, e)
	return e, nil
}

// Add creates a new entry in the primitive set and returns the added entry.
func (ps *PrimitiveSet[T]) Add(primitive T, key *tinkpb.Keyset_Key) (*Entry[T], error) {
	return ps.add(primitive, key, false)
}

// AddFullPrimitive adds a full primitive to the primitive set.
func (ps *PrimitiveSet[T]) AddFullPrimitive(primitive T, key *tinkpb.Keyset_Key) (*Entry[T], error) {
	return ps.add(primitive, key, true)
}

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

// Package prefixmap provides a map that adds a prefix to each primitive.
package prefixmap

import (
	"fmt"
	"iter"
	"slices"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
)

const (
	// EmptyPrefix is the empty prefix.
	EmptyPrefix = ""
)

// PrefixMap is a map that adds a prefix to each primitive.
type PrefixMap[P any] struct {
	items map[string][]P
}

// New creates a new PrefixMap.
func New[P any]() *PrefixMap[P] {
	return &PrefixMap[P]{
		items: make(map[string][]P),
	}
}

func concat[P any](seqs ...iter.Seq[P]) iter.Seq[P] {
	return func(yield func(P) bool) {
		for _, seq := range seqs {
			for e := range seq {
				if !yield(e) {
					return
				}
			}
		}
	}
}

// PrimitivesMatchingPrefix returns the primitive with the given prefix.
func (m *PrefixMap[P]) PrimitivesMatchingPrefix(prefix []byte) iter.Seq[P] {
	var entriesWithPrefix []P
	if len(prefix) >= cryptofmt.NonRawPrefixSize {
		// Cap the prefix to the size of the non-raw prefix.
		entriesWithPrefix = m.items[string(prefix[:cryptofmt.NonRawPrefixSize])]
	}
	entriesWithoutPrefix := m.items[EmptyPrefix]
	return concat[P](slices.Values(entriesWithPrefix), slices.Values(entriesWithoutPrefix))
}

// Insert adds the primitive with the given prefix.
func (m *PrefixMap[P]) Insert(prefix string, primitive P) error {
	if len(prefix) > 0 && len(prefix) != cryptofmt.NonRawPrefixSize {
		return fmt.Errorf("prefixmap: prefix has size %d, want %d", len(prefix), cryptofmt.NonRawPrefixSize)
	}
	m.items[prefix] = append(m.items[prefix], primitive)
	return nil
}

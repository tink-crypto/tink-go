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

// Package protoserialization contains key types that wrap proto keysets.
package protoserialization

import (
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
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

// Copyright 2018 Google LLC
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

// Package keyset provides methods to generate, read, write or validate
// keysets.
package keyset

import (
	"github.com/tink-crypto/tink-go/v2/internal"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// keysetHandle is used by package insecurecleartextkeyset and package
// testkeyset (via package internal) to create a keyset.Handle from cleartext
// key material.
func keysetHandle(ks *tinkpb.Keyset, opts ...Option) (*Handle, error) {
	return newWithOptions(ks, opts...)
}

// keysetMaterial is used by package insecurecleartextkeyset and package
// testkeyset (via package internal) to read the key material in a
// keyset.Handle. Returns a clone of the keyset.
func keysetMaterial(h *Handle) *tinkpb.Keyset {
	ks, err := entriesToProtoKeyset(h.entries)
	if err != nil {
		return nil
	}
	return ks
}

func init() {
	internal.KeysetHandle = keysetHandle
	internal.KeysetMaterial = keysetMaterial
}

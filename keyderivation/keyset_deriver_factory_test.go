// Copyright 2022 Google LLC
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

package keyderivation

import (
	"strings"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// invalidDeriver returns two keys, but wrappedKeysetDeriver accepts only one.
type invalidDeriver struct{}

var _ KeysetDeriver = (*invalidDeriver)(nil)

func (i *invalidDeriver) DeriveKeyset(salt []byte) (*keyset.Handle, error) {
	manager := keyset.NewManager()
	keyID, err := manager.Add(aead.AES128GCMKeyTemplate())
	if err != nil {
		return nil, err
	}
	manager.SetPrimary(keyID)
	if _, err = manager.Add(aead.AES256GCMKeyTemplate()); err != nil {
		return nil, err
	}
	return manager.Handle()
}

func TestDeriveKeysetWithInvalidPrimitiveImplementationFails(t *testing.T) {
	entry := &primitiveset.Entry[KeysetDeriver]{
		KeyID:     119,
		Primitive: &invalidDeriver{},
		Prefix:    cryptofmt.RawPrefix,
		Status:    tinkpb.KeyStatusType_ENABLED,
		TypeURL:   "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
	}
	ps := &primitiveset.PrimitiveSet[KeysetDeriver]{
		Primary: entry,
		Entries: map[string][]*primitiveset.Entry[KeysetDeriver]{
			cryptofmt.RawPrefix: []*primitiveset.Entry[KeysetDeriver]{entry},
		},
		EntriesInKeysetOrder: []*primitiveset.Entry[KeysetDeriver]{entry},
	}
	wrappedDeriver := &wrappedKeysetDeriver{ps: ps}
	_, err := wrappedDeriver.DeriveKeyset([]byte("salt"))
	if err == nil {
		t.Fatal("DeriveKeyset() err = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "exactly one key") {
		t.Errorf("DeriveKeyset() err = %q, doesn't contain %q", err, "exactly one key")
	}
}

func TestNewWrappedKeysetDeriverWrongPrimitiveFails(t *testing.T) {
	handle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	if _, err := New(handle); err == nil {
		t.Errorf("New() err = nil, want non-nil")
	}
}

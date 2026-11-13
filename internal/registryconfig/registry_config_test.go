// Copyright 2023 Google LLC
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

package registryconfig_test

import (
	"testing"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/keytest"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func mustCreateTestKeysetHandle(t *testing.T) *keyset.Handle {
	t.Helper()
	km := keyset.NewManager()
	p, err := keytest.NewParameters(keytest.VariantTink)
	if err != nil {
		t.Fatalf("keytest.NewParameters(keytest.VariantTink) err = %v, want nil", err)
	}
	keyID, err := km.AddNewKeyFromParameters(p)
	if err != nil {
		t.Fatalf("km.AddNewKeyFromParameters(%v) err = %v, want nil", p, err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary(%d) err = %v, want nil", keyID, err)
	}
	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}
	return handle
}

func TestPrimitiveFromKey(t *testing.T) {
	keyset := mustCreateTestKeysetHandle(t)
	entry, err := keyset.Entry(0)
	if err != nil {
		t.Fatalf("keyset.Entry() err = %v, want nil", err)
	}

	registryConfig := &registryconfig.RegistryConfig{}
	p, err := registryConfig.PrimitiveFromKey(entry.Key(), internalapi.Token{})
	if err != nil {
		t.Errorf("registryConfig.PrimitiveFromKey() err = %v, want nil", err)
	}
	if _, ok := p.(tink.AEAD); !ok {
		t.Errorf("p is not of type tink.AEAD; got %T", p)
	}
}

func TestPrimitiveFromKeyErrors(t *testing.T) {
	registryConfig := &registryconfig.RegistryConfig{}
	testCases := []struct {
		name string
		key  key.Key
	}{
		{
			name: "unregistered key type",
			key:  &stubKey{},
		},
		{
			name: "nil key",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := registryConfig.PrimitiveFromKey(tc.key, internalapi.Token{}); err == nil {
				t.Errorf("registryConfig.PrimitiveFromKey() err = nil, want error")
			}
		})
	}
}

type stubKey struct{}

func (k *stubKey) Parameters() key.Parameters    { return nil }
func (k *stubKey) Equal(other key.Key) bool      { return true }
func (k *stubKey) IDRequirement() (uint32, bool) { return 123, true }

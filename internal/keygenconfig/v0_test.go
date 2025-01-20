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

package keygenconfig_test

import (
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/internal/keygenconfig"
	"github.com/tink-crypto/tink-go/v2/key"
)

func mustCreateAESGCMParams(t *testing.T, variant aesgcm.Variant) *aesgcm.Parameters {
	t.Helper()
	params, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        variant,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	return params
}

func tryCast[T any](k key.Key) error {
	if _, ok := k.(T); !ok {
		return fmt.Errorf("key is of type %T; want %T", k, (*T)(nil))
	}
	return nil
}

func TestV0(t *testing.T) {
	config := keygenconfig.V0()
	for _, tc := range []struct {
		name          string
		p             key.Parameters
		idRequirement uint32
		tryCast       func(key.Key) error
	}{
		{
			name:          "AES-GCM-TINK",
			p:             mustCreateAESGCMParams(t, aesgcm.VariantTink),
			idRequirement: 123,
			tryCast:       tryCast[*aesgcm.Key],
		},
		{
			name:          "AES-GCM-NO_PREFIX",
			p:             mustCreateAESGCMParams(t, aesgcm.VariantNoPrefix),
			idRequirement: 0,
			tryCast:       tryCast[*aesgcm.Key],
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := config.CreateKey(tc.p, tc.idRequirement)
			if err != nil {
				t.Fatalf("config.CreateKey(%v, %v) err = %v, want nil", tc.p, tc.idRequirement, err)
			}
			if err := tc.tryCast(key); err != nil {
				t.Errorf("tc.tryCast(key) = %v, want nil", err)
			}
		})
	}
}

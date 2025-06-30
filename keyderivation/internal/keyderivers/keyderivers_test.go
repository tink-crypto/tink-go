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

package keyderivers_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyderivation/internal/keyderivers"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

func TestDeriveKey(t *testing.T) {
	aes128GCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	aes128GCMKey, err := aesgcm.NewKey(secretdata.NewBytesFromData([]byte("0123456789012345"), insecuresecretdataaccess.Token{}), 123, aes128GCMParams)
	if err != nil {
		t.Fatalf("aesgcm.NewKey() err = %v, want nil", err)
	}

	aes128GCMNoPrefixParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	aes128GCMNoPrefixKey, err := aesgcm.NewKey(secretdata.NewBytesFromData([]byte("0123456789012345"), insecuresecretdataaccess.Token{}), 0, aes128GCMNoPrefixParams)
	if err != nil {
		t.Fatalf("aesgcm.NewKey() err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name          string
		params        key.Parameters
		idRequirement uint32
		randomBytes   []byte
		wantKey       key.Key
	}{
		{
			name:          "AES128GCM",
			params:        aes128GCMParams,
			idRequirement: 123,
			randomBytes:   []byte("0123456789012345"),
			wantKey:       aes128GCMKey,
		},
		{
			name:          "AES128GCM_longer_key_bytes",
			params:        aes128GCMParams,
			idRequirement: 123,
			randomBytes:   []byte("0123456789012345ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
			wantKey:       aes128GCMKey,
		},
		{
			name:          "AES128GCMNoPrefix",
			params:        aes128GCMNoPrefixParams,
			idRequirement: 0,
			randomBytes:   []byte("0123456789012345"),
			wantKey:       aes128GCMNoPrefixKey,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			derivedKey, err := keyderivers.DeriveKey(tc.params, tc.idRequirement, bytes.NewBuffer(tc.randomBytes))
			if err != nil {
				t.Fatalf("keyderivation.DeriveKey() err = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.wantKey, derivedKey); diff != "" {
				t.Errorf("keyderivation.DeriveKey() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDeriveKey_Failures(t *testing.T) {
	aes128GCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}

	aes128GCMNoPrefixParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name          string
		params        key.Parameters
		idRequirement uint32
		keyBytes      []byte
	}{
		{
			name:          "invalid parameters type",
			params:        &stubParams{},
			idRequirement: 123,
			keyBytes:      []byte("0123456789012345"),
		},
		{
			name:          "insufficient random bytes",
			params:        aes128GCMParams,
			idRequirement: 123,
			keyBytes:      []byte("01234"),
		},
		{
			name:          "invalid ID requirement",
			params:        aes128GCMNoPrefixParams,
			idRequirement: 123,
			keyBytes:      []byte("0123456789012345"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := keyderivers.DeriveKey(&stubParams{}, 123, bytes.NewBuffer(tc.keyBytes)); err == nil {
				t.Fatal("keyderivers.DeriveKey() err = nil, want error")
			}
		})
	}
}

type stubParams struct {
	hasIDRequirement bool
}

var _ key.Parameters = (*stubParams)(nil)

func (p *stubParams) HasIDRequirement() bool { return p.hasIDRequirement }

func (p *stubParams) Equal(other key.Parameters) bool {
	_, ok := other.(*stubParams)
	return ok
}

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

package aescmac_test

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/mac/aescmac"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

var (
	aes128Key = secretdata.NewBytesFromData([]byte("0123456789012345"), insecuresecretdataaccess.Token{})
	aes256Key = secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{})
)

func TestNewKeyFailsIfKeySizeIsInvalid(t *testing.T) {
	params, err := aescmac.NewParameters(aescmac.ParametersOpts{
		KeySizeInBytes: 16,
		TagSizeInBytes: 16,
		Variant:        aescmac.VariantTink,
	})
	if err != nil {
		t.Fatalf("NewParameters(16, 16, VariantTink) err = %v, want nil", err)
	}
	_, err = aescmac.NewKey(secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{}), params, 0x01020304)
	if err == nil {
		t.Errorf("NewKey(secretdata.NewBytesFromData([]byte(\"01234567890123456789012345678901\"), insecuresecretdataaccess.Token{}), params, 0x01020304) err = nil, want error")
	}
}

func TestNewKeyFailsWithInvalidIDRequirement(t *testing.T) {
	params, err := aescmac.NewParameters(aescmac.ParametersOpts{
		KeySizeInBytes: 16,
		TagSizeInBytes: 16,
		Variant:        aescmac.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("NewParameters(16, 16, VariantTink) err = %v, want nil", err)
	}
	if _, err = aescmac.NewKey(secretdata.NewBytesFromData([]byte("0123456789012345"), insecuresecretdataaccess.Token{}), params, 0x01020304); err == nil {
		t.Errorf("NewKey(secretdata.NewBytesFromData([]byte(\"0123456789012345\"), insecuresecretdataaccess.Token{}), params, 0x01020304) err = nil, want error")
	}
}

func TestNewKey(t *testing.T) {
	for _, tc := range []struct {
		name             string
		key              secretdata.Bytes
		params           *aescmac.Parameters
		idRequirement    uint32
		wantOutputPrefix []byte
	}{
		{
			name:             "AES128 Tink",
			key:              aes128Key,
			params:           mustCreateParameters(t, aescmac.ParametersOpts{KeySizeInBytes: 16, TagSizeInBytes: 16, Variant: aescmac.VariantTink}),
			idRequirement:    0x01020304,
			wantOutputPrefix: slices.Concat([]byte{cryptofmt.TinkStartByte}, []byte{0x01, 0x02, 0x03, 0x04}),
		},
		{
			name:             "AES256 Tink",
			key:              aes256Key,
			params:           mustCreateParameters(t, aescmac.ParametersOpts{KeySizeInBytes: 32, TagSizeInBytes: 16, Variant: aescmac.VariantTink}),
			idRequirement:    0x01020304,
			wantOutputPrefix: slices.Concat([]byte{cryptofmt.TinkStartByte}, []byte{0x01, 0x02, 0x03, 0x04}),
		},
		{
			name:             "AES128 Crunchy",
			key:              aes128Key,
			params:           mustCreateParameters(t, aescmac.ParametersOpts{KeySizeInBytes: 16, TagSizeInBytes: 16, Variant: aescmac.VariantCrunchy}),
			idRequirement:    0x01020304,
			wantOutputPrefix: slices.Concat([]byte{cryptofmt.LegacyStartByte}, []byte{0x01, 0x02, 0x03, 0x04}),
		},
		{
			name:             "AES256 Crunchy",
			key:              aes256Key,
			params:           mustCreateParameters(t, aescmac.ParametersOpts{KeySizeInBytes: 32, TagSizeInBytes: 16, Variant: aescmac.VariantCrunchy}),
			idRequirement:    0x01020304,
			wantOutputPrefix: slices.Concat([]byte{cryptofmt.LegacyStartByte}, []byte{0x01, 0x02, 0x03, 0x04}),
		},
		{
			name:             "AES128 Raw",
			key:              aes128Key,
			params:           mustCreateParameters(t, aescmac.ParametersOpts{KeySizeInBytes: 16, TagSizeInBytes: 16, Variant: aescmac.VariantNoPrefix}),
			idRequirement:    0,
			wantOutputPrefix: nil,
		},
		{
			name:             "AES256 Raw",
			key:              aes256Key,
			params:           mustCreateParameters(t, aescmac.ParametersOpts{KeySizeInBytes: 32, TagSizeInBytes: 16, Variant: aescmac.VariantNoPrefix}),
			idRequirement:    0,
			wantOutputPrefix: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := aescmac.NewKey(tc.key, tc.params, tc.idRequirement)
			if err != nil {
				t.Errorf("NewKey(%v, %v, %d) err = %v, want nil", tc.key, tc.params, tc.idRequirement, err)
			}
			if !key.Parameters().Equal(tc.params) {
				t.Errorf("key.Parameters() = %v, want %v", key.Parameters(), tc.params)
			}
			if !key.KeyBytes().Equal(tc.key) {
				t.Errorf("key.KeyBytes() = %v, want %v", key.KeyBytes(), tc.key)
			}
			id, required := key.IDRequirement()
			if got, want := id, tc.idRequirement; got != tc.idRequirement {
				t.Errorf("key.IDRequirement() = %v, _, want %v", got, want)
			}
			if got, want := required, tc.params.HasIDRequirement(); got != want {
				t.Errorf("key.IDRequirement() = _, %v, want %v", got, want)
			}
			if diff := cmp.Diff(tc.wantOutputPrefix, key.OutputPrefix()); diff != "" {
				t.Errorf("key.OutputPrefix() diff (-want +got):\n%s", diff)
			}

			// Test equality.
			if !key.Equal(key) {
				t.Errorf("key.Equal(key) = false, want true")
			}
			otherKey, err := aescmac.NewKey(tc.key, tc.params, tc.idRequirement)
			if err != nil {
				t.Fatalf("NewKey(%v, %v, %d) err = %v, want nil", tc.key, tc.params, tc.idRequirement, err)
			}
			if !key.Equal(otherKey) {
				t.Errorf("key.Equal(otherKey) = false, want true")
			}
		})
	}
}

func mustCreateKey(t *testing.T, key secretdata.Bytes, params *aescmac.Parameters, idRequirement uint32) *aescmac.Key {
	t.Helper()
	cmacKey, err := aescmac.NewKey(key, params, idRequirement)
	if err != nil {
		t.Fatalf("NewKey(%v, %v, %d) err = %v, want nil", key, params, idRequirement, err)
	}
	return cmacKey
}

type stubKey struct{}

var _ key.Key = (*stubKey)(nil)

func (k *stubKey) Parameters() key.Parameters    { return nil }
func (k *stubKey) Equal(other key.Key) bool      { return true }
func (k *stubKey) IDRequirement() (uint32, bool) { return 123, true }

func TestKeyEqualFalseIfDifferent(t *testing.T) {
	for _, tc := range []struct {
		name string
		key1 *aescmac.Key
		key2 key.Key
	}{
		{
			name: "Different Key type",
			key1: mustCreateKey(t, aes128Key, mustCreateParameters(t, aescmac.ParametersOpts{KeySizeInBytes: 16, TagSizeInBytes: 16, Variant: aescmac.VariantTink}), 0x01020304),
			key2: &stubKey{},
		},
		{
			name: "Different Key Bytes",
			key1: mustCreateKey(t, aes128Key, mustCreateParameters(t, aescmac.ParametersOpts{KeySizeInBytes: 16, TagSizeInBytes: 16, Variant: aescmac.VariantTink}), 0x01020304),
			key2: mustCreateKey(t, secretdata.NewBytesFromData([]byte("0000000000000000"), insecuresecretdataaccess.Token{}), mustCreateParameters(t, aescmac.ParametersOpts{KeySizeInBytes: 16, TagSizeInBytes: 16, Variant: aescmac.VariantTink}), 0x01020304),
		},
		{
			name: "Different IDRequirement",
			key1: mustCreateKey(t, aes128Key, mustCreateParameters(t, aescmac.ParametersOpts{KeySizeInBytes: 16, TagSizeInBytes: 16, Variant: aescmac.VariantTink}), 0x01020304),
			key2: mustCreateKey(t, aes128Key, mustCreateParameters(t, aescmac.ParametersOpts{KeySizeInBytes: 16, TagSizeInBytes: 16, Variant: aescmac.VariantTink}), 0x05060708),
		},
		{
			name: "Different Parameters",
			key1: mustCreateKey(t, aes256Key, mustCreateParameters(t, aescmac.ParametersOpts{KeySizeInBytes: 32, TagSizeInBytes: 16, Variant: aescmac.VariantTink}), 0x01020304),
			key2: mustCreateKey(t, aes256Key, mustCreateParameters(t, aescmac.ParametersOpts{KeySizeInBytes: 32, TagSizeInBytes: 16, Variant: aescmac.VariantCrunchy}), 0x01020304),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.key1.Equal(tc.key2) {
				t.Errorf("key1.Equal(key2) = true, want false")
			}
		})
	}
}

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

package hmac_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/mac/hmac"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

var (
	hmac128Key = secretdata.NewBytesFromData([]byte("0123456789012345"), insecuresecretdataaccess.Token{})
	hmac256Key = secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{})
)

func TestNewKeyFailsIfKeySizeIsInvalid(t *testing.T) {
	opts := hmac.ParametersOpts{
		KeySizeInBytes: 16,
		TagSizeInBytes: 16,
		HashType:       hmac.SHA256,
		Variant:        hmac.VariantTink,
	}
	params, err := hmac.NewParameters(opts)
	if err != nil {
		t.Fatalf("NewParameters(%v) err = %v, want nil", opts, err)
	}
	keyBytes := secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{})
	_, err = hmac.NewKey(keyBytes, params, 0x01020304)
	if err == nil {
		t.Errorf("NewKey(%x, params, 0x01020304) err = nil, want error", keyBytes)
	}
}

func TestNewKeyFailsWithInvalidIDRequirement(t *testing.T) {
	opts := hmac.ParametersOpts{
		KeySizeInBytes: 16,
		TagSizeInBytes: 16,
		HashType:       hmac.SHA256,
		Variant:        hmac.VariantNoPrefix,
	}
	params, err := hmac.NewParameters(opts)
	if err != nil {
		t.Fatalf("NewParameters(%v) err = %v, want nil", opts, err)
	}
	keyBytes := secretdata.NewBytesFromData([]byte("0123456789012345"), insecuresecretdataaccess.Token{})
	if _, err = hmac.NewKey(keyBytes, params, 0x01020304); err == nil {
		t.Errorf("NewKey(%x, params, 0x01020304) err = nil, want error", keyBytes)
	}
}

func TestNewKey(t *testing.T) {
	for _, tc := range []struct {
		name             string
		key              secretdata.Bytes
		params           *hmac.Parameters
		idRequirement    uint32
		wantOutputPrefix []byte
	}{
		{
			name: fmt.Sprintf("keySize=%v,variant=%v", 16, hmac.VariantTink),
			key:  hmac128Key,
			params: mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantTink,
			}),
			idRequirement:    0x01020304,
			wantOutputPrefix: slices.Concat([]byte{cryptofmt.TinkStartByte}, []byte{0x01, 0x02, 0x03, 0x04}),
		},
		{
			name: fmt.Sprintf("keySize=%v,variant=%v", 32, hmac.VariantTink),
			key:  hmac256Key,
			params: mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 32,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantTink,
			}),
			idRequirement:    0x01020304,
			wantOutputPrefix: slices.Concat([]byte{cryptofmt.TinkStartByte}, []byte{0x01, 0x02, 0x03, 0x04}),
		},
		{
			name: fmt.Sprintf("keySize=%v,variant=%v", 16, hmac.VariantCrunchy),
			key:  hmac128Key,
			params: mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantCrunchy,
			}),
			idRequirement:    0x01020304,
			wantOutputPrefix: slices.Concat([]byte{cryptofmt.LegacyStartByte}, []byte{0x01, 0x02, 0x03, 0x04}),
		},
		{
			name: fmt.Sprintf("keySize=%v,variant=%v", 32, hmac.VariantCrunchy),
			key:  hmac256Key,
			params: mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 32,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantCrunchy,
			}),
			idRequirement:    0x01020304,
			wantOutputPrefix: slices.Concat([]byte{cryptofmt.LegacyStartByte}, []byte{0x01, 0x02, 0x03, 0x04}),
		},
		{
			name: fmt.Sprintf("keySize=%v,variant=%v", 16, hmac.VariantNoPrefix),
			key:  hmac128Key,
			params: mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantNoPrefix,
			}),
			idRequirement:    0,
			wantOutputPrefix: nil,
		},
		{
			name: fmt.Sprintf("keySize=%v,variant=%v", 32, hmac.VariantNoPrefix),
			key:  hmac256Key,
			params: mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 32,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantNoPrefix,
			}),
			idRequirement:    0,
			wantOutputPrefix: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := hmac.NewKey(tc.key, tc.params, tc.idRequirement)
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
			otherKey, err := hmac.NewKey(tc.key, tc.params, tc.idRequirement)
			if err != nil {
				t.Fatalf("NewKey(%v, %v, %d) err = %v, want nil", tc.key, tc.params, tc.idRequirement, err)
			}
			if !key.Equal(otherKey) {
				t.Errorf("key.Equal(otherKey) = false, want true")
			}
		})
	}
}

func mustCreateKey(t *testing.T, key secretdata.Bytes, params *hmac.Parameters, idRequirement uint32) *hmac.Key {
	t.Helper()
	cmacKey, err := hmac.NewKey(key, params, idRequirement)
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
		key1 *hmac.Key
		key2 key.Key
	}{
		{
			name: "Different key type",
			key1: mustCreateKey(t, hmac128Key, mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantTink,
			}), 0x01020304),
			key2: &stubKey{},
		},
		{
			name: "Different Key Bytes",
			key1: mustCreateKey(t, hmac128Key, mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantTink,
			}), 0x01020304),
			key2: mustCreateKey(t, secretdata.NewBytesFromData([]byte("0000000000000000"), insecuresecretdataaccess.Token{}), mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantTink,
			}), 0x01020304),
		},
		{
			name: "Different IDRequirement",
			key1: mustCreateKey(t, hmac128Key, mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantTink,
			}), 0x01020304),
			key2: mustCreateKey(t, hmac128Key, mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantTink,
			}), 0x05060708),
		},
		{
			name: "Different Parameters",
			key1: mustCreateKey(t, hmac256Key, mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 32,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantTink,
			}), 0x01020304),
			key2: mustCreateKey(t, hmac256Key, mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 32,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantCrunchy,
			}), 0x01020304),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.key1.Equal(tc.key2) {
				t.Errorf("key1.Equal(key2) = true, want false")
			}
		})
	}
}

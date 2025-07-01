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

package aesctrhmac_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesctrhmac"
)

func TestNewKey_Fails(t *testing.T) {
	params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		KeySizeInBytes:        32,
		DerivedKeySizeInBytes: 32,
		HkdfHashType:          aesctrhmac.SHA256,
		HmacHashType:          aesctrhmac.SHA256,
		HmacTagSizeInBytes:    32,
		SegmentSizeInBytes:    4096,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name       string
		keyBytes   secretdata.Bytes
		parameters *aesctrhmac.Parameters
	}{
		{
			name:       "nil parameters",
			keyBytes:   secretdata.NewBytesFromData([]byte("0123456789abcdef0123456789abcdef"), insecuresecretdataaccess.Token{}),
			parameters: nil,
		},
		{
			name:       "invalid key size",
			keyBytes:   secretdata.NewBytesFromData([]byte("0123456789abcdef"), insecuresecretdataaccess.Token{}),
			parameters: params,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := aesctrhmac.NewKey(tc.parameters, tc.keyBytes); err == nil {
				t.Errorf("aesctrhmac.NewKey() err = nil, want error")
			}
		})
	}
}

func TestNewKey_Success(t *testing.T) {
	keyBytes := []byte("0123456789abcdef0123456789abcdef")
	for _, tc := range getParametersTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			params, err := aesctrhmac.NewParameters(tc.parameterOpts)
			if err != nil {
				t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
			}
			secretKeyBytes := secretdata.NewBytesFromData(keyBytes[:tc.parameterOpts.KeySizeInBytes], insecuresecretdataaccess.Token{})
			k, err := aesctrhmac.NewKey(params, secretKeyBytes)
			if err != nil {
				t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
			}
			if diff := cmp.Diff(params, k.Parameters()); diff != "" {
				t.Errorf("k.Parameters() returned unexpected diff (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(secretKeyBytes, k.KeyBytes()); diff != "" {
				t.Errorf("k.KeyBytes() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

type stubKey struct{}

var _ key.Key = (*stubKey)(nil)

func (k *stubKey) Parameters() key.Parameters    { return nil }
func (k *stubKey) Equal(other key.Key) bool      { return true }
func (k *stubKey) IDRequirement() (uint32, bool) { return 0, false }

func TestKeyEqual_FalseIfDifferent(t *testing.T) {
	params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		KeySizeInBytes:        32,
		DerivedKeySizeInBytes: 32,
		HkdfHashType:          aesctrhmac.SHA256,
		HmacHashType:          aesctrhmac.SHA256,
		HmacTagSizeInBytes:    32,
		SegmentSizeInBytes:    4096,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
	}
	keyBytes := secretdata.NewBytesFromData([]byte("0123456789abcdef0123456789abcdef"), insecuresecretdataaccess.Token{})
	k, err := aesctrhmac.NewKey(params, keyBytes)
	if err != nil {
		t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name string
		key  key.Key
	}{
		{
			name: "different_key_size",
			key: func() *aesctrhmac.Key {
				params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
					KeySizeInBytes:        16,
					DerivedKeySizeInBytes: 16,
					HkdfHashType:          aesctrhmac.SHA256,
					HmacHashType:          aesctrhmac.SHA256,
					HmacTagSizeInBytes:    32,
					SegmentSizeInBytes:    4096,
				},
				)
				if err != nil {
					t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
				}
				keyBytes := secretdata.NewBytesFromData([]byte("0123456789abcdef"), insecuresecretdataaccess.Token{})
				k, err := aesctrhmac.NewKey(params, keyBytes)
				if err != nil {
					t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
				}
				return k
			}(),
		},
		{
			name: "different_key_bytes",
			key: func() *aesctrhmac.Key {
				params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
					KeySizeInBytes:        32,
					DerivedKeySizeInBytes: 32,
					HkdfHashType:          aesctrhmac.SHA256,
					HmacHashType:          aesctrhmac.SHA256,
					HmacTagSizeInBytes:    32,
					SegmentSizeInBytes:    4096,
				},
				)
				if err != nil {
					t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
				}
				keyBytes := secretdata.NewBytesFromData([]byte("fedcba9876543210fedcba9876543210"), insecuresecretdataaccess.Token{})
				k, err := aesctrhmac.NewKey(params, keyBytes)
				if err != nil {
					t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
				}
				return k
			}(),
		},
		{
			name: "different_key_type",
			key:  &stubKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.key, k); diff == "" {
				t.Errorf("k.Equal(k2) = true, want false, diff: %v", diff)
			}
		})
	}
}

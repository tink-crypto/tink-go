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

package aesgcmhkdf_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesgcmhkdf"
)

var (
	keyBytes16 = secretdata.NewBytesFromData([]byte("1111111111111111"), insecuresecretdataaccess.Token{})
	keyBytes32 = secretdata.NewBytesFromData([]byte("11111111111111111111111111111111"), insecuresecretdataaccess.Token{})
)

func TestNewKey_Fails(t *testing.T) {
	params, err := aesgcmhkdf.NewParameters(aesgcmhkdf.ParametersOpts{
		KeySizeInBytes:        32,
		DerivedKeySizeInBytes: 32,
		SegmentSizeInBytes:    1024,
		HKDFHashType:          aesgcmhkdf.SHA256,
	})
	if err != nil {
		t.Fatalf("aesgcmhkdf.NewParameters() err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name     string
		keyBytes secretdata.Bytes
		params   *aesgcmhkdf.Parameters
	}{
		{
			name:     "nil parameters",
			keyBytes: keyBytes16,
			params:   nil,
		},
		{
			name:     "invalid parameters",
			keyBytes: keyBytes16,
			params:   &aesgcmhkdf.Parameters{},
		},
		{
			name:     "invalid parameters and empty key",
			keyBytes: secretdata.NewBytesFromData([]byte{}, insecuresecretdataaccess.Token{}),
			params:   &aesgcmhkdf.Parameters{},
		},
		{
			name:     "invalid key size",
			keyBytes: keyBytes16,
			params:   params,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := aesgcmhkdf.NewKey(tc.params, tc.keyBytes); err == nil {
				t.Errorf("aesgcmhkdf.NewKey() err = nil, want error")
			}
		})
	}
}

type TestKey struct {
	name         string
	key          secretdata.Bytes
	parameterOps aesgcmhkdf.ParametersOpts
}

func TestNewKey(t *testing.T) {
	for _, test := range []TestKey{
		{
			name: "AES128-GCM-HKDF-SHA256",
			key:  keyBytes16,
			parameterOps: aesgcmhkdf.ParametersOpts{
				KeySizeInBytes:        16,
				DerivedKeySizeInBytes: 16,
				SegmentSizeInBytes:    1024,
				HKDFHashType:          aesgcmhkdf.SHA256,
			},
		},
		{
			name: "AES256-GCM-HKDF-SHA256",
			key:  keyBytes32,
			parameterOps: aesgcmhkdf.ParametersOpts{
				KeySizeInBytes:        32,
				DerivedKeySizeInBytes: 32,
				SegmentSizeInBytes:    1024,
				HKDFHashType:          aesgcmhkdf.SHA256,
			},
		},
		{
			name: "AES256-GCM-HKDF-SHA512",
			key:  keyBytes32,
			parameterOps: aesgcmhkdf.ParametersOpts{
				KeySizeInBytes:        32,
				DerivedKeySizeInBytes: 32,
				SegmentSizeInBytes:    1024,
				HKDFHashType:          aesgcmhkdf.SHA512,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := aesgcmhkdf.NewParameters(test.parameterOps)
			if err != nil {
				t.Fatalf("aesgcmhkdf.NewParameters(%v) err = %v, want nil", test.parameterOps, err)
			}
			// Create two keys with the same parameters and key bytes.
			key1, err := aesgcmhkdf.NewKey(params, test.key)
			if err != nil {
				t.Fatalf("aesgcmhkdf.NewKey() err = %v, want nil", err)
			}
			if !key1.Parameters().Equal(params) {
				t.Errorf("key1.Parameters() = %v, want %v", key1.Parameters(), params)
			}
			key1Bytes := key1.KeyBytes()
			if !key1Bytes.Equal(test.key) {
				t.Errorf("key1Bytes.Equal(test.key) = false, want true")
			}
			keyID1, _ := key1.IDRequirement()
			if keyID1 != 0 {
				t.Errorf("keyID1 = %v, want 0", keyID1)
			}
			key2, err := aesgcmhkdf.NewKey(params, test.key)
			if err != nil {
				t.Fatalf("aesgcmhkdf.NewKey() err = %v, want nil", err)
			}
			// Test Equal.
			if diff := cmp.Diff(key1, key2); diff != "" {
				t.Errorf("key1 diff (-want +got):\n%s", diff)
			}
		})
	}
}

type stubKey struct{}

var _ key.Key = (*stubKey)(nil)

func (k *stubKey) Parameters() key.Parameters    { return nil }
func (k *stubKey) Equal(other key.Key) bool      { return true }
func (k *stubKey) IDRequirement() (uint32, bool) { return 0, false }

func TestKeyEqual_FalseIfDifferentType(t *testing.T) {
	params, err := aesgcmhkdf.NewParameters(aesgcmhkdf.ParametersOpts{
		KeySizeInBytes:        32,
		DerivedKeySizeInBytes: 32,
		SegmentSizeInBytes:    1024,
		HKDFHashType:          aesgcmhkdf.SHA256,
	})
	if err != nil {
		t.Fatalf("aesgcmhkdf.NewParameters() err = %v, want nil", err)
	}
	keyBytes := secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{})
	key, err := aesgcmhkdf.NewKey(params, keyBytes)
	if err != nil {
		t.Fatalf("aesgcmhkdf.NewKey() err = %v, want nil", err)
	}
	if key.Equal(&stubKey{}) {
		t.Errorf("key.Equal(&stubKey{}) = true, want false")
	}
}

func TestKeyEqual_FalseIfDifferent(t *testing.T) {
	key2Bytes16 := secretdata.NewBytesFromData([]byte("3333333333333333"), insecuresecretdataaccess.Token{})
	for _, test := range []struct {
		name   string
		first  TestKey
		second TestKey
	}{
		{
			name: "different key size",
			first: TestKey{
				key: keyBytes16,
				parameterOps: aesgcmhkdf.ParametersOpts{
					KeySizeInBytes:        16,
					DerivedKeySizeInBytes: 16,
					SegmentSizeInBytes:    1024,
					HKDFHashType:          aesgcmhkdf.SHA256,
				},
			},
			second: TestKey{
				key: keyBytes32,
				parameterOps: aesgcmhkdf.ParametersOpts{
					KeySizeInBytes:        32,
					DerivedKeySizeInBytes: 16,
					SegmentSizeInBytes:    1024,
					HKDFHashType:          aesgcmhkdf.SHA256,
				},
			},
		},
		{
			name: "different derived key size",
			first: TestKey{
				key: keyBytes32,
				parameterOps: aesgcmhkdf.ParametersOpts{
					KeySizeInBytes:        32,
					DerivedKeySizeInBytes: 32,
					SegmentSizeInBytes:    1024,
					HKDFHashType:          aesgcmhkdf.SHA256,
				},
			},
			second: TestKey{
				key: keyBytes32,
				parameterOps: aesgcmhkdf.ParametersOpts{
					KeySizeInBytes:        32,
					DerivedKeySizeInBytes: 16,
					SegmentSizeInBytes:    1024,
					HKDFHashType:          aesgcmhkdf.SHA256,
				},
			},
		},
		{
			name: "different key bytes",
			first: TestKey{
				key: keyBytes16,
				parameterOps: aesgcmhkdf.ParametersOpts{
					KeySizeInBytes:        16,
					DerivedKeySizeInBytes: 16,
					SegmentSizeInBytes:    1024,
					HKDFHashType:          aesgcmhkdf.SHA256,
				},
			},
			second: TestKey{
				key: key2Bytes16,
				parameterOps: aesgcmhkdf.ParametersOpts{
					KeySizeInBytes:        16,
					DerivedKeySizeInBytes: 16,
					SegmentSizeInBytes:    1024,
					HKDFHashType:          aesgcmhkdf.SHA256,
				},
			},
		},
		{
			name: "different hash function",
			first: TestKey{
				key: keyBytes16,
				parameterOps: aesgcmhkdf.ParametersOpts{
					KeySizeInBytes:        16,
					DerivedKeySizeInBytes: 16,
					SegmentSizeInBytes:    1024,
					HKDFHashType:          aesgcmhkdf.SHA256,
				},
			},
			second: TestKey{
				key: keyBytes16,
				parameterOps: aesgcmhkdf.ParametersOpts{
					KeySizeInBytes:        16,
					DerivedKeySizeInBytes: 16,
					SegmentSizeInBytes:    1024,
					HKDFHashType:          aesgcmhkdf.SHA512,
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			firstParams, err := aesgcmhkdf.NewParameters(test.first.parameterOps)
			if err != nil {
				t.Fatalf("aesgcmhkdf.NewParameters() err = %v, want nil", err)
			}
			firstKey, err := aesgcmhkdf.NewKey(firstParams, test.first.key)
			if err != nil {
				t.Fatalf("aesgcmhkdf.NewKey() err = %v, want nil", err)
			}
			secondParams, err := aesgcmhkdf.NewParameters(test.second.parameterOps)
			if err != nil {
				t.Fatalf("aesgcmhkdf.NewParameters() err = %v, want nil", err)
			}
			secondKey, err := aesgcmhkdf.NewKey(secondParams, test.second.key)
			if err != nil {
				t.Fatalf("aesgcmhkdf.NewKey() err = %v, want nil", err)
			}
			if firstKey.Equal(secondKey) {
				t.Errorf("firstKey.Equal(secondKey) = true, want false")
			}
			if cmp.Equal(firstKey, secondKey) {
				t.Errorf("firstKey.Equal(secondKey) = true, want false")
			}
		})
	}
}

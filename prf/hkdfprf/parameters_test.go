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

package hkdfprf_test

import (
	"bytes"
	"testing"

	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
)

func TestParametersValid(t *testing.T) {
	for _, keySize := range []int{16, 32} {
		for _, hashType := range []hkdfprf.HashType{hkdfprf.SHA256, hkdfprf.SHA512, hkdfprf.SHA1, hkdfprf.SHA384} {
			for _, salt := range [][]byte{nil, []byte("another salt")} {
				params, err := hkdfprf.NewParameters(keySize, hashType, salt)
				if err != nil {
					t.Errorf("hkdfprf.NewParameters(%d, %v, %v) failed: %v", keySize, hashType, salt, err)
				}
				if params.KeySizeInBytes() != keySize {
					t.Errorf("params.KeySizeInBytes() = %d, want %d", params.KeySizeInBytes(), keySize)
				}
				if params.HashType() != hashType {
					t.Errorf("params.HashType() = %v, want %v", params.HashType(), hashType)
				}
				if (salt == nil && params.Salt() != nil) || (salt != nil && !bytes.Equal(params.Salt(), salt)) {
					t.Errorf("params.Salt() = %v, want %v", params.Salt(), salt)
				}

				params2, err := hkdfprf.NewParameters(keySize, hashType, salt)
				if err != nil {
					t.Errorf("hkdfprf.NewParameters(%d, %v, %v) failed: %v", keySize, hashType, salt, err)
				}
				if !params.Equal(params2) {
					t.Errorf("Equal() returned false, expected true")
				}
				if !params2.Equal(params) {
					t.Errorf("Equal() returned false, expected true")
				}
			}
		}
	}
}

func TestParametersInvalidValues(t *testing.T) {
	for _, tc := range []struct {
		name      string
		keySize   int
		hashType  hkdfprf.HashType
		salt      []byte
		wantError string
	}{
		{
			name:      "key size too small",
			keySize:   15,
			hashType:  hkdfprf.SHA256,
			salt:      []byte("salt"),
			wantError: "keySizeInBytes must be >= 16, got 15",
		},
		{
			name:      "unknown hash type",
			keySize:   16,
			hashType:  hkdfprf.UnknownHashType,
			salt:      []byte("salt"),
			wantError: "hashType must be specified",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := hkdfprf.NewParameters(tc.keySize, tc.hashType, tc.salt); err == nil {
				t.Errorf("hkdfprf.NewParameters(%d, %v, %v) succeeded, expected error with message %q", tc.keySize, tc.hashType, tc.salt, tc.wantError)
			}
		})
	}
}

func mustCreateParameters(t *testing.T, keySize int, hashType hkdfprf.HashType, salt []byte) *hkdfprf.Parameters {
	t.Helper()
	params, err := hkdfprf.NewParameters(keySize, hashType, salt)
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters(%d, %v, %v) failed: %v", keySize, hashType, salt, err)
	}
	return params
}

func TestParametersNotEquals(t *testing.T) {

	for _, tc := range []struct {
		name    string
		params1 *hkdfprf.Parameters
		params2 *hkdfprf.Parameters
	}{
		{
			name:    "different key size",
			params1: mustCreateParameters(t, 32, hkdfprf.SHA256, []byte("salt")),
			params2: mustCreateParameters(t, 16, hkdfprf.SHA256, []byte("salt")),
		},
		{
			name:    "different hash type",
			params1: mustCreateParameters(t, 32, hkdfprf.SHA256, []byte("salt")),
			params2: mustCreateParameters(t, 32, hkdfprf.SHA512, []byte("salt")),
		},
		{
			name:    "different salt",
			params1: mustCreateParameters(t, 32, hkdfprf.SHA256, []byte("salt")),
			params2: mustCreateParameters(t, 32, hkdfprf.SHA256, nil),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.params1.Equal(tc.params2) {
				t.Errorf("Equal() returned true, expected false")
			}
		})
	}

}

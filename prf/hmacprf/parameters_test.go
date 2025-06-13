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

package hmacprf_test

import (
	"testing"

	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/prf/hmacprf"
)

func TestParametersValid(t *testing.T) {
	for _, keySize := range []int{16, 32} {
		for _, hashType := range []hmacprf.HashType{hmacprf.SHA256, hmacprf.SHA512, hmacprf.SHA1, hmacprf.SHA384} {
			params, err := hmacprf.NewParameters(keySize, hashType)
			if err != nil {
				t.Errorf("hmacprf.NewParameters(%d, %v) failed: %v", keySize, hashType, err)
			}
			if params.KeySizeInBytes() != keySize {
				t.Errorf("params.KeySizeInBytes() = %d, want %d", params.KeySizeInBytes(), keySize)
			}
			if params.HashType() != hashType {
				t.Errorf("params.HashType() = %v, want %v", params.HashType(), hashType)
			}

			params2, err := hmacprf.NewParameters(keySize, hashType)
			if err != nil {
				t.Errorf("hmacprf.NewParameters(%d, %v) failed: %v", keySize, hashType, err)
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

func TestParametersInvalidValues(t *testing.T) {
	for _, tc := range []struct {
		name      string
		keySize   int
		hashType  hmacprf.HashType
		wantError string
	}{
		{
			name:      "key size too small",
			keySize:   15,
			hashType:  hmacprf.SHA256,
			wantError: "keySizeInBytes must be >= 16, got 15",
		},
		{
			name:      "unknown hash type",
			keySize:   16,
			hashType:  hmacprf.UnknownHashType,
			wantError: "hashType must be specified",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := hmacprf.NewParameters(tc.keySize, tc.hashType); err == nil {
				t.Errorf("hmacprf.NewParameters(%d, %v) succeeded, expected error with message %q", tc.keySize, tc.hashType, tc.wantError)
			}
		})
	}
}

func mustCreateParameters(t *testing.T, keySize int, hashType hmacprf.HashType) *hmacprf.Parameters {
	t.Helper()
	params, err := hmacprf.NewParameters(keySize, hashType)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters(%d, %v) failed: %v", keySize, hashType, err)
	}
	return params
}

type stubParameters struct{}

var _ key.Parameters = (*stubParameters)(nil)

func (p *stubParameters) Equal(other key.Parameters) bool { return false }

func (p *stubParameters) HasIDRequirement() bool { return false }

func TestParametersNotEquals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		params1 *hmacprf.Parameters
		params2 key.Parameters
	}{
		{
			name:    "different key size",
			params1: mustCreateParameters(t, 32, hmacprf.SHA256),
			params2: mustCreateParameters(t, 16, hmacprf.SHA256),
		},
		{
			name:    "different hash type",
			params1: mustCreateParameters(t, 32, hmacprf.SHA256),
			params2: mustCreateParameters(t, 32, hmacprf.SHA512),
		},
		{
			name:    "different parameters type",
			params1: mustCreateParameters(t, 32, hmacprf.SHA256),
			params2: &stubParameters{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.params1.Equal(tc.params2) {
				t.Errorf("Equal() returned true, expected false")
			}
		})
	}

}

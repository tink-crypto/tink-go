// Copyright 2021 Google LLC
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

package ecies_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/aesctrhmac"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/daead/aessiv"
	"github.com/tink-crypto/tink-go/v2/hybrid/internal/ecies"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type testCase struct {
	name    string
	params  key.Parameters
	keySize uint32
}

func newAESGCMParameters(keySizeInBytes uint32) *aesgcm.Parameters {
	params, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: int(keySizeInBytes),
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		panic(fmt.Sprintf("aesgcm.NewParameters() err = %v, want nil", err))
	}
	return params
}

func newAESCTRHMACParameters(aesKeySizeInBytes, hmacKeySizeInBytes uint32, hashType aesctrhmac.HashType) *aesctrhmac.Parameters {
	params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		AESKeySizeInBytes:  int(aesKeySizeInBytes),
		HMACKeySizeInBytes: int(hmacKeySizeInBytes),
		HashType:           hashType,
		IVSizeInBytes:      12,
		TagSizeInBytes:     16,
		Variant:            aesctrhmac.VariantNoPrefix,
	})
	if err != nil {
		panic(fmt.Sprintf("aesctrhmac.NewParameters() err = %v, want nil", err))
	}
	return params
}

func newAESSIVParameters(keySizeInBytes uint32) *aessiv.Parameters {
	params, err := aessiv.NewParameters(int(keySizeInBytes), aessiv.VariantNoPrefix)
	if err != nil {
		panic(fmt.Sprintf("aesctrhmac.NewParameters() err = %v, want nil", err))
	}
	return params
}

var (
	supportedAEADTestCases = []testCase{
		{
			name:    "AESCTRHMACSHA256",
			params:  newAESCTRHMACParameters(32, 32, aesctrhmac.SHA256),
			keySize: 64, // 32 + 32
		},
		{
			name:    "AES128CTRHMACSHA256",
			params:  newAESCTRHMACParameters(16, 32, aesctrhmac.SHA256),
			keySize: 48, // 16 + 32
		},
		{
			name:    "AES256GCM",
			params:  newAESGCMParameters(32),
			keySize: 32,
		},
		{
			name:    "AES128GCM",
			params:  newAESGCMParameters(16),
			keySize: 16,
		},
	}

	supportedDAEADTestCases = []testCase{
		{
			name:    "AESSIV",
			params:  newAESSIVParameters(64),
			keySize: 64,
		},
	}
)

func TestDEMHelper_AEADKeyTemplates(t *testing.T) {
	plaintext := random.GetRandomBytes(20)
	associatedData := random.GetRandomBytes(20)

	for _, tc := range supportedAEADTestCases {
		t.Run(tc.name, func(t *testing.T) {
			dem, err := ecies.NewDEMHelper(tc.params)
			if err != nil {
				t.Fatalf("ecies.NewDEMHelper(tc.params) err = %s, want nil", err)
			}

			sk := random.GetRandomBytes(dem.GetSymmetricKeySize())
			primitive, err := dem.GetAEADOrDAEAD(sk)
			if err != nil {
				t.Fatalf("dem.GetAEADorDAEAD(sk) err = %v, want nil", err)
			}
			a, ok := primitive.(tink.AEAD)
			if !ok {
				t.Fatalf("primitive is not of type tink.AEAD")
			}

			var ciphertext []byte
			ciphertext, err = a.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("a.Encrypt() err = %v, want nil", err)
			}

			var decrypted []byte
			decrypted, err = a.Decrypt(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("a.Decrypt() err = %v, want nil", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("a.Decrypt() = %x, want: %x", decrypted, plaintext)
			}
		})
	}
}

func TestDEMHelper_DAEADKeyTemplates(t *testing.T) {
	plaintext := random.GetRandomBytes(20)
	associatedData := random.GetRandomBytes(20)

	for _, tc := range supportedDAEADTestCases {
		t.Run(tc.name, func(t *testing.T) {
			dem, err := ecies.NewDEMHelper(tc.params)
			if err != nil {
				t.Fatalf("ecies.NewDEMHelper(tc.params) err = %s, want nil", err)
			}

			sk := random.GetRandomBytes(dem.GetSymmetricKeySize())
			primitive, err := dem.GetAEADOrDAEAD(sk)
			if err != nil {
				t.Fatalf("dem.GetAEADorDAEAD(sk) err = %v, want nil", err)
			}
			d, ok := primitive.(tink.DeterministicAEAD)
			if !ok {
				t.Fatalf("primitive is not of type tink.DeterministicAEAD")
			}

			var ciphertext []byte
			ciphertext, err = d.EncryptDeterministically(plaintext, associatedData)
			if err != nil {
				t.Fatalf("d.Encrypt() err = %v, want nil", err)
			}

			var decrypted []byte
			decrypted, err = d.DecryptDeterministically(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("d.Decrypt() err = %v, want nil", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("d.Decrypt() = %x, want: %x", decrypted, plaintext)
			}
		})
	}
}

func TestDEMHelper_KeySizes(t *testing.T) {
	var testCases []testCase
	testCases = append(testCases, supportedAEADTestCases...)
	testCases = append(testCases, supportedDAEADTestCases...)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dem, err := ecies.NewDEMHelper(tc.params)
			if err != nil {
				t.Fatalf("ecies.NewDEMHelper(tc.params): %s", err)
			}
			if dem.GetSymmetricKeySize() != tc.keySize {
				t.Errorf("dem.GetSymmetricKeySize() = %d, want: %d", dem.GetSymmetricKeySize(), tc.keySize)
			}

			shortKey := make([]byte, tc.keySize-1)
			if _, err = dem.GetAEADOrDAEAD(shortKey); err == nil {
				t.Errorf("dem.GetAEADOrDAEAD(shortKey) err = nil, want non-nil")
			}

			longKey := make([]byte, tc.keySize+1)
			if _, err = dem.GetAEADOrDAEAD(longKey); err == nil {
				t.Errorf("dem.GetAEADOrDAEAD(longKey) err = nil, want non-nil")
			}
		})
	}
}

type stubParameters struct{}

var _ key.Parameters = (*stubParameters)(nil)

func (stubParameters) HasIDRequirement() bool      { return false }
func (stubParameters) Equal(_ key.Parameters) bool { return false }

func TestNewDEMHelper_UnsupportedParameters(t *testing.T) {
	testCases := []struct {
		name   string
		params key.Parameters
	}{
		{
			name:   "unsupported_parameters",
			params: &stubParameters{},
		},
		{
			name:   "nil",
			params: nil,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ecies.NewDEMHelper(tc.params); err == nil {
				t.Errorf("ecies.NewDEMHelper() err = nil, want non-nil")
			}
		})
	}
}

// Copyright 2024 Google LLC
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
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/aead/aesctrhmac"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

var (
	aes256KeyBytes  = secretdata.NewBytesFromData([]byte("11111111111111111111111111111111"), insecuresecretdataaccess.Token{})
	hmac256KeyBytes = secretdata.NewBytesFromData([]byte("22222222222222222222222222222222"), insecuresecretdataaccess.Token{})
	aes128KeyBytes  = secretdata.NewBytesFromData([]byte("1111111111111111"), insecuresecretdataaccess.Token{})
	hmac128KeyBytes = secretdata.NewBytesFromData([]byte("2222222222222222"), insecuresecretdataaccess.Token{})
)

func TestNewKeyFails(t *testing.T) {
	params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		AESKeySizeInBytes:  32,
		HMACKeySizeInBytes: 32,
		IVSizeInBytes:      12,
		TagSizeInBytes:     16,
		HashType:           aesctrhmac.SHA256,
		Variant:            aesctrhmac.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
	}
	paramsNoPrefix, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		AESKeySizeInBytes:  32,
		HMACKeySizeInBytes: 32,
		IVSizeInBytes:      12,
		TagSizeInBytes:     16,
		HashType:           aesctrhmac.SHA256,
		Variant:            aesctrhmac.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name         string
		aesKeyBytes  secretdata.Bytes
		hmacKeyBytes secretdata.Bytes
		params       *aesctrhmac.Parameters
	}{
		{
			name:         "nil parameters",
			aesKeyBytes:  aes128KeyBytes,
			hmacKeyBytes: hmac128KeyBytes,
			params:       nil,
		},
		{
			name:         "invalid parameters",
			aesKeyBytes:  aes128KeyBytes,
			hmacKeyBytes: hmac128KeyBytes,
			params:       &aesctrhmac.Parameters{},
		},
		{
			name:         "invalid AES key size",
			aesKeyBytes:  aes128KeyBytes,
			hmacKeyBytes: hmac256KeyBytes,
			params:       params,
		},
		{
			name:         "invalid HMAC key size",
			aesKeyBytes:  aes256KeyBytes,
			hmacKeyBytes: hmac128KeyBytes,
			params:       params,
		},
		{
			name:         "invalid HMAC key size",
			aesKeyBytes:  aes256KeyBytes,
			hmacKeyBytes: hmac128KeyBytes,
			params:       params,
		},
		{
			name:         "invalid ID requirement",
			aesKeyBytes:  aes256KeyBytes,
			hmacKeyBytes: hmac256KeyBytes,
			params:       paramsNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := aesctrhmac.KeyOpts{
				AESKeyBytes:   tc.aesKeyBytes,
				HMACKeyBytes:  tc.hmacKeyBytes,
				IDRequirement: 123,
				Parameters:    tc.params,
			}
			if _, err := aesctrhmac.NewKey(opts); err == nil {
				t.Errorf("aesctrhmac.NewKey() err = nil, want error")
			}
		})
	}
}

func TestOutputPrefix(t *testing.T) {
	for _, test := range []struct {
		name    string
		variant aesctrhmac.Variant
		id      uint32
		want    []byte
	}{
		{
			name:    "Tink",
			variant: aesctrhmac.VariantTink,
			id:      uint32(0x11223344),
			want:    []byte{cryptofmt.TinkStartByte, 0x11, 0x22, 0x33, 0x44},
		},
		{
			name:    "Crunchy",
			variant: aesctrhmac.VariantCrunchy,
			id:      uint32(0x11223344),
			want:    []byte{cryptofmt.LegacyStartByte, 0x11, 0x22, 0x33, 0x44},
		},
		{
			name:    "No prefix",
			variant: aesctrhmac.VariantNoPrefix,
			id:      0,
			want:    nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  32,
				HMACKeySizeInBytes: 32,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            test.variant,
			}
			params, err := aesctrhmac.NewParameters(opts)
			if err != nil {
				t.Fatalf("aesctrhmac.NewParameters(%v) err = %v, want nil", opts, err)
			}
			aesKeyBytes, err := secretdata.NewBytesFromRand(uint32(params.AESKeySizeInBytes()))
			if err != nil {
				t.Fatalf("secretdata.NewBytes() err = %v, want nil", err)
			}
			hmacKeyBytes, err := secretdata.NewBytesFromRand(uint32(params.HMACKeySizeInBytes()))
			if err != nil {
				t.Fatalf("secretdata.NewBytes() err = %v, want nil", err)
			}
			keyOpts := aesctrhmac.KeyOpts{
				AESKeyBytes:   aesKeyBytes,
				HMACKeyBytes:  hmacKeyBytes,
				IDRequirement: test.id,
				Parameters:    params,
			}
			key, err := aesctrhmac.NewKey(keyOpts)
			if err != nil {
				t.Fatalf("aesctrhmac.NewKey(aesKeyBytes, %v, %v) err = %v, want nil", test.id, params, err)
			}
			if got := key.OutputPrefix(); !bytes.Equal(got, test.want) {
				t.Errorf("params.OutputPrefix() = %v, want %v", got, test.want)
			}
		})
	}
}

type TestKey struct {
	name         string
	id           uint32
	aesKey       secretdata.Bytes
	hmacKey      secretdata.Bytes
	parameterOps aesctrhmac.ParametersOpts
}

func TestNewKeyWorks(t *testing.T) {
	for _, test := range []TestKey{
		{
			name:    "AES128-HMAC128-SHA256-Tink",
			id:      1,
			aesKey:  aes128KeyBytes,
			hmacKey: hmac128KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantTink,
			},
		},
		{
			name:    "AES128-HMAC128-SHA256-Crunchy",
			id:      1,
			aesKey:  aes128KeyBytes,
			hmacKey: hmac128KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantCrunchy,
			},
		},
		{
			name:    "AES128-HMAC128-SHA256-NoPrefix",
			id:      0,
			aesKey:  aes128KeyBytes,
			hmacKey: hmac128KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantNoPrefix,
			},
		},
		{
			name:    "AES128-HMAC256-SHA256-Tink",
			id:      1,
			aesKey:  aes128KeyBytes,
			hmacKey: hmac256KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 32,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantTink,
			},
		},
		{
			name:    "AES128-HMAC256-SHA256-Crunchy",
			id:      1,
			aesKey:  aes128KeyBytes,
			hmacKey: hmac256KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 32,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantCrunchy,
			},
		},
		{
			name:    "AES128-HMAC256-SHA256-NoPrefix",
			id:      0,
			aesKey:  aes128KeyBytes,
			hmacKey: hmac256KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 32,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantNoPrefix,
			},
		},
		{
			name:    "AES256-HMAC128-SHA256-Tink",
			id:      1,
			aesKey:  aes256KeyBytes,
			hmacKey: hmac128KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  32,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantTink,
			},
		},
		{
			name:    "AES256-HMAC128-SHA256-Crunchy",
			id:      1,
			aesKey:  aes256KeyBytes,
			hmacKey: hmac128KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  32,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantCrunchy,
			},
		},
		{
			name:    "AES256-HMAC128-SHA256-NoPrefix",
			id:      0,
			aesKey:  aes256KeyBytes,
			hmacKey: hmac128KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  32,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantNoPrefix,
			},
		},
		{
			name:    "AES256-HMAC256-SHA256-Tink",
			id:      1,
			aesKey:  aes256KeyBytes,
			hmacKey: hmac256KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  32,
				HMACKeySizeInBytes: 32,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantTink,
			},
		},
		{
			name:    "AES256-HMAC256-SHA256-Crunchy",
			id:      1,
			aesKey:  aes256KeyBytes,
			hmacKey: hmac256KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  32,
				HMACKeySizeInBytes: 32,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantCrunchy,
			},
		},
		{
			name:    "AES256-HMAC256-SHA256-NoPrefix",
			id:      0,
			aesKey:  aes256KeyBytes,
			hmacKey: hmac256KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  32,
				HMACKeySizeInBytes: 32,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantNoPrefix,
			},
		},
		{
			name:    "AES256-HMAC256-SHA512-Tink",
			id:      1,
			aesKey:  aes256KeyBytes,
			hmacKey: hmac256KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  32,
				HMACKeySizeInBytes: 32,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA512,
				Variant:            aesctrhmac.VariantTink,
			},
		},
		{
			name:    "AES256-HMAC256-SHA512-Crunchy",
			id:      1,
			aesKey:  aes256KeyBytes,
			hmacKey: hmac256KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  32,
				HMACKeySizeInBytes: 32,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA512,
				Variant:            aesctrhmac.VariantCrunchy,
			},
		},
		{
			name:    "AES256-HMAC256-SHA512-NoPrefix",
			id:      0,
			aesKey:  aes256KeyBytes,
			hmacKey: hmac256KeyBytes,
			parameterOps: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  32,
				HMACKeySizeInBytes: 32,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA512,
				Variant:            aesctrhmac.VariantNoPrefix,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := aesctrhmac.NewParameters(test.parameterOps)
			if err != nil {
				t.Fatalf("aesctrhmac.NewParameters(%v) err = %v, want nil", test.parameterOps, err)
			}
			// Create two keys with the same parameters and key bytes.
			key1, err := aesctrhmac.NewKey(aesctrhmac.KeyOpts{
				AESKeyBytes:   test.aesKey,
				HMACKeyBytes:  test.hmacKey,
				IDRequirement: test.id,
				Parameters:    params,
			})
			if err != nil {
				t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
			}
			if !key1.Parameters().Equal(params) {
				t.Errorf("key1.Parameters() = %v, want %v", key1.Parameters(), params)
			}
			aesKey1Bytes := key1.AESKeyBytes()
			if !aesKey1Bytes.Equal(test.aesKey) {
				t.Errorf("aesKey1Bytes.Equal(test.aesKey) = false, want true")
			}
			hmacKey1Bytes := key1.HMACKeyBytes()
			if !hmacKey1Bytes.Equal(test.hmacKey) {
				t.Errorf("hmacKey1Bytes.Equal(test.hmacKey) = false, want true")
			}
			keyID1, required := key1.IDRequirement()
			if wantRequired := test.parameterOps.Variant != aesctrhmac.VariantNoPrefix; required != wantRequired {
				t.Errorf("required = %v, want %v", required, wantRequired)
			}
			wantID := test.id
			if !required {
				wantID = 0
			}
			if keyID1 != wantID {
				t.Errorf("keyID1 = %v, want %v", keyID1, wantID)
			}
			key2, err := aesctrhmac.NewKey(aesctrhmac.KeyOpts{
				AESKeyBytes:   test.aesKey,
				HMACKeyBytes:  test.hmacKey,
				IDRequirement: test.id,
				Parameters:    params,
			})
			if err != nil {
				t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
			}
			// Test Equal.
			if !key1.Equal(key2) {
				t.Errorf("key1.Equal(key2) = %v, want true", key1.Equal(key2))
			}
			if diff := cmp.Diff(key1, key2); diff != "" {
				t.Errorf("key1 diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestKeyEqualReturnsFalseIfDifferent(t *testing.T) {
	aes128Key2Bytes := secretdata.NewBytesFromData([]byte("3333333333333333"), insecuresecretdataaccess.Token{})
	hmac128Key2Bytes := secretdata.NewBytesFromData([]byte("4444444444444444"), insecuresecretdataaccess.Token{})
	for _, test := range []struct {
		name   string
		first  TestKey
		second TestKey
	}{
		{
			name: "different AES key size",
			first: TestKey{
				aesKey:  aes128KeyBytes,
				hmacKey: hmac128KeyBytes,
				id:      0x01,
				parameterOps: aesctrhmac.ParametersOpts{
					AESKeySizeInBytes:  16,
					HMACKeySizeInBytes: 16,
					IVSizeInBytes:      12,
					TagSizeInBytes:     16,
					HashType:           aesctrhmac.SHA256,
					Variant:            aesctrhmac.VariantTink,
				},
			},
			second: TestKey{
				aesKey:  aes256KeyBytes,
				hmacKey: hmac128KeyBytes,
				id:      0x01,
				parameterOps: aesctrhmac.ParametersOpts{
					AESKeySizeInBytes:  32,
					HMACKeySizeInBytes: 16,
					IVSizeInBytes:      12,
					TagSizeInBytes:     16,
					HashType:           aesctrhmac.SHA256,
					Variant:            aesctrhmac.VariantTink,
				},
			},
		},
		{
			name: "different HMAC key size",
			first: TestKey{
				aesKey:  aes128KeyBytes,
				hmacKey: hmac128KeyBytes,
				id:      0x01,
				parameterOps: aesctrhmac.ParametersOpts{
					AESKeySizeInBytes:  16,
					HMACKeySizeInBytes: 16,
					IVSizeInBytes:      12,
					TagSizeInBytes:     16,
					HashType:           aesctrhmac.SHA256,
					Variant:            aesctrhmac.VariantTink,
				},
			},
			second: TestKey{
				aesKey:  aes128KeyBytes,
				hmacKey: hmac256KeyBytes,
				id:      0x01,
				parameterOps: aesctrhmac.ParametersOpts{
					AESKeySizeInBytes:  16,
					HMACKeySizeInBytes: 32,
					IVSizeInBytes:      12,
					TagSizeInBytes:     16,
					HashType:           aesctrhmac.SHA256,
					Variant:            aesctrhmac.VariantTink,
				},
			},
		},
		{
			name: "different variant",
			first: TestKey{
				aesKey:  aes128KeyBytes,
				hmacKey: hmac128KeyBytes,
				id:      0x01,
				parameterOps: aesctrhmac.ParametersOpts{
					AESKeySizeInBytes:  16,
					HMACKeySizeInBytes: 16,
					IVSizeInBytes:      12,
					TagSizeInBytes:     16,
					HashType:           aesctrhmac.SHA256,
					Variant:            aesctrhmac.VariantCrunchy,
				},
			},
			second: TestKey{
				aesKey:  aes128KeyBytes,
				hmacKey: hmac128KeyBytes,
				id:      0x01,
				parameterOps: aesctrhmac.ParametersOpts{
					AESKeySizeInBytes:  16,
					HMACKeySizeInBytes: 16,
					IVSizeInBytes:      12,
					TagSizeInBytes:     16,
					HashType:           aesctrhmac.SHA256,
					Variant:            aesctrhmac.VariantTink,
				},
			},
		},
		{
			name: "different key IDs",
			first: TestKey{
				aesKey:  aes128KeyBytes,
				hmacKey: hmac128KeyBytes,
				id:      0x01,
				parameterOps: aesctrhmac.ParametersOpts{
					AESKeySizeInBytes:  16,
					HMACKeySizeInBytes: 16,
					IVSizeInBytes:      12,
					TagSizeInBytes:     16,
					HashType:           aesctrhmac.SHA256,
					Variant:            aesctrhmac.VariantCrunchy,
				},
			},
			second: TestKey{
				aesKey:  aes128KeyBytes,
				hmacKey: hmac128KeyBytes,
				id:      0x02,
				parameterOps: aesctrhmac.ParametersOpts{
					AESKeySizeInBytes:  16,
					HMACKeySizeInBytes: 16,
					IVSizeInBytes:      12,
					TagSizeInBytes:     16,
					HashType:           aesctrhmac.SHA256,
					Variant:            aesctrhmac.VariantTink,
				},
			},
		},
		{
			name: "different AES key bytes",
			first: TestKey{
				aesKey:  aes128KeyBytes,
				hmacKey: hmac128KeyBytes,
				id:      0x01,
				parameterOps: aesctrhmac.ParametersOpts{
					AESKeySizeInBytes:  16,
					HMACKeySizeInBytes: 16,
					IVSizeInBytes:      12,
					TagSizeInBytes:     16,
					HashType:           aesctrhmac.SHA256,
					Variant:            aesctrhmac.VariantTink,
				},
			},
			second: TestKey{
				aesKey:  aes128Key2Bytes,
				hmacKey: hmac128KeyBytes,
				id:      0x02,
				parameterOps: aesctrhmac.ParametersOpts{
					AESKeySizeInBytes:  16,
					HMACKeySizeInBytes: 16,
					IVSizeInBytes:      12,
					TagSizeInBytes:     16,
					HashType:           aesctrhmac.SHA256,
					Variant:            aesctrhmac.VariantTink,
				},
			},
		},
		{
			name: "different HMAC key bytes",
			first: TestKey{
				aesKey:  aes128KeyBytes,
				hmacKey: hmac128KeyBytes,
				id:      0x01,
				parameterOps: aesctrhmac.ParametersOpts{
					AESKeySizeInBytes:  16,
					HMACKeySizeInBytes: 16,
					IVSizeInBytes:      12,
					TagSizeInBytes:     16,
					HashType:           aesctrhmac.SHA256,
					Variant:            aesctrhmac.VariantTink,
				},
			},
			second: TestKey{
				aesKey:  aes128KeyBytes,
				hmacKey: hmac128Key2Bytes,
				id:      0x01,
				parameterOps: aesctrhmac.ParametersOpts{
					AESKeySizeInBytes:  16,
					HMACKeySizeInBytes: 16,
					IVSizeInBytes:      12,
					TagSizeInBytes:     16,
					HashType:           aesctrhmac.SHA256,
					Variant:            aesctrhmac.VariantTink,
				},
			},
		},
		{
			name: "different hash function",
			first: TestKey{
				aesKey:  aes128KeyBytes,
				hmacKey: hmac128KeyBytes,
				id:      0x01,
				parameterOps: aesctrhmac.ParametersOpts{
					AESKeySizeInBytes:  16,
					HMACKeySizeInBytes: 16,
					IVSizeInBytes:      12,
					TagSizeInBytes:     16,
					HashType:           aesctrhmac.SHA256,
					Variant:            aesctrhmac.VariantTink,
				},
			},
			second: TestKey{
				aesKey:  aes128KeyBytes,
				hmacKey: hmac128KeyBytes,
				id:      0x01,
				parameterOps: aesctrhmac.ParametersOpts{
					AESKeySizeInBytes:  16,
					HMACKeySizeInBytes: 16,
					IVSizeInBytes:      12,
					TagSizeInBytes:     16,
					HashType:           aesctrhmac.SHA384,
					Variant:            aesctrhmac.VariantTink,
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			firstParams, err := aesctrhmac.NewParameters(test.first.parameterOps)
			if err != nil {
				t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
			}
			firstKey, err := aesctrhmac.NewKey(aesctrhmac.KeyOpts{
				AESKeyBytes:   test.first.aesKey,
				HMACKeyBytes:  test.first.hmacKey,
				IDRequirement: test.first.id,
				Parameters:    firstParams,
			})
			if err != nil {
				t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
			}
			secondParams, err := aesctrhmac.NewParameters(test.second.parameterOps)
			if err != nil {
				t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
			}
			secondKey, err := aesctrhmac.NewKey(aesctrhmac.KeyOpts{
				AESKeyBytes:   test.second.aesKey,
				HMACKeyBytes:  test.second.hmacKey,
				IDRequirement: test.second.id,
				Parameters:    secondParams,
			})
			if err != nil {
				t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
			}
			if firstKey.Equal(secondKey) {
				t.Errorf("firstKey.Equal(secondKey) = true, want false")
			}
			// Use cmp.Equal to compare the keys.
			if cmp.Equal(firstKey, secondKey) {
				t.Errorf("firstKey.Equal(secondKey) = true, want false")
			}
		})
	}
}

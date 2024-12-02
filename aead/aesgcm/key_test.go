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

package aesgcm_test

import (
	"bytes"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

var (
	key128Bits = []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	key256Bits = []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
)

func TestNewParametersInvalidKeySize(t *testing.T) {
	for _, keySize := range []int{1, 15, 17, 31, 33} {
		opts := aesgcm.ParametersOpts{
			KeySizeInBytes: keySize,
			IVSizeInBytes:  12,
			TagSizeInBytes: 16,
			Variant:        aesgcm.VariantTink,
		}
		if _, err := aesgcm.NewParameters(opts); err == nil {
			t.Errorf("aesgcm.NewParameters(%v) err = nil, want error", opts)
		}
	}
}

func TestNewParametersInvalidIVSize(t *testing.T) {
	for _, ivSize := range []int{-1, 0} {
		opts := aesgcm.ParametersOpts{
			KeySizeInBytes: 16,
			IVSizeInBytes:  ivSize,
			TagSizeInBytes: 16,
			Variant:        aesgcm.VariantTink,
		}
		if _, err := aesgcm.NewParameters(opts); err == nil {
			t.Errorf("aesgcm.NewParameters(%v) err = nil, want error", opts)
		}
	}
}

func TestNewParametersInvalidTagSize(t *testing.T) {
	for _, tagSize := range []int{1, 11, 17} {
		opts := aesgcm.ParametersOpts{
			KeySizeInBytes: 16,
			IVSizeInBytes:  12,
			TagSizeInBytes: tagSize,
			Variant:        aesgcm.VariantTink,
		}
		if _, err := aesgcm.NewParameters(opts); err == nil {
			t.Errorf("aesgcm.NewParameters(%v) err = nil, want error", opts)
		}
	}
}

func TestNewParametersInvalidVariant(t *testing.T) {
	opts := aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantUnknown,
	}
	if _, err := aesgcm.NewParameters(opts); err == nil {
		t.Errorf("aesgcm.NewParameters(%v) err = nil, want error", opts)
	}
}

func TestNewKeyFailsIfParametersIsNil(t *testing.T) {
	keyBytes, err := secretdata.NewBytesFromRand(32)
	if err != nil {
		t.Fatalf("secretdata.NewBytesFromRand(32) err = %v, want nil", err)
	}
	if _, err := aesgcm.NewKey(keyBytes, 123, nil); err == nil {
		t.Errorf("aesgcm.NewKey(keyBytes, 123, nil) err = nil, want error")
	}
}

func TestNewKeyFailsIfKeySizeIsDifferentThanParameters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		keyBytes secretdata.Bytes
		opts     aesgcm.ParametersOpts
	}{
		{
			name:     "key size is 16 but parameters is 32",
			keyBytes: secretdata.NewBytesFromData(key128Bits, insecuresecretdataaccess.Token{}),
			opts: aesgcm.ParametersOpts{
				KeySizeInBytes: 32,
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        aesgcm.VariantTink,
			},
		},
		{
			name:     "key size is 32 but parameters is 16",
			keyBytes: secretdata.NewBytesFromData(key256Bits, insecuresecretdataaccess.Token{}),
			opts: aesgcm.ParametersOpts{
				KeySizeInBytes: 16,
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        aesgcm.VariantTink,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := aesgcm.NewParameters(tc.opts)
			if err != nil {
				t.Fatalf("aesgcm.NewParameters(%v) err = %v, want nil", tc.opts, err)
			}
			if _, err := aesgcm.NewKey(tc.keyBytes, 123, params); err == nil {
				t.Errorf("aesgcm.NewKey(%v, 123, %v) err = nil, want error", tc.keyBytes, params)
			}
		})
	}
}

// TestNewKeyFailsIfInvalidParams tests that NewKey fails if the parameters are invalid.
//
// The only way to create invalid parameters is to create a struct literal with default
// values.
func TestNewKeyFailsIfInvalidParams(t *testing.T) {
	keyBytes, err := secretdata.NewBytesFromRand(32)
	if err != nil {
		t.Fatalf("secretdata.NewBytesFromRand(32) err = %v, want nil", err)
	}
	params := &aesgcm.Parameters{}
	if _, err := aesgcm.NewKey(keyBytes, 123, params); err == nil {
		t.Errorf("aesgcm.NewKey(keyBytes, 123, nil) err = nil, want error")
	}
}

func TestNewKeyFailsIfNoPrefixAndIDIsNotZero(t *testing.T) {
	opts := aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	}
	params, err := aesgcm.NewParameters(opts)
	if err != nil {
		t.Fatalf("aesgcm.NewParameters(%v) err = %v, want nil", opts, err)
	}
	keyBytes := secretdata.NewBytesFromData(key128Bits, insecuresecretdataaccess.Token{})
	if _, err := aesgcm.NewKey(keyBytes, 123, params); err == nil {
		t.Errorf("aesgcm.NewKey(keyBytes, 123, %v) err = nil, want error", params)
	}
}

func TestOutputPrefix(t *testing.T) {
	for _, test := range []struct {
		name    string
		variant aesgcm.Variant
		id      uint32
		want    []byte
	}{
		{
			name:    "Tink",
			variant: aesgcm.VariantTink,
			id:      uint32(0x01020304),
			want:    []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "Crunchy",
			variant: aesgcm.VariantCrunchy,
			id:      uint32(0x01020304),
			want:    []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "No prefix",
			variant: aesgcm.VariantNoPrefix,
			id:      0,
			want:    nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := aesgcm.ParametersOpts{
				KeySizeInBytes: 32,
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        test.variant,
			}
			params, err := aesgcm.NewParameters(opts)
			if err != nil {
				t.Fatalf("aesgcm.NewParameters(%v) err = %v, want nil", opts, err)
			}
			keyBytes, err := secretdata.NewBytesFromRand(32)
			if err != nil {
				t.Fatalf("secretdata.NewBytes(32fNewBytesFromRand() err = %v, want nil", err)
			}
			key, err := aesgcm.NewKey(keyBytes, test.id, params)
			if err != nil {
				t.Fatalf("aesgcm.NewKey(keyBytes, %v, %v) err = %v, want nil", test.id, params, err)
			}
			if got := key.OutputPrefix(); !bytes.Equal(got, test.want) {
				t.Errorf("params.OutputPrefix() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestNewParametersWorks(t *testing.T) {
	for _, test := range []struct {
		name    string
		keySize int
		variant aesgcm.Variant
	}{
		{
			name:    "128-bit key with Tink prefix",
			keySize: 16,
			variant: aesgcm.VariantTink,
		},
		{
			name:    "128-bit key with Crunchy prefix",
			keySize: 16,
			variant: aesgcm.VariantCrunchy,
		},
		{
			name:    "128-bit key with NoPrefix prefix",
			keySize: 16,
			variant: aesgcm.VariantNoPrefix,
		},
		{
			name:    "256-bit key with Tink prefix",
			keySize: 32,
			variant: aesgcm.VariantTink,
		},
		{
			name:    "256-bit key with Crunchy prefix",
			keySize: 32,
			variant: aesgcm.VariantCrunchy,
		},
		{
			name:    "256-bit key with NoPrefix prefix",
			keySize: 32,
			variant: aesgcm.VariantNoPrefix,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := aesgcm.ParametersOpts{
				KeySizeInBytes: test.keySize,
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        test.variant,
			}
			params, err := aesgcm.NewParameters(opts)
			if err != nil {
				t.Fatalf("aesgcm.NewParameters(%v) err = %v, want nil", opts, err)
			}
			if params.HasIDRequirement() != (test.variant != aesgcm.VariantNoPrefix) {
				t.Errorf("params.HasIDRequirement() = %v, want %v", params.HasIDRequirement(), (test.variant != aesgcm.VariantNoPrefix))
			}
			if params.KeySizeInBytes() != test.keySize {
				t.Errorf("params.KeySizeInBytes()() = %v, want %v", params.KeySizeInBytes(), test.keySize)
			}
			if params.TagSizeInBytes() != 16 {
				t.Errorf("params.TagSizeInBytes() = %v, want 16", params.TagSizeInBytes())
			}
			if params.IVSizeInBytes() != 12 {
				t.Errorf("params.IVSizeInBytes() = %v, want 12", params.IVSizeInBytes())
			}
			if params.Variant() != test.variant {
				t.Errorf("params.Variant() = %v, want %v", params.Variant(), test.variant)
			}
			otherParams, err := aesgcm.NewParameters(opts)
			if err != nil {
				t.Fatalf("aesgcm.NewParameters(%v) err = %v, want nil", opts, err)
			}
			if !params.Equal(otherParams) {
				t.Errorf("params.Equal(otherParams) = %v, want true", params.Equal(otherParams))
			}
		})
	}
}

func TestParametersEqualFalseIfDifferent(t *testing.T) {
	for _, test := range []struct {
		name        string
		key1Size    int
		key1Variant aesgcm.Variant
		key2Size    int
		key2Variant aesgcm.Variant
	}{
		{
			name:        "different key size",
			key1Size:    16,
			key1Variant: aesgcm.VariantTink,
			key2Size:    32,
			key2Variant: aesgcm.VariantTink,
		},
		{
			name:        "different prefix variant",
			key1Size:    16,
			key1Variant: aesgcm.VariantCrunchy,
			key2Size:    16,
			key2Variant: aesgcm.VariantTink,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts1 := aesgcm.ParametersOpts{
				KeySizeInBytes: test.key1Size,
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        test.key1Variant,
			}
			params1, err := aesgcm.NewParameters(opts1)
			if err != nil {
				t.Fatalf("aesgcm.NewParameters(%v) err = %v, want nil", opts1, err)
			}
			opts2 := aesgcm.ParametersOpts{
				KeySizeInBytes: test.key2Size,
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        test.key2Variant,
			}
			params2, err := aesgcm.NewParameters(opts2)
			if err != nil {
				t.Errorf("aesgcm.NewParameters(%v) err = %v, want nil", opts2, err)
			}
			if params1.Equal(params2) {
				t.Errorf("params.Equal(params2) = %v, want false", params1.Equal(params2))
			}
		})
	}
}

type TestKey struct {
	name    string
	keySize int
	id      uint32
	key     []byte
	variant aesgcm.Variant
}

func TestNewKeyWorks(t *testing.T) {
	for _, test := range []TestKey{
		{
			name:    "128-bit key with Tink prefix",
			keySize: 16,
			id:      1,
			key:     key128Bits,
			variant: aesgcm.VariantTink,
		},
		{
			name:    "128-bit key with Crunchy prefix",
			keySize: 16,
			id:      1,
			key:     key128Bits,
			variant: aesgcm.VariantCrunchy,
		},
		{
			name:    "128-bit key with NoPrefix prefix",
			keySize: 16,
			id:      0,
			key:     key128Bits,
			variant: aesgcm.VariantNoPrefix,
		},
		{
			name:    "256-bit key with Tink prefix",
			keySize: 32,
			id:      1,
			key:     key256Bits,
			variant: aesgcm.VariantTink,
		},
		{
			name:    "256-bit key with Crunchy prefix",
			keySize: 32,
			id:      1,
			key:     key256Bits,
			variant: aesgcm.VariantCrunchy,
		},
		{
			name:    "256-bit key with NoPrefix prefix",
			keySize: 32,
			id:      0,
			key:     key256Bits,
			variant: aesgcm.VariantNoPrefix,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := aesgcm.ParametersOpts{
				KeySizeInBytes: test.keySize,
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        test.variant,
			}
			params, err := aesgcm.NewParameters(opts)
			if err != nil {
				t.Fatalf("aesgcm.NewParameters(%v) err = %v, want nil", opts, err)
			}
			keyBytes := secretdata.NewBytesFromData(test.key, insecuresecretdataaccess.Token{})

			// Create two keys with the same parameters and key bytes.
			key1, err := aesgcm.NewKey(keyBytes, test.id, params)
			if err != nil {
				t.Fatalf("aesgcm.NewKey(keyBytes, %v, %v) err = %v, want nil", test.id, params, err)
			}
			if !key1.Parameters().Equal(params) {
				t.Errorf("key1.Parameters() = %v, want %v", key1.Parameters(), params)
			}
			key1Bytes := key1.KeyBytes()
			if !keyBytes.Equal(key1Bytes) {
				t.Errorf("keyBytes.Equal(key1Bytes) = false, want true")
			}
			keyID1, required := key1.IDRequirement()
			if wantRequired := test.variant != aesgcm.VariantNoPrefix; required != wantRequired {
				t.Errorf("required = %v, want %v", required, wantRequired)
			}
			wantID := test.id
			if !required {
				wantID = 0
			}
			if keyID1 != wantID {
				t.Errorf("keyID1 = %v, want %v", keyID1, wantID)
			}
			key2, err := aesgcm.NewKey(keyBytes, keyID1, params)
			if err != nil {
				t.Fatalf("aesgcm.NewKey(keyBytes, %v, %v) err = %v, want nil", keyID1, params, err)
			}
			// Test Equal.
			if !key1.Equal(key2) {
				t.Errorf("key1.Equal(key2) = %v, want true", key1.Equal(key2))
			}
		})
	}
}

func TestKeyEqualReturnsFalseIfDifferent(t *testing.T) {
	for _, test := range []struct {
		name   string
		first  TestKey
		second TestKey
	}{
		{
			name: "different key size",
			first: TestKey{
				keySize: 16,
				variant: aesgcm.VariantTink,
				key:     key128Bits,
				id:      0x01,
			},
			second: TestKey{
				keySize: 32,
				variant: aesgcm.VariantTink,
				key:     key256Bits,
				id:      0x01,
			},
		},
		{
			name: "different prefix variant",
			first: TestKey{
				keySize: 16,
				variant: aesgcm.VariantTink,
				key:     key128Bits,
				id:      0x01,
			},
			second: TestKey{
				keySize: 16,
				variant: aesgcm.VariantCrunchy,
				key:     key128Bits,
				id:      0x01,
			},
		},
		{
			name: "different key IDs",
			first: TestKey{
				keySize: 16,
				variant: aesgcm.VariantTink,
				key:     key128Bits,
				id:      0x01,
			},
			second: TestKey{
				keySize: 16,
				variant: aesgcm.VariantTink,
				key:     key128Bits,
				id:      0x02,
			},
		},
		{
			name: "different key bytes",
			first: TestKey{
				keySize: 16,
				variant: aesgcm.VariantCrunchy,
				key:     key128Bits,
				id:      0x01,
			},
			second: TestKey{
				keySize: 16,
				variant: aesgcm.VariantCrunchy,
				key: []byte{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09,
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				},
				id: 0x01,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			firstOpts := aesgcm.ParametersOpts{
				KeySizeInBytes: test.first.keySize,
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        test.first.variant,
			}
			firstParams, err := aesgcm.NewParameters(firstOpts)
			if err != nil {
				t.Fatalf("aesgcm.NewParameters(%v) err = %v, want nil", firstOpts, err)
			}
			firstKeyBytes := secretdata.NewBytesFromData(test.first.key, insecuresecretdataaccess.Token{})
			firstKey, err := aesgcm.NewKey(firstKeyBytes, test.first.id, firstParams)
			if err != nil {
				t.Fatalf("aesgcm.NewKey(firstKeyBytes, %v, %v) err = %v, want nil", test.first.id, firstParams, err)
			}

			secondOpts := aesgcm.ParametersOpts{
				KeySizeInBytes: test.second.keySize,
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        test.second.variant,
			}
			secondParams, err := aesgcm.NewParameters(secondOpts)
			if err != nil {
				t.Fatalf("aesgcm.NewParameters(%v) err = %v, want nil", secondOpts, err)
			}
			secondKeyBytes := secretdata.NewBytesFromData(test.second.key, insecuresecretdataaccess.Token{})
			secondKey, err := aesgcm.NewKey(secondKeyBytes, test.second.id, secondParams)
			if err != nil {
				t.Fatalf("aesgcm.NewKey(secondKeyBytes, %v, %v) err = %v, want nil", test.second.id, secondParams, err)
			}
			if firstKey.Equal(secondKey) {
				t.Errorf("firstKey.Equal(secondKey) = true, want false")
			}
		})
	}
}

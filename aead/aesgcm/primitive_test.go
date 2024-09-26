// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aesgcm

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
)

type testCase struct {
	name string
	opts ParametersOpts
}

func newKey(t *testing.T, keyData []byte, opts ParametersOpts) *Key {
	t.Helper()
	params, err := NewParameters(opts)
	if err != nil {
		t.Fatalf("NewParameters(%v) err = %v, want nil", opts, err)
	}
	keyBytes := secretdata.NewBytesFromData(keyData, insecuresecretdataaccess.Token{})
	if err != nil {
		t.Fatalf("secretdata.NewBytesFromRand(%v) err = %v, want nil", opts.KeySizeInBytes, err)
	}
	idRequirement := uint32(123)
	if opts.Variant == VariantNoPrefix {
		idRequirement = 0
	}
	key, err := NewKey(keyBytes, idRequirement, params)
	if err != nil {
		t.Fatalf("NewKey(keyBytes, %v, %v) err = %v, want nil", params, idRequirement, err)
	}
	return key
}

func hexDecode(t *testing.T, hexStr string) []byte {
	t.Helper()
	x, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex.DecodeString(%v) err = %v, want nil", hexStr, err)
	}
	return x
}

func TestPrimitiveCreator(t *testing.T) {
	// Test vectors from
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_gcm_test.json.
	// 16 bytes key.
	key1 := hexDecode(t, "5b9604fe14eadba931b0ccf34843dab9")
	ciphertext1 := hexDecode(t, "028318abc1824029138141a226073cc1d851beff176384dc9896d5ff0a3ea7a5487cb5f7d70fb6c58d038554")
	wantMessage1 := hexDecode(t, "001d0c231287c1182784554ca3a21908")
	// 32 bytes key.
	key2 := hexDecode(t, "51e4bf2bad92b7aff1a4bc05550ba81df4b96fabf41c12c7b00e60e48db7e152")
	ciphertext2 := hexDecode(t, "4f07afedfdc3b6c2361823d3cf332a12fdee800b602e8d7c4799d62c140c9bb834876b09")
	wantMessage2 := hexDecode(t, "be3308f72a2c6aed")
	for _, testCase := range []struct {
		name          string
		opts          ParametersOpts
		keyBytes      []byte
		ciphertext    []byte
		wantPlaintext []byte
	}{
		{
			name: fmt.Sprintf("%d-bit key, Tink Variant", len(key1)*8),
			opts: ParametersOpts{
				KeySizeInBytes: len(key1),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        VariantTink,
			},
			keyBytes:      key1,
			ciphertext:    ciphertext1,
			wantPlaintext: wantMessage1,
		},
		{
			name: fmt.Sprintf("%d-bit key, Crunchy Variant", len(key1)*8),
			opts: ParametersOpts{
				KeySizeInBytes: len(key1),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        VariantCrunchy,
			},
			keyBytes:      key1,
			ciphertext:    ciphertext1,
			wantPlaintext: wantMessage1,
		},
		{
			name: fmt.Sprintf("%d-bit key, No Prefix Variant", len(key1)*8),
			opts: ParametersOpts{
				KeySizeInBytes: len(key1),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        VariantNoPrefix,
			},
			keyBytes:      key1,
			ciphertext:    ciphertext1,
			wantPlaintext: wantMessage1,
		},
		{
			name: fmt.Sprintf("%d-bit key, Tink Variant", len(key2)*8),
			opts: ParametersOpts{
				KeySizeInBytes: len(key2),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        VariantTink,
			},
			keyBytes:      key2,
			ciphertext:    ciphertext2,
			wantPlaintext: wantMessage2,
		},
		{
			name: fmt.Sprintf("%d-bit key, Crunchy Variant", len(key2)*8),
			opts: ParametersOpts{
				KeySizeInBytes: len(key2),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        VariantCrunchy,
			},
			keyBytes:      key2,
			ciphertext:    ciphertext2,
			wantPlaintext: wantMessage2,
		},
		{
			name: fmt.Sprintf("%d-bit key, No Prefix Variant", len(key2)*8),
			opts: ParametersOpts{
				KeySizeInBytes: len(key2),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        VariantNoPrefix,
			},
			keyBytes:      key2,
			ciphertext:    ciphertext2,
			wantPlaintext: wantMessage2,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			key := newKey(t, testCase.keyBytes, testCase.opts)
			primitive, err := primitiveConstructor(key)
			if err != nil {
				t.Fatalf("primitiveConstructor(key) err = %v, want nil", err)
			}
			aesgcmPrimitive := primitive.(*subtle.AESGCM)
			if aesgcmPrimitive == nil {
				t.Errorf("primitiveConstructor(key) has type %T, wanted *subtle.AESGCM", primitive)
			}
			decrypted, err := aesgcmPrimitive.Decrypt(testCase.ciphertext, []byte{})
			if err != nil {
				t.Fatalf("aesgcmPrimitive.Decrypt(%x, []byte{}) err = %v, want nil", testCase.ciphertext, err)
			}
			if got, want := decrypted, testCase.wantPlaintext; !bytes.Equal(got, want) {
				t.Errorf("aesgcmPrimitive.Decrypt(%x, %x) = %x, want %x", testCase.ciphertext, testCase.wantPlaintext, got, want)
			}
		})
	}
}

func TestPrimitiveCreatorInvalidParameters(t *testing.T) {
	for _, variant := range []Variant{VariantTink, VariantCrunchy, VariantNoPrefix} {
		// Key allows keySize in {16, 24, 32}, but the primitive wants {16, 32}.
		for _, keySize := range []uint32{24} {
			// Key allows ivSize > 0, but the primitive wants 12.
			for _, ivSize := range []int{1, 13} {
				// Key allows 12 <= tagSize <= 16, but the primitive wants 16.
				for _, tagSize := range []int{12, 15} {
					t.Run(fmt.Sprintf("variant: %v, keySize: %v, ivSize: %v, tagSize: %v", variant, keySize, ivSize, tagSize), func(t *testing.T) {
						opts := ParametersOpts{
							KeySizeInBytes: int(keySize),
							IVSizeInBytes:  ivSize,
							TagSizeInBytes: tagSize,
							Variant:        variant,
						}
						keyData := random.GetRandomBytes(keySize)
						key := newKey(t, keyData, opts)
						if _, err := primitiveConstructor(key); err == nil {
							t.Errorf("primitiveConstructor(key) err = nil, want error")
						}
					})
				}
			}
		}
	}
}

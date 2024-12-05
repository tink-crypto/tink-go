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

package aesgcm_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/internal/aead"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	testingaead "github.com/tink-crypto/tink-go/v2/internal/testing/aead"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type testCase struct {
	name string
	opts aesgcm.ParametersOpts
}

const ivSize = 12
const tagSize = 16

// Key allows sizes of IV, tag and key that are not supported by the primitive.
func TestNewAEADFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts aesgcm.ParametersOpts
	}{
		{
			name: "AES128-TINK-IV:11",
			opts: aesgcm.ParametersOpts{KeySizeInBytes: 16, IVSizeInBytes: 11, TagSizeInBytes: 16, Variant: aesgcm.VariantTink},
		},
		{
			name: "AES256-TINK-IV:11",
			opts: aesgcm.ParametersOpts{KeySizeInBytes: 32, IVSizeInBytes: 11, TagSizeInBytes: 16, Variant: aesgcm.VariantTink},
		},
		{
			name: "AES128-TINK-Tag:12",
			opts: aesgcm.ParametersOpts{KeySizeInBytes: 16, IVSizeInBytes: 12, TagSizeInBytes: 12, Variant: aesgcm.VariantTink},
		},
		{
			name: "AES256-TINK-Tag:12",
			opts: aesgcm.ParametersOpts{KeySizeInBytes: 32, IVSizeInBytes: 12, TagSizeInBytes: 12, Variant: aesgcm.VariantTink},
		},
		{
			name: "AES192-TINK",
			opts: aesgcm.ParametersOpts{KeySizeInBytes: 24, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantTink},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := mustCreateKey(t, random.GetRandomBytes(uint32(tc.opts.KeySizeInBytes)), 0x11223344, tc.opts)
			if _, err := aesgcm.NewAEAD(key); err == nil {
				t.Errorf("aesgcm.NewAEAD(%v) err = nil, want error", key)
			}
		})
	}
}

func TestAEAD(t *testing.T) {
	largePlaintext := random.GetRandomBytes(1 << 24)
	for _, tc := range []struct {
		name             string
		opts             aesgcm.ParametersOpts
		idRequirement    uint32
		wantOutputPrefix []byte
		plaintext        []byte
	}{
		{
			name:             "AES128-TINK-Empty",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 16, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantTink},
			idRequirement:    0x11223344,
			wantOutputPrefix: []byte{0x01, 0x11, 0x22, 0x33, 0x44},
			plaintext:        []byte{},
		},
		{
			name:             "AES128-CRUNCHY-Empty",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 16, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantCrunchy},
			idRequirement:    0x22334455,
			wantOutputPrefix: []byte{0x00, 0x22, 0x33, 0x44, 0x55},
			plaintext:        []byte{},
		},
		{
			name:             "AES128-NO_PREFIX-Empty",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 16, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantNoPrefix},
			idRequirement:    0,
			wantOutputPrefix: []byte{},
			plaintext:        []byte{},
		},
		{
			name:             "AES256-TINK-Empty",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 32, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantTink},
			idRequirement:    0x11223344,
			wantOutputPrefix: []byte{0x01, 0x11, 0x22, 0x33, 0x44},
			plaintext:        []byte{},
		},
		{
			name:             "AES256-CRUNCHY-Empty",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 32, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantCrunchy},
			idRequirement:    0x22334455,
			wantOutputPrefix: []byte{0x00, 0x22, 0x33, 0x44, 0x55},
			plaintext:        []byte{},
		},
		{
			name:             "AES256-NO_PREFIX-Empty",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 32, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantNoPrefix},
			idRequirement:    0,
			wantOutputPrefix: []byte{},
			plaintext:        []byte{},
		},
		{
			name:             "AES128-TINK-Small",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 16, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantTink},
			idRequirement:    0x11223344,
			wantOutputPrefix: []byte{0x01, 0x11, 0x22, 0x33, 0x44},
			plaintext:        []byte("Some small plaintext"),
		},
		{
			name:             "AES128-CRUNCHY-Small",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 16, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantCrunchy},
			idRequirement:    0x22334455,
			wantOutputPrefix: []byte{0x00, 0x22, 0x33, 0x44, 0x55},
			plaintext:        []byte("Some small plaintext"),
		},
		{
			name:             "AES128-NO_PREFIX-Small",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 16, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantNoPrefix},
			idRequirement:    0,
			wantOutputPrefix: []byte{},
			plaintext:        []byte("Some small plaintext"),
		},
		{
			name:             "AES256-TINK-Small",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 32, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantTink},
			idRequirement:    0x11223344,
			wantOutputPrefix: []byte{0x01, 0x11, 0x22, 0x33, 0x44},
			plaintext:        []byte("Some small plaintext"),
		},
		{
			name:             "AES256-CRUNCHY-Small",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 32, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantCrunchy},
			idRequirement:    0x22334455,
			wantOutputPrefix: []byte{0x00, 0x22, 0x33, 0x44, 0x55},
			plaintext:        []byte("Some small plaintext"),
		},
		{
			name:             "AES256-NO_PREFIX-Small",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 32, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantNoPrefix},
			idRequirement:    0,
			wantOutputPrefix: []byte{},
			plaintext:        []byte("Some small plaintext"),
		},
		{
			name:             "AES128-TINK-Large",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 16, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantTink},
			idRequirement:    0x11223344,
			wantOutputPrefix: []byte{0x01, 0x11, 0x22, 0x33, 0x44},
			plaintext:        largePlaintext,
		},
		{
			name:             "AES128-CRUNCHY-Large",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 16, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantCrunchy},
			idRequirement:    0x22334455,
			wantOutputPrefix: []byte{0x00, 0x22, 0x33, 0x44, 0x55},
			plaintext:        largePlaintext,
		},
		{
			name:             "AES128-NO_PREFIX-Large",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 16, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantNoPrefix},
			idRequirement:    0,
			wantOutputPrefix: []byte{},
			plaintext:        largePlaintext,
		},
		{
			name:             "AES256-TINK-Large",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 32, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantTink},
			idRequirement:    0x11223344,
			wantOutputPrefix: []byte{0x01, 0x11, 0x22, 0x33, 0x44},
			plaintext:        largePlaintext,
		},
		{
			name:             "AES256-CRUNCHY-Large",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 32, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantCrunchy},
			idRequirement:    0x22334455,
			wantOutputPrefix: []byte{0x00, 0x22, 0x33, 0x44, 0x55},
			plaintext:        largePlaintext,
		},
		{
			name:             "AES256-NO_PREFIX-Large",
			opts:             aesgcm.ParametersOpts{KeySizeInBytes: 32, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantNoPrefix},
			idRequirement:    0,
			wantOutputPrefix: []byte{},
			plaintext:        largePlaintext,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyValue := random.GetRandomBytes(uint32(tc.opts.KeySizeInBytes))
			key := mustCreateKey(t, keyValue, tc.idRequirement, tc.opts)
			aead, err := aesgcm.NewAEAD(key)
			if err != nil {
				t.Fatalf("aesgcm.NewAEAD(%v) err = %v, want nil", key, err)
			}
			associatedData := []byte("associatedData")
			ciphertext, err := aead.Encrypt(tc.plaintext, associatedData)
			if err != nil {
				t.Fatalf("aead.Encrypt(%v, %v) err = %v, want nil", tc.plaintext, associatedData, err)
			}

			if got, want := len(ciphertext), len(key.OutputPrefix())+len(tc.plaintext)+ivSize+tagSize; got != want {
				t.Errorf("ciphertext has wrong length: got %d, want %d", got, want)
			}

			// Check the prefix is correct.
			if !bytes.Equal(ciphertext[:len(tc.wantOutputPrefix)], tc.wantOutputPrefix) {
				t.Errorf("ciphertext has wrong prefix: got %x, want %x", ciphertext[:len(tc.wantOutputPrefix)], tc.wantOutputPrefix)
			}

			// Check the tag length is 16 bytes.
			if want, got := tagSize, len(ciphertext)-len(key.OutputPrefix())-len(tc.plaintext)-ivSize; want != got {
				t.Errorf("ciphertext has wrong tag length: want %d, got %d", want, got)
			}

			decrypted, err := aead.Decrypt(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("aead.Decrypt(%v, %v) err = %v, want nil", ciphertext, associatedData, err)
			}
			if got, want := decrypted, tc.plaintext; !bytes.Equal(got, want) {
				t.Errorf("aead.Decrypt(%v, %v) = %v, want %v", ciphertext, associatedData, got, want)
			}
		})
	}
}

func TestAEADDecryptFailsIfCiphertextIsCorruptedOrTruncated(t *testing.T) {
	ad := random.GetRandomBytes(33)
	key := random.GetRandomBytes(16)
	pt := random.GetRandomBytes(32)
	a, err := aesgcm.NewAEAD(mustCreateKey(t, key, 0x11223344, aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantTink,
	}))
	if err != nil {
		t.Fatalf("aesgcm.NewAEAD() err = %q, want nil", err)
	}
	ct, err := a.Encrypt(pt, ad)
	if err != nil {
		t.Fatalf("a.Encrypt() err = %q, want nil", err)
	}
	// flipping bits
	for i := 0; i < len(ct); i++ {
		tmp := ct[i]
		for j := 0; j < 8; j++ {
			ct[i] ^= 1 << uint8(j)
			if _, err := a.Decrypt(ct, ad); err == nil {
				t.Errorf("a.Decrypt(ct, ad) err = nil, want error when flipping bit of ciphertext: byte %d, bit %d", i, j)
			}
			ct[i] = tmp
		}
	}
	// truncated ciphertext
	for i := 1; i < len(ct); i++ {
		if _, err := a.Decrypt(ct[:i], ad); err == nil {
			t.Errorf("a.Decrypt(ct[:%d], ad) err = nil, want error", i)
		}
	}
	// modify associated data
	for i := 0; i < len(ad); i++ {
		tmp := ad[i]
		for j := 0; j < 8; j++ {
			ad[i] ^= 1 << uint8(j)
			if _, err := a.Decrypt(ct, ad); err == nil {
				t.Errorf("a.Decrypt(ct, ad) err = nil, want error when flipping bit of ad: byte %d, bit %d", i, j)
			}
			ad[i] = tmp
		}
	}
	// replace ciphertext with a random string with a small, unacceptable size
	for _, ctSize := range []uint32{ivSize / 2, ivSize - 1} {
		smallCT := random.GetRandomBytes(ctSize)
		emptyAD := []byte{}
		if _, err := a.Decrypt(smallCT, emptyAD); err == nil {
			t.Error("a.Decrypt(smallCT, emptyAD) err = nil, want error")
		}
	}
}

// Checks that the nonce is random by making sure that the multiple ciphertexts
// of the same message are distinct.
func TestAEADEncryptUsesRandomNonce(t *testing.T) {
	nSample := 1 << 17
	keyValue := random.GetRandomBytes(16)
	pt := []byte{}
	ad := []byte{}
	opts := aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantTink,
	}
	key := mustCreateKey(t, keyValue, 0x11223344, opts)
	a, err := aesgcm.NewAEAD(key)
	if err != nil {
		t.Fatalf("aesgcm.NewAEAD() err = %q, want nil", err)
	}
	ctSet := make(map[string]bool)
	for i := 0; i < nSample; i++ {
		ct, err := a.Encrypt(pt, ad)
		if err != nil {
			t.Fatalf("a.Encrypt() err = %q, want nil", err)
		}
		ctHex := hex.EncodeToString(ct)
		_, existed := ctSet[ctHex]
		if existed {
			t.Fatalf("nonce is repeated after %d samples", i)
		}
		ctSet[ctHex] = true
	}
}

func TestAEADWycheproofCases(t *testing.T) {
	suite := new(testingaead.WycheproofSuite)
	if err := testutil.PopulateSuite(suite, "aes_gcm_test.json"); err != nil {
		t.Fatalf("failed populating suite: %s", err)
	}
	for _, group := range suite.TestGroups {
		// Skip unsupported key and IV sizes.
		if err := aead.ValidateAESKeySize(group.KeySize / 8); err != nil {
			continue
		}
		if group.IvSize != ivSize*8 {
			continue
		}
		for _, tc := range group.Tests {
			caseName := fmt.Sprintf("%s-%s(%d,%d):Case-%d",
				suite.Algorithm, group.Type, group.KeySize, group.TagSize, tc.CaseID)
			t.Run(caseName, func(t *testing.T) {
				var combinedCt []byte
				combinedCt = append(combinedCt, tc.Iv...)
				combinedCt = append(combinedCt, tc.Ct...)
				combinedCt = append(combinedCt, tc.Tag...)
				key := mustCreateKey(t, tc.Key, 0, aesgcm.ParametersOpts{
					KeySizeInBytes: len(tc.Key),
					IVSizeInBytes:  len(tc.Iv),
					TagSizeInBytes: len(tc.Tag),
					Variant:        aesgcm.VariantNoPrefix,
				})
				a, err := aesgcm.NewAEAD(key)
				if err != nil {
					t.Fatalf("aesgcm.NewAEAD(key) err = %v, want nil", err)
				}
				decrypted, err := a.Decrypt(combinedCt, tc.Aad)
				if err != nil {
					if tc.Result == "valid" {
						t.Errorf("unexpected error in test case: %s", err)
					}
				} else {
					if tc.Result == "invalid" {
						t.Error("decrypted invalid test case")
					}
					if !bytes.Equal(decrypted, tc.Msg) {
						t.Error("incorrect decryption in test case")
					}
				}

			})
		}
	}
}

func TestPrimitiveCreator(t *testing.T) {
	// Test vectors from
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_gcm_test.json.
	// 16 bytes key.
	key1 := mustDecodeHex(t, "5b9604fe14eadba931b0ccf34843dab9")
	ciphertext1 := mustDecodeHex(t, "028318abc1824029138141a226073cc1d851beff176384dc9896d5ff0a3ea7a5487cb5f7d70fb6c58d038554")
	wantMessage1 := mustDecodeHex(t, "001d0c231287c1182784554ca3a21908")
	// 32 bytes key.
	key2 := mustDecodeHex(t, "51e4bf2bad92b7aff1a4bc05550ba81df4b96fabf41c12c7b00e60e48db7e152")
	ciphertext2 := mustDecodeHex(t, "4f07afedfdc3b6c2361823d3cf332a12fdee800b602e8d7c4799d62c140c9bb834876b09")
	wantMessage2 := mustDecodeHex(t, "be3308f72a2c6aed")

	config, err := config.New()
	if err != nil {
		t.Fatalf("config.New() err = %v, want nil", err)
	}
	if err := aesgcm.RegisterPrimitiveConstructor(config, internalapi.Token{}); err != nil {
		t.Fatalf("aesgcm.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	for _, testCase := range []struct {
		name          string
		key           *aesgcm.Key
		ciphertext    []byte
		wantPlaintext []byte
	}{
		{
			name: fmt.Sprintf("%d-bit key, Tink Variant", len(key1)*8),
			key: mustCreateKey(t, key1, 0x11223344, aesgcm.ParametersOpts{
				KeySizeInBytes: len(key1),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        aesgcm.VariantTink,
			}),
			ciphertext:    slices.Concat([]byte{0x01, 0x11, 0x22, 0x33, 0x44}, ciphertext1),
			wantPlaintext: wantMessage1,
		},
		{
			name: fmt.Sprintf("%d-bit key, Crunchy Variant", len(key1)*8),
			key: mustCreateKey(t, key1, 0x22334455, aesgcm.ParametersOpts{
				KeySizeInBytes: len(key1),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        aesgcm.VariantCrunchy,
			}),
			ciphertext:    slices.Concat([]byte{0x00, 0x22, 0x33, 0x44, 0x55}, ciphertext1),
			wantPlaintext: wantMessage1,
		},
		{
			name: fmt.Sprintf("%d-bit key, No Prefix Variant", len(key1)*8),
			key: mustCreateKey(t, key1, 0, aesgcm.ParametersOpts{
				KeySizeInBytes: len(key1),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        aesgcm.VariantNoPrefix,
			}),
			ciphertext:    ciphertext1,
			wantPlaintext: wantMessage1,
		},
		{
			name: fmt.Sprintf("%d-bit key, Tink Variant", len(key2)*8),
			key: mustCreateKey(t, key2, 0x11223344, aesgcm.ParametersOpts{
				KeySizeInBytes: len(key2),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        aesgcm.VariantTink,
			}),
			ciphertext:    slices.Concat([]byte{0x01, 0x11, 0x22, 0x33, 0x44}, ciphertext2),
			wantPlaintext: wantMessage2,
		},
		{
			name: fmt.Sprintf("%d-bit key, Crunchy Variant", len(key2)*8),
			key: mustCreateKey(t, key2, 0x22334455, aesgcm.ParametersOpts{
				KeySizeInBytes: len(key2),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        aesgcm.VariantCrunchy,
			}),
			ciphertext:    slices.Concat([]byte{0x00, 0x22, 0x33, 0x44, 0x55}, ciphertext2),
			wantPlaintext: wantMessage2,
		},
		{
			name: fmt.Sprintf("%d-bit key, No Prefix Variant", len(key2)*8),
			key: mustCreateKey(t, key2, 0, aesgcm.ParametersOpts{
				KeySizeInBytes: len(key2),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        aesgcm.VariantNoPrefix,
			}),
			ciphertext:    ciphertext2,
			wantPlaintext: wantMessage2,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			p, err := config.PrimitiveFromKey(testCase.key, internalapi.Token{})
			if err != nil {
				t.Fatalf("config.PrimitiveFromKey() err = %v, want nil", err)
			}
			a, ok := p.(tink.AEAD)
			if !ok {
				t.Errorf("primitiveConstructor(key) has type %T, wanted *aesgcm.AEAD", a)
			}
			decrypted, err := a.Decrypt(testCase.ciphertext, nil)
			if err != nil {
				t.Fatalf("a.Decrypt(testCase.ciphertext, nil) err = %v, want nil", err)
			}
			if !bytes.Equal(decrypted, testCase.wantPlaintext) {
				t.Errorf("a.Decrypt(testCase.ciphertext, nil) = %v, want %v", decrypted, testCase.wantPlaintext)
			}
		})
	}
}

func TestPrimitiveCreatorInvalidParameters(t *testing.T) {
	config, err := config.New()
	if err != nil {
		t.Fatalf("config.New() err = %v, want nil", err)
	}
	if err := aesgcm.RegisterPrimitiveConstructor(config, internalapi.Token{}); err != nil {
		t.Fatalf("aesgcm.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	for _, variant := range []aesgcm.Variant{aesgcm.VariantTink, aesgcm.VariantCrunchy, aesgcm.VariantNoPrefix} {
		// Key allows keySize in {16, 24, 32}, but the primitive wants {16, 32}.
		for _, keySize := range []uint32{24} {
			// Key allows ivSize > 0, but the primitive wants 12.
			for _, ivSize := range []int{1, 13} {
				// Key allows 12 <= tagSize <= 16, but the primitive wants 16.
				for _, tagSize := range []int{12, 15} {
					t.Run(fmt.Sprintf("variant: %v, keySize: %v, ivSize: %v, tagSize: %v", variant, keySize, ivSize, tagSize), func(t *testing.T) {
						opts := aesgcm.ParametersOpts{
							KeySizeInBytes: int(keySize),
							IVSizeInBytes:  ivSize,
							TagSizeInBytes: tagSize,
							Variant:        variant,
						}
						keyData := random.GetRandomBytes(keySize)
						idRequirement := uint32(0)
						if variant != aesgcm.VariantNoPrefix {
							idRequirement = 0x11223344
						}
						key := mustCreateKey(t, keyData, idRequirement, opts)
						if _, err := config.PrimitiveFromKey(key, internalapi.Token{}); err == nil {
							t.Errorf("config.PrimitiveFromKey(testCase.key, internalapi.Token{}) err = nil, want error")
						}
					})
				}
			}
		}
	}
}

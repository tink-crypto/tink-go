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

package xaesgcm_test

import (
	"bytes"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/xaesgcm"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
)

const (
	ivSize  = 12
	tagSize = 16
)

type testVector struct {
	name           string
	keyBytes       []byte
	nonce          []byte
	associatedData []byte
	plaintext      []byte
	ciphertext     []byte
	saltSize       int
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", s, err)
	}
	return b
}

// Test vectors from
// https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md#test-vectors.
func testVectors(t *testing.T) []testVector {
	return []testVector{
		{
			name:           "test_vector_1",
			keyBytes:       mustHexDecode(t, "0101010101010101010101010101010101010101010101010101010101010101"),
			nonce:          []byte("ABCDEFGHIJKLMNOPQRSTUVWX"),
			associatedData: []byte(""),
			plaintext:      []byte("XAES-256-GCM"),
			ciphertext:     mustHexDecode(t, "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"),
			saltSize:       12,
		},
		{
			name:           "test_vector_2",
			keyBytes:       mustHexDecode(t, "0303030303030303030303030303030303030303030303030303030303030303"),
			nonce:          []byte("ABCDEFGHIJKLMNOPQRSTUVWX"),
			associatedData: []byte("c2sp.org/XAES-256-GCM"),
			plaintext:      []byte("XAES-256-GCM"),
			ciphertext:     mustHexDecode(t, "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d"),
			saltSize:       12,
		},
		// Generated from Tink C++.
		{
			name:           "test_vector_3",
			keyBytes:       mustHexDecode(t, "0202020202020202020202020202020202020202020202020202020202020202"),
			nonce:          mustHexDecode(t, "1836e1ba8e24f42f39fa06030310caa4bc08a2788b790e6c"),
			associatedData: []byte("c2sp.org/XAES-256-GCM"),
			plaintext:      []byte(""),
			ciphertext:     mustHexDecode(t, "376f92ec763e3b423b00fc05800376f8"),
			saltSize:       12,
		},
		{
			name:           "test_vector_4",
			keyBytes:       mustHexDecode(t, "0202020202020202020202020202020202020202020202020202020202020202"),
			nonce:          mustHexDecode(t, "2c34e2274b88436ca0b1af9d019c66b6b105bec8695b4a39"),
			associatedData: []byte("c2sp.org/XAES-256-GCM"),
			plaintext:      []byte(""),
			ciphertext:     mustHexDecode(t, "766c4912f981661689bca92b"),
			saltSize:       8,
		},
		{
			name:           "test_vector_5",
			keyBytes:       mustHexDecode(t, "0202020202020202020202020202020202020202020202020202020202020202"),
			nonce:          mustHexDecode(t, "91f4020fa0bb08fe642ca8049f76b661e149e9bbe5b1203b"),
			associatedData: []byte("c2sp.org/XAES-256-GCM"),
			plaintext:      []byte("XAES-256-GCM"),
			ciphertext:     mustHexDecode(t, "9c05ae5b0469db4d356e64b9a90efeda8c057cd02e5fbe2e"),
			saltSize:       8,
		},
		{
			name:           "test_vector_6",
			keyBytes:       mustHexDecode(t, "0202020202020202020202020202020202020202020202020202020202020202"),
			nonce:          mustHexDecode(t, "c03b16a4e8d3c50f0b422bb12d2424b5ac4e72e98a1e31ba"),
			associatedData: []byte(""),
			plaintext:      []byte("XAES-256-GCM"),
			ciphertext:     mustHexDecode(t, "61380655c9192133aabd199a9bc7b7c4bb5f835956899c9c"),
			saltSize:       8,
		},
		// Nil associated data or plaintext.
		{
			name:           "test_vector_7",
			keyBytes:       mustHexDecode(t, "0202020202020202020202020202020202020202020202020202020202020202"),
			nonce:          mustHexDecode(t, "1836e1ba8e24f42f39fa06030310caa4bc08a2788b790e6c"),
			associatedData: []byte("c2sp.org/XAES-256-GCM"),
			plaintext:      nil,
			ciphertext:     mustHexDecode(t, "376f92ec763e3b423b00fc05800376f8"),
			saltSize:       12,
		},
		{
			name:           "test_vector_8",
			keyBytes:       mustHexDecode(t, "0202020202020202020202020202020202020202020202020202020202020202"),
			nonce:          mustHexDecode(t, "c03b16a4e8d3c50f0b422bb12d2424b5ac4e72e98a1e31ba"),
			associatedData: nil,
			plaintext:      []byte("XAES-256-GCM"),
			ciphertext:     mustHexDecode(t, "61380655c9192133aabd199a9bc7b7c4bb5f835956899c9c"),
			saltSize:       8,
		},
	}
}

func TestAEADTestVectors(t *testing.T) {
	for _, tc := range testVectors(t) {
		t.Run(tc.name, func(t *testing.T) {
			params, err := xaesgcm.NewParameters(xaesgcm.VariantNoPrefix, tc.saltSize)
			if err != nil {
				t.Fatalf("xaesgcm.NewParameters(%v, %v) err = %v, want nil", xaesgcm.VariantNoPrefix, tc.saltSize, err)
			}
			key, err := xaesgcm.NewKey(secretdata.NewBytesFromData(tc.keyBytes, testonlyinsecuresecretdataaccess.Token()), 0x00, params)
			if err != nil {
				t.Fatalf("xaesgcm.NewKey(%v, %v, %v) err = %v, want nil", tc.keyBytes, 0x00, params, err)
			}
			aead, err := xaesgcm.NewAEAD(key, internalapi.Token{})
			if err != nil {
				t.Fatalf("xaesgcm.NewAEAD(%v, %v) err = %v, want nil", key, internalapi.Token{}, err)
			}
			ciphertext, err := aead.Encrypt(tc.plaintext, tc.associatedData)
			if err != nil {
				t.Fatalf("aead.Encrypt(%v, %v) err = %v, want nil", tc.plaintext, tc.associatedData, err)
			}
			plaintext, err := aead.Decrypt(ciphertext, tc.associatedData)
			if err != nil {
				t.Fatalf("aead.Decrypt(%v, %v) err = %v, want nil", ciphertext, tc.associatedData, err)
			}
			if !bytes.Equal(plaintext, tc.plaintext) {
				t.Errorf("aead.Decrypt(%v, %v) = %v, want %v", ciphertext, tc.associatedData, plaintext, tc.plaintext)
			}

			// Decrypt known test vector.
			testCiphertext := slices.Concat(tc.nonce, tc.ciphertext)
			plaintext2, err := aead.Decrypt(testCiphertext, tc.associatedData)
			if err != nil {
				t.Fatalf("aead.Decrypt(%v, %v) err = %v, want nil", testCiphertext, tc.associatedData, err)
			}
			if !bytes.Equal(plaintext2, tc.plaintext) {
				t.Errorf("aead.Decrypt(%v, %v) = %v, want %v", testCiphertext, tc.associatedData, plaintext2, tc.plaintext)
			}
		})
	}
}

func TestAEADEncryptAndDecrypt(t *testing.T) {
	for _, tc := range []struct {
		name             string
		keyBytes         []byte
		saltSize         int
		variant          xaesgcm.Variant
		idRequirement    uint32
		wantOutputPrefix []byte
	}{
		{
			name:             "Tink, 8 bytes salt",
			keyBytes:         []byte("01010101010101010101010101010101"),
			saltSize:         8,
			variant:          xaesgcm.VariantTink,
			idRequirement:    0x11223344,
			wantOutputPrefix: []byte{0x01, 0x11, 0x22, 0x33, 0x44},
		},
		{
			name:             "NoPrefix, 8 bytes salt",
			keyBytes:         []byte("01010101010101010101010101010101"),
			saltSize:         8,
			variant:          xaesgcm.VariantNoPrefix,
			idRequirement:    0x00,
			wantOutputPrefix: []byte{},
		},
		{
			name:             "Tink, 12 bytes salt",
			keyBytes:         []byte("01010101010101010101010101010101"),
			saltSize:         12,
			variant:          xaesgcm.VariantTink,
			idRequirement:    0x11223344,
			wantOutputPrefix: []byte{0x01, 0x11, 0x22, 0x33, 0x44},
		},
		{
			name:             "NoPrefix, 12 bytes salt",
			keyBytes:         []byte("01010101010101010101010101010101"),
			saltSize:         12,
			variant:          xaesgcm.VariantNoPrefix,
			idRequirement:    0x00,
			wantOutputPrefix: []byte{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := xaesgcm.NewParameters(tc.variant, tc.saltSize)
			if err != nil {
				t.Fatalf("xaesgcm.NewParameters(%v, %v) err = %v, want nil", tc.variant, tc.saltSize, err)
			}
			key, err := xaesgcm.NewKey(secretdata.NewBytesFromData(tc.keyBytes, testonlyinsecuresecretdataaccess.Token()), tc.idRequirement, params)
			if err != nil {
				t.Fatalf("xaesgcm.NewKey(%v, %v, %v) err = %v, want nil", tc.keyBytes, tc.idRequirement, params, err)
			}
			aead, err := xaesgcm.NewAEAD(key, internalapi.Token{})
			if err != nil {
				t.Fatalf("xaesgcm.NewAEAD(%v, %v) err = %v, want nil", key, internalapi.Token{}, err)
			}

			plaintext := random.GetRandomBytes(4096)
			aad := []byte("aad")

			ciphertext, err := aead.Encrypt(plaintext, aad)
			if err != nil {
				t.Fatalf("aead.Encrypt(%v, %v) err = %v, want nil", plaintext, aad, err)
			}

			// Check the ciphertext length.
			if got, want := len(ciphertext), len(tc.wantOutputPrefix)+params.SaltSizeInBytes()+len(plaintext)+ivSize+tagSize; want != got {
				t.Errorf("ciphertext has wrong length: want %d, got %d", want, got)
			}
			// Check the prefix.
			if !bytes.Equal(ciphertext[:len(tc.wantOutputPrefix)], tc.wantOutputPrefix) {
				t.Errorf("ciphertext prefix does not match: got %v, want %v", ciphertext[:len(tc.wantOutputPrefix)], tc.wantOutputPrefix)
			}

			decrypted, err := aead.Decrypt(ciphertext, aad)
			if err != nil {
				t.Fatalf("aead.Decrypt(%v, %v) err = %v, want nil", ciphertext, aad, err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("aead.Decrypt(%v, %v) = %v, want %v", ciphertext, aad, decrypted, plaintext)
			}
		})
	}
}

func TestAEADDecryptModifiedCiphertext(t *testing.T) {
	const ivSize = 12
	const tagSize = 16
	for _, variant := range []xaesgcm.Variant{xaesgcm.VariantNoPrefix, xaesgcm.VariantTink} {
		t.Run(variant.String(), func(t *testing.T) {
			params, err := xaesgcm.NewParameters(xaesgcm.VariantNoPrefix, 12)
			if err != nil {
				t.Fatalf("xaesgcm.NewParameters(%v, %v) err = %v, want nil", xaesgcm.VariantNoPrefix, 12, err)
			}
			keyBytes := secretdata.NewBytesFromData([]byte("01010101010101010101010101010101"), testonlyinsecuresecretdataaccess.Token())
			key, err := xaesgcm.NewKey(keyBytes, 0x00, params)
			if err != nil {
				t.Fatalf("xaesgcm.NewKey(%x, %v, %v) err = %v, want nil", keyBytes.Data(testonlyinsecuresecretdataaccess.Token()), 0x00, params, err)
			}
			a, err := xaesgcm.NewAEAD(key, internalapi.Token{})
			if err != nil {
				t.Fatalf("xaesgcm.NewAEAD(%v, %v) err = %v, want nil", key, internalapi.Token{}, err)
			}

			message := []byte("Some data to encrypt.")
			associatedData := []byte("Some data to authenticate.")
			ciphertext, err := a.Encrypt(message, associatedData)
			if err != nil {
				t.Fatalf("encryption failed, error: %v", err)
			}

			prefix := ciphertext[:len(key.OutputPrefix())]
			salt := ciphertext[len(key.OutputPrefix()) : len(key.OutputPrefix())+12]
			iv := ciphertext[len(key.OutputPrefix())+len(salt) : len(key.OutputPrefix())+len(salt)+ivSize]
			ct := ciphertext[len(key.OutputPrefix())+len(salt)+ivSize : len(key.OutputPrefix())+len(salt)+ivSize+len(message)]
			tag := ciphertext[len(key.OutputPrefix())+len(salt)+ivSize+len(message):]

			// Invalid prefix.
			if len(prefix) > 0 {
				wrongPrefix := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
				if _, err := a.Decrypt(slices.Concat(wrongPrefix, salt, iv, ct, tag), associatedData); err == nil {
					t.Errorf("a.Decrypt() err = nil, want error")
				}
			}

			// Invalid salt.
			wrongSalt := bytes.Clone(salt)
			wrongSalt[0] ^= 1
			if _, err := a.Decrypt(slices.Concat(prefix, wrongSalt, iv, ct, tag), associatedData); err == nil {
				t.Errorf("a.Decrypt() err = nil, want error")
			}

			// Invalid IV.
			wrongIV := bytes.Clone(iv)
			wrongIV[0] ^= 1
			if _, err := a.Decrypt(slices.Concat(prefix, salt, wrongIV, ct, tag), associatedData); err == nil {
				t.Errorf("a.Decrypt() err = nil, want error")
			}

			// Invalid ciphertext.
			wrongCiphertext := bytes.Clone(ciphertext)
			wrongCiphertext[0] ^= 1
			if _, err := a.Decrypt(slices.Concat(prefix, salt, iv, wrongCiphertext, tag), associatedData); err == nil {
				t.Errorf("a.Decrypt() err = nil, want error")
			}

			// Invalid tag.
			wrongTag := bytes.Clone(tag)
			wrongTag[0] ^= 1
			if _, err := a.Decrypt(slices.Concat(prefix, salt, iv, ct, wrongTag), associatedData); err == nil {
				t.Errorf("a.Decrypt() err = nil, want error")
			}

			// Truncate the ciphertext.
			for i := 1; i < len(ciphertext); i++ {
				if _, err := a.Decrypt(ciphertext[:i], associatedData); err == nil {
					t.Errorf("a.Decrypt(ciphertext[:%d], associatedData) err = nil, want error", i)
				}
			}

			// Invalid associated data.
			if _, err := a.Decrypt(ciphertext, []byte("invalidAssociatedData")); err == nil {
				t.Errorf("a.Decrypt() err = nil, want error")
			}
		})
	}
}

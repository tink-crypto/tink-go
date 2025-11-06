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

package aesgcmsiv

import (
	"bytes"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
)

func TestEncryptDecrypt(t *testing.T) {
	for _, tc := range []struct {
		name           string
		keySizeInBytes int
		variant        Variant
		idRequirement  uint32
		wantPrefix     []byte
	}{
		{
			name:           "AES256-GCM-SIV-TINK",
			keySizeInBytes: 32,
			variant:        VariantTink,
			idRequirement:  0x11223344,
			wantPrefix:     []byte{cryptofmt.TinkStartByte, 0x11, 0x22, 0x33, 0x44},
		},
		{
			name:           "AES256-GCM-SIV-CRUNCHY",
			keySizeInBytes: 32,
			variant:        VariantCrunchy,
			idRequirement:  0x11223344,
			wantPrefix:     []byte{cryptofmt.LegacyStartByte, 0x11, 0x22, 0x33, 0x44},
		},
		{
			name:           "AES128-GCM-SIV-TINK",
			keySizeInBytes: 16,
			variant:        VariantTink,
			idRequirement:  0x11223344,
			wantPrefix:     []byte{cryptofmt.TinkStartByte, 0x11, 0x22, 0x33, 0x44},
		},
		{
			name:           "AES128-GCM-SIV-CRUNCHY",
			keySizeInBytes: 16,
			variant:        VariantCrunchy,
			idRequirement:  0x11223344,
			wantPrefix:     []byte{cryptofmt.LegacyStartByte, 0x11, 0x22, 0x33, 0x44},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := NewParameters(tc.keySizeInBytes, tc.variant)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v) err = %v, want nil", tc.keySizeInBytes, tc.variant, err)
			}
			keyBytes, err := secretdata.NewBytesFromRand(uint32(tc.keySizeInBytes))
			if err != nil {
				t.Fatalf("secretdata.NewBytesFromRand(%v) err = %v, want nil", tc.keySizeInBytes, err)
			}
			key, err := NewKey(keyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("NewKey() err = %v, want nil", err)
			}
			aead, err := newAEAD(key)
			if err != nil {
				t.Fatalf("newAEAD() err = %v, want nil", err)
			}
			plaintext := []byte("plaintext")
			associatedData := []byte("associatedData")
			ciphertext, err := aead.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("aead.Encrypt(%v, %v) err = %v, want nil", plaintext, associatedData, err)
			}
			if got, want := ciphertext[:len(tc.wantPrefix)], tc.wantPrefix; !bytes.Equal(got, want) {
				t.Errorf("ciphertext has wrong prefix: got %x, want %x", got, want)
			}
			decrypted, err := aead.Decrypt(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("aead.Decrypt(%x, %x) err = %v, want nil", ciphertext, associatedData, err)
			}
			if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
				t.Errorf("aead.Decrypt(%x, %x) = %x, want %x", ciphertext, associatedData, got, want)
			}
		})
	}
}

func TestDecryptFailsWithWrongPrefix(t *testing.T) {
	for _, tc := range []struct {
		name           string
		keySizeInBytes int
		variant        Variant
	}{
		{
			name:           "AES256-GCM-SIV-TINK",
			keySizeInBytes: 32,
			variant:        VariantTink,
		},
		{
			name:           "AES256-GCM-SIV-CRUNCHY",
			keySizeInBytes: 32,
			variant:        VariantCrunchy,
		},
		{
			name:           "AES128-GCM-SIV-TINK",
			keySizeInBytes: 16,
			variant:        VariantTink,
		},
		{
			name:           "AES128-GCM-SIV-CRUNCHY",
			keySizeInBytes: 16,
			variant:        VariantCrunchy,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := NewParameters(tc.keySizeInBytes, tc.variant)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v) err = %v, want nil", tc.keySizeInBytes, tc.variant, err)
			}
			keyBytes, err := secretdata.NewBytesFromRand(uint32(tc.keySizeInBytes))
			if err != nil {
				t.Fatalf("secretdata.NewBytesFromRand(%v) err = %v, want nil", tc.keySizeInBytes, err)
			}
			key, err := NewKey(keyBytes, 0x11223344, params)
			if err != nil {
				t.Fatalf("NewKey() err = %v, want nil", err)
			}
			aead, err := newAEAD(key)
			if err != nil {
				t.Fatalf("newAEAD() err = %v, want nil", err)
			}
			plaintext := []byte("plaintext")
			associatedData := []byte("associatedData")
			ciphertext, err := aead.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("aead.Encrypt(%v, %v) err = %v, want nil", plaintext, associatedData, err)
			}

			// Modify the prefix.
			prefix := ciphertext[:len(key.OutputPrefix())]
			for i := 0; i < len(prefix); i++ {
				modifiedPrefix := slices.Clone(prefix)
				for j := 0; j < 8; j++ {
					modifiedPrefix[i] = byte(modifiedPrefix[i] ^ (1 << uint32(j)))
					s := slices.Concat(modifiedPrefix, ciphertext[len(key.OutputPrefix()):])
					if _, err := aead.Decrypt(s, associatedData); err == nil {
						t.Errorf("aead.Decrypt(%x, %x) err = nil, want error", s, associatedData)
					}
				}
			}
		})
	}
}

func mustDecodeHex(t *testing.T, hexStr string) []byte {
	t.Helper()
	x, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex.DecodeString(%v) err = %v, want nil", hexStr, err)
	}
	return x
}

func TestDecryptCorrectness(t *testing.T) {
	// Test vectors from
	// https://github.com/C2SP/wycheproof/blob/b063b4aedae951c69df014cd25fa6d69ae9e8cb9/testvectors/aes_gcm_siv_test.json#L58
	key := secretdata.NewBytesFromData(mustDecodeHex(t, "01000000000000000000000000000000"), testonlyinsecuresecretdataaccess.Token())
	iv := "030000000000000000000000"
	msg := "01000000000000000000000000000000"
	aad := ""
	ct := "743f7c8077ab25f8624e2e948579cf77"
	tag := "303aaf90f6fe21199c6068577437a0c4"
	for _, tc := range []struct {
		name           string
		variant        Variant
		idRequirement  uint32
		key            secretdata.Bytes
		plaintext      []byte
		associatedData []byte
		ciphertext     []byte
	}{
		{
			name:           "TINK",
			variant:        VariantTink,
			idRequirement:  0x11223344,
			key:            key,
			plaintext:      mustDecodeHex(t, msg),
			associatedData: mustDecodeHex(t, aad),
			ciphertext:     mustDecodeHex(t, "0111223344"+iv+ct+tag),
		},
		{
			name:           "CRUNCHY",
			variant:        VariantCrunchy,
			idRequirement:  0x11223344,
			key:            key,
			plaintext:      mustDecodeHex(t, msg),
			associatedData: mustDecodeHex(t, aad),
			ciphertext:     mustDecodeHex(t, "0011223344"+iv+ct+tag),
		},
		{
			name:           "NO_PREFIX",
			variant:        VariantNoPrefix,
			idRequirement:  0,
			key:            key,
			plaintext:      mustDecodeHex(t, msg),
			associatedData: mustDecodeHex(t, aad),
			ciphertext:     mustDecodeHex(t, iv+ct+tag),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := NewParameters(key.Len(), tc.variant)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v) err = %v, want nil", tc.key.Len(), tc.variant, err)
			}
			key, err := NewKey(tc.key, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("NewKey() err = %v, want nil", err)
			}
			aead, err := newAEAD(key)
			if err != nil {
				t.Fatalf("newAEAD() err = %v, want nil", err)
			}
			decrypted, err := aead.Decrypt(tc.ciphertext, tc.associatedData)
			if err != nil {
				t.Fatalf("aead.Decrypt(%x, %x) err = %v, want nil", tc.ciphertext, tc.associatedData, err)
			}
			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Errorf("aead.Decrypt(%x, %x) = %v, want %v", tc.ciphertext, tc.associatedData, decrypted, tc.plaintext)
			}
		})
	}
}

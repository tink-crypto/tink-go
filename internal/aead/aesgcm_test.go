// Copyright 2022 Google LLC
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

package aead_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/tink-crypto/tink-go/v2/internal/aead"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
)

func TestNewAESGCMCipherInvalidInputs(t *testing.T) {
	for _, keySize := range []uint32{15, 33} {
		key := random.GetRandomBytes(keySize)
		if _, err := aead.NewAESGCMCipher(key); err == nil {
			t.Errorf("NewAESGCMCipher(%v) err = nil, want error", key)
		}
	}
}

func hexDecode(t *testing.T, hexStr string) []byte {
	t.Helper()
	x, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex.DecodeString(%v) err = %v, want nil", hexStr, err)
	}
	return x
}

func TestNewAESGCMCipherEncryptDecrypt(t *testing.T) {
	for _, keySize := range []uint32{16, 32} {
		key := random.GetRandomBytes(keySize)
		c, err := aead.NewAESGCMCipher(key)
		if err != nil {
			t.Errorf("NewAESGCMCipher(%v) err = %v, want nil", key, err)
		}
		ad := random.GetRandomBytes(5)
		pt := random.GetRandomBytes(100)
		iv := random.GetRandomBytes(aead.AESGCMIVSize)
		ct := c.Seal(nil, iv, pt, ad)
		decrypted, err := c.Open(nil, iv, ct, ad)
		if err != nil {
			t.Errorf("Open(%v) err = %v, want nil", ct, err)
		}
		if !bytes.Equal(pt, decrypted) {
			t.Errorf("Open(%v) = %v, want %v", ct, decrypted, pt)
		}
	}
}

func TestNewAESGCMCipherDecryptWorks(t *testing.T) {
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
	for _, tc := range []struct {
		name       string
		key        []byte
		ciphertext []byte
		want       []byte
	}{
		{
			name:       "128-bit key",
			key:        key1,
			ciphertext: ciphertext1,
			want:       wantMessage1,
		},
		{
			name:       "256-bit key",
			key:        key2,
			ciphertext: ciphertext2,
			want:       wantMessage2,
		},
	} {
		c, err := aead.NewAESGCMCipher(tc.key)
		if err != nil {
			t.Errorf("NewAESGCMCipher(%v) err = %v, want nil", tc.key, err)
		}
		iv := tc.ciphertext[:aead.AESGCMIVSize]
		got, err := c.Open(nil, iv, tc.ciphertext[aead.AESGCMIVSize:], nil)
		if err != nil {
			t.Errorf("Open(%v) err = %v, want nil", tc.ciphertext, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("Open(%v) = %v, want %v", tc.ciphertext, got, tc.want)
		}
	}
}

func TestCheckPlaintextSize(t *testing.T) {
	for _, plaintextSize := range []uint64{16, 1 << 24} {
		if err := aead.CheckPlaintextSize(plaintextSize); err != nil {
			t.Errorf("aead.CheckPlaintextSize(%v) err = %v, want nil", plaintextSize, err)
		}
	}
	if err := aead.CheckPlaintextSize(1 << 60); err == nil {
		t.Errorf("aead.CheckPlaintextSize(%v) err = nil, want error", 1<<60)
	}
}

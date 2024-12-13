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

package aead_test

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/internal/aead"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
)

func TestNewAESCTR(t *testing.T) {
	key := make([]byte, 64)

	// Test various key sizes with a fixed IV size.
	for i := 0; i < 64; i++ {
		k := key[:i]
		_, err := aead.NewAESCTR(k, subtle.AESCTRMinIVSize)
		switch len(k) {
		case 16:
			fallthrough
		case 32:
			// Valid key sizes.
			if err != nil {
				t.Errorf("want: valid cipher (key size=%d), got: error %v", len(k), err)
			}
		default:
			// Invalid key sizes.
			if !strings.Contains(err.Error(), "aes_ctr: invalid AES key size; want 16 or 32") {
				t.Errorf("wrong error message; want a string starting with \"aes_ctr: invalid AES key size; want 16 or 32\", got %v", err)
			}
		}
	}

	// Test different IV sizes with a fixed key.
	for i := 0; i < 64; i++ {
		k := key[:16]
		_, err := aead.NewAESCTR(k, i)
		if i >= subtle.AESCTRMinIVSize && i <= aes.BlockSize {
			if err != nil {
				t.Errorf("want: valid cipher (IV size=%d), got: error %v", i, err)
			}
			continue
		}
		if !strings.Contains(err.Error(), "aes_ctr: invalid IV size:") {
			t.Errorf("want: error invalid IV size, got: %v", err)
		}
	}
}

func TestNistTestVector(t *testing.T) {
	// NIST SP 800-38A pp 55
	key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	if err != nil {
		t.Fatalf("failed to hex decode key, error: %v", err)
	}

	// NIST IV
	iv := "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
	// NIST ciphertext blocks
	c := "874d6191b620e3261bef6864990db6ce" +
		"9806f66b7970fdff8617187bb9fffdff" +
		"5ae4df3edbd5d35e5b4f09020db03eab" +
		"1e031dda2fbe03d1792170a0f3009cee"
	ciphertext, err := hex.DecodeString(iv + c)
	if err != nil {
		t.Fatalf("failed to hex decode ciphertext, error: %v", err)
	}

	// NIST plaintext blocks
	p := "6bc1bee22e409f96e93d7e117393172a" +
		"ae2d8a571e03ac9c9eb76fac45af8e51" +
		"30c81c46a35ce411e5fbc1191a0a52ef" +
		"f69f2445df4f9b17ad2b417be66c3710"
	message, err := hex.DecodeString(p)
	if err != nil {
		t.Fatalf("failed to hex decode message, error: %v", err)
	}

	stream, err := aead.NewAESCTR(key, len(iv)/2)
	if err != nil {
		t.Fatalf("failed to create AESCTR instance, error: %v", err)
	}

	plaintext, err := stream.Decrypt(nil, ciphertext)
	if err != nil {
		t.Errorf("failed to decrypt ciphertext, error: %v", err)
	}

	if !bytes.Equal(plaintext, message) {
		t.Errorf("plaintext doesn't match message")
	}
}

func TestMultipleEncrypt(t *testing.T) {
	key := random.GetRandomBytes(16)

	stream, err := aead.NewAESCTR(key, subtle.AESCTRMinIVSize)
	if err != nil {
		t.Fatalf("failed to create AESCTR instance, error: %v", err)
	}

	plaintext := []byte("Some data to encrypt.")
	ct1, err := stream.Encrypt(nil, plaintext)
	if err != nil {
		t.Errorf("encryption failed, error: %v", err)
	}
	ct2, err := stream.Encrypt(nil, plaintext)
	if err != nil {
		t.Errorf("encryption failed, error: %v", err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Error("the two ciphertexts cannot be equal")
	}
	// Encrypt 100 times and verify that the result is 100 different ciphertexts.
	ciphertexts := map[string]bool{}
	for i := 0; i < 100; i++ {
		c, err := stream.Encrypt(nil, plaintext)
		if err != nil {
			t.Errorf("encryption failed for iteration %d, error: %v", i, err)
		}
		ciphertexts[string(c)] = true
	}

	if len(ciphertexts) != 100 {
		t.Errorf("got: %d ciphertexts, want: 100 ciphertexts", len(ciphertexts))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal("failed to hex decode key")
	}

	stream, err := aead.NewAESCTR(key, subtle.AESCTRMinIVSize)
	if err != nil {
		t.Fatalf("failed to get AESCTR instance, error: %v", err)
	}

	message := []byte("Some data to encrypt.")
	ciphertext, err := stream.Encrypt(nil, message)
	if err != nil {
		t.Errorf("encryption failed, error: %v", err)
	}

	if len(ciphertext) != len(message)+subtle.AESCTRMinIVSize {
		t.Errorf("ciphertext incorrect size, got: %d, want: %d", len(ciphertext), len(message)+subtle.AESCTRMinIVSize)
	}

	plaintext, err := stream.Decrypt(nil, ciphertext)
	if err != nil {
		t.Errorf("decryption failed, error: %v", err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Errorf("decryption result mismatch, got: %v, want: %v", plaintext, message)
	}
}

func TestEncryptRandomMessage(t *testing.T) {
	key := random.GetRandomBytes(16)

	stream, err := aead.NewAESCTR(key, subtle.AESCTRMinIVSize)
	if err != nil {
		t.Errorf("failed to instantiate AESCTR, error: %v", err)
	}

	for i := 0; i < 256; i++ {
		message := random.GetRandomBytes(uint32(i))
		ciphertext, err := stream.Encrypt(nil, message)
		if err != nil {
			t.Errorf("encryption failed at iteration %d, error: %v", i, err)
		}
		if len(ciphertext) != len(message)+subtle.AESCTRMinIVSize {
			t.Errorf("invalid ciphertext length for i = %d", i)
		}

		plaintext, err := stream.Decrypt(nil, ciphertext)
		if err != nil {
			t.Errorf("decryption failed at iteration %d, error: %v", i, err)
		}

		if !bytes.Equal(plaintext, message) {
			t.Errorf("plaintext doesn't match message, i = %d", i)
		}
	}
}

func TestEncryptRandomKeyAndMessage(t *testing.T) {
	for i := 0; i < 256; i++ {
		key := random.GetRandomBytes(16)

		stream, err := aead.NewAESCTR(key, subtle.AESCTRMinIVSize)
		if err != nil {
			t.Errorf("failed to instantiate AESCTR, error: %v", err)
		}

		message := random.GetRandomBytes(uint32(i))
		ciphertext, err := stream.Encrypt(nil, message)
		if err != nil {
			t.Errorf("encryption failed at iteration %d, error: %v", i, err)
		}
		if len(ciphertext) != len(message)+subtle.AESCTRMinIVSize {
			t.Errorf("invalid ciphertext length for i = %d", i)
		}

		plaintext, err := stream.Decrypt(nil, ciphertext)
		if err != nil {
			t.Errorf("decryption failed at iteration %d, error: %v", i, err)
		}

		if !bytes.Equal(plaintext, message) {
			t.Errorf("plaintext doesn't match message, i = %d", i)
		}
	}
}

func TestEncryptDecryptWithDestinationBuffer(t *testing.T) {
	aesCTR, err := aead.NewAESCTR(random.GetRandomBytes(16), subtle.AESCTRMinIVSize)
	if err != nil {
		t.Fatalf("NewAESCTR failed, error: %v, want nil", err)
	}
	pt := random.GetRandomBytes(16)
	ct := make([]byte, len(pt)+subtle.AESCTRMinIVSize)
	if _, err = aesCTR.Encrypt(ct, pt); err != nil {
		t.Fatalf("Encrypt failed, error: %v, want nil", err)
	}
	rpt := make([]byte, len(pt))
	if _, err := aesCTR.Decrypt(rpt, ct); err != nil {
		t.Fatalf("Decrypt failed, error: %v, want nil", err)
	}
	if !bytes.Equal(pt, rpt) {
		t.Errorf("recovered plaintext doesn't match original plaintext, got: %v, want: %v", hex.EncodeToString(pt), hex.EncodeToString(rpt))
	}
}

func TestEncryptDecryptWithInvalidDestinationBufferFails(t *testing.T) {
	aesCTR, err := aead.NewAESCTR(random.GetRandomBytes(16), subtle.AESCTRMinIVSize)
	if err != nil {
		t.Fatalf("NewAESCTR failed, error: %v, want nil", err)
	}
	pt := random.GetRandomBytes(16)
	ct := make([]byte, len(pt)+subtle.AESCTRMinIVSize)
	if _, err = aesCTR.Encrypt(ct[len(ct)-1:], pt); err == nil {
		t.Fatal("Encrypt() succeeded, want error", err)
	}
	rpt := make([]byte, len(pt)-1)
	if _, err := aesCTR.Decrypt(rpt, ct); err == nil {
		t.Fatal("Decrypt() succeeded, want error", err)
	}
}

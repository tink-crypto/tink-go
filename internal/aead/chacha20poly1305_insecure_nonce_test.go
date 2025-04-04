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
	"fmt"
	"math/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"github.com/tink-crypto/tink-go/v2/internal/aead"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil"
)

// TODO(b/201070904): Improve tests and rename aad to ad.

func TestChaCha20Poly1305EncryptDecrypt(t *testing.T) {
	for i, test := range chaCha20Poly1305Tests {
		key, err := hex.DecodeString(test.key)
		if err != nil {
			t.Fatalf("hex.DecodeString(test.key) err = %q, want nil", err)
		}
		pt, err := hex.DecodeString(test.plaintext)
		if err != nil {
			t.Fatalf("hex.DecodeString(test.plaintext) err = %q, want nil", err)
		}
		aad, err := hex.DecodeString(test.aad)
		if err != nil {
			t.Fatalf("hex.DecodeString(test.aad) err = %q, want nil", err)
		}
		nonce, err := hex.DecodeString(test.nonce)
		if err != nil {
			t.Fatalf("hex.DecodeString(test.nonce) err = %q, want nil", err)
		}
		ct, err := hex.DecodeString(test.out)
		if err != nil {
			t.Fatalf("hex.DecodeString(test.out) err = %q, want nil", err)
		}

		ca, err := aead.NewChaCha20Poly1305InsecureNonce(key)
		if err != nil {
			t.Errorf("#%d, aead.NewChaCha20Poly1305InsecureNonce(key) err = %q", i, err)
			continue
		}

		ciphertextFromNil, err := ca.Encrypt(nil, nonce, pt, aad)
		if err != nil {
			t.Errorf("#%d, ca.Encrypt(nil, nonce, pt, aad) err = %q", i, err)
			continue
		}
		var dst []byte
		ciphertextFromDst, err := ca.Encrypt(dst, nonce, pt, aad)
		if err != nil {
			t.Errorf("#%d, ca.Encrypt(dst, nonce, pt, aad) err = %q", i, err)
			continue
		}
		if !bytes.Equal(ciphertextFromNil, ciphertextFromDst) {
			t.Errorf("#%d, ciphertextFromNil = %x, ciphertextFromDst = %x", i, ciphertextFromNil, ciphertextFromDst)
			continue
		}

		if got, err := ca.Decrypt(nonce, ct, aad); err != nil {
			t.Errorf("#%d, unexpected decryption error: %s", i, err)
			continue
		} else if !bytes.Equal(pt, got) {
			t.Errorf("#%d, plaintext's don't match: got %x vs %x", i, got, pt)
			continue
		}
	}
}

func TestChaCha20Poly1305EmptyAssociatedData(t *testing.T) {
	key := random.GetRandomBytes(chacha20poly1305.KeySize)
	ca, err := aead.NewChaCha20Poly1305InsecureNonce(key)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 75; i++ {
		pt := random.GetRandomBytes(uint32(i))

		emptyAADs := [][]byte{[]byte{}, nil}
		for _, encAAD := range emptyAADs {
			nonce := random.GetRandomBytes(chacha20poly1305.NonceSize)
			ct, err := ca.Encrypt(nil, nonce, pt, encAAD)
			if err != nil {
				t.Errorf("Encrypt() err = %v, want nil", err)
				continue
			}

			for _, decAAD := range emptyAADs {
				got, err := ca.Decrypt(nonce, ct, decAAD)
				if err != nil {
					t.Errorf("Decrypt() err = %v, want nil", err)
				}
				if want := pt; !bytes.Equal(want, got) {
					t.Errorf("Decrypt() = %x, want %x", got, want)
				}
			}

			badAAD := []byte{1, 2, 3}
			if _, err := ca.Decrypt(nonce, ct, badAAD); err == nil {
				t.Errorf("Decrypt() err = nil, want error")
			}
		}
	}
}

func TestChaCha20Poly1305LongMessages(t *testing.T) {
	dataSize := uint32(16)
	// Encrypts and decrypts messages of size <= 8192.
	for dataSize <= 1<<24 {
		pt := random.GetRandomBytes(dataSize)
		aad := random.GetRandomBytes(dataSize / 3)
		key := random.GetRandomBytes(chacha20poly1305.KeySize)

		ca, err := aead.NewChaCha20Poly1305InsecureNonce(key)
		if err != nil {
			t.Fatal(err)
		}

		nonce := random.GetRandomBytes(chacha20poly1305.NonceSize)
		ct, err := ca.Encrypt(nil, nonce, pt, aad)
		if err != nil {
			t.Errorf("Encrypt(%x, %x) failed", pt, aad)
			continue
		}

		if got, err := ca.Decrypt(nonce, ct, aad); err != nil || !bytes.Equal(pt, got) {
			t.Errorf("Decrypt(Encrypt(pt, %x)): plaintext's don't match: got %x vs %x; error: %v", aad, got, pt, err)
		}

		dataSize += 5 * dataSize / 11
	}
}

func TestChaCha20Poly1305ModifyCiphertext(t *testing.T) {
	for i, test := range chaCha20Poly1305Tests {
		key, err := hex.DecodeString(test.key)
		if err != nil {
			t.Fatalf("hex.DecodeString(test.key) err = %q, want nil", err)
		}
		pt, err := hex.DecodeString(test.plaintext)
		if err != nil {
			t.Fatalf("hex.DecodeString(test.plaintext) err = %q, want nil", err)
		}
		aad, err := hex.DecodeString(test.aad)
		if err != nil {
			t.Fatalf("hex.DecodeString(test.aad) err = %q, want nil", err)
		}

		ca, err := aead.NewChaCha20Poly1305InsecureNonce(key)
		if err != nil {
			t.Fatal(err)
		}

		nonce := random.GetRandomBytes(chacha20poly1305.NonceSize)
		ct, err := ca.Encrypt(nil, nonce, pt, aad)
		if err != nil {
			t.Errorf("#%d: Encrypt failed", i)
			continue
		}

		if len(aad) > 0 {
			alterAadIdx := rand.Intn(len(aad))
			aad[alterAadIdx] ^= 0x80
			if _, err := ca.Decrypt(nonce, ct, aad); err == nil {
				t.Errorf("#%d: Decrypt was successful after altering additional data", i)
				continue
			}
			aad[alterAadIdx] ^= 0x80
		}

		alterCtIdx := rand.Intn(len(ct))
		ct[alterCtIdx] ^= 0x80
		if _, err := ca.Decrypt(nonce, ct, aad); err == nil {
			t.Errorf("#%d: Decrypt was successful after altering ciphertext", i)
			continue
		}
		ct[alterCtIdx] ^= 0x80
	}
}

// This is a very simple test for the randomness of the nonce.
// The test simply checks that the multiple ciphertexts of the same message are distinct.
func TestChaCha20Poly1305RandomNonce(t *testing.T) {
	key := random.GetRandomBytes(chacha20poly1305.KeySize)
	ca, err := aead.NewChaCha20Poly1305InsecureNonce(key)
	if err != nil {
		t.Fatal(err)
	}

	cts := make(map[string]bool)
	pt, aad := []byte{}, []byte{}
	for i := 0; i < 1<<10; i++ {
		nonce := random.GetRandomBytes(chacha20poly1305.NonceSize)
		ct, err := ca.Encrypt(nil, nonce, pt, aad)
		ctHex := hex.EncodeToString(ct)
		if err != nil || cts[ctHex] {
			t.Errorf("TestRandomNonce failed: %v", err)
		} else {
			cts[ctHex] = true
		}
	}
}

func TestChaCha20Poly1305WycheproofCases(t *testing.T) {
	suite := new(AEADSuite)
	if err := testutil.PopulateSuite(suite, "chacha20_poly1305_test.json"); err != nil {
		t.Fatalf("failed populating suite: %s", err)
	}
	for _, group := range suite.TestGroups {
		if group.KeySize/8 != chacha20poly1305.KeySize {
			continue
		}
		if group.IVSize/8 != chacha20poly1305.NonceSize {
			continue
		}

		for _, test := range group.Tests {
			caseName := fmt.Sprintf("%s-%s:Case-%d", suite.Algorithm, group.Type, test.CaseID)
			t.Run(caseName, func(t *testing.T) { runChaCha20Poly1305WycheproofCase(t, test) })
		}
	}
}

func runChaCha20Poly1305WycheproofCase(t *testing.T, tc *AEADCase) {
	ca, err := aead.NewChaCha20Poly1305InsecureNonce(tc.Key)
	if err != nil {
		t.Fatalf("cannot create new instance of ChaCha20Poly1305: %s", err)
	}

	nonce := random.GetRandomBytes(chacha20poly1305.NonceSize)
	_, err = ca.Encrypt(nil, nonce, tc.Message, tc.AD)
	if err != nil {
		t.Fatalf("unexpected encryption error: %s", err)
	}

	var ct []byte
	ct = append(ct, tc.CT...)
	ct = append(ct, tc.Tag...)
	decrypted, err := ca.Decrypt(tc.IV, ct, tc.AD)
	if err != nil {
		if tc.Result == "valid" {
			t.Errorf("unexpected error: %s", err)
		}
	} else {
		if tc.Result == "invalid" {
			t.Error("decrypted invalid")
		}
		if !bytes.Equal(decrypted, tc.Message) {
			t.Error("incorrect decryption")
		}
	}
}

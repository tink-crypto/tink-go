// Copyright 2026 Google LLC
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

package keytest_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/keytest"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveregistry"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
)

var otherKey128Bits = []byte{
	0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
	0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
}

type keyTestCase struct {
	name     string
	variant  keytest.Variant
	keyID    uint32
	keyBytes []byte
}

func keyTestCases() []keyTestCase {
	return []keyTestCase{
		{
			name:     "TINK",
			variant:  keytest.VariantTink,
			keyID:    0x01020304,
			keyBytes: key128Bits,
		},
		{
			name:     "CRUNCHY",
			variant:  keytest.VariantCrunchy,
			keyID:    0x01020304,
			keyBytes: key128Bits,
		},
		{
			name:     "NO_PREFIX",
			variant:  keytest.VariantNoPrefix,
			keyID:    0,
			keyBytes: key128Bits,
		},
	}
}

func mustCreateKey(t *testing.T, variant keytest.Variant, keyID uint32, keyBytes []byte) *keytest.Key {
	t.Helper()
	params, err := keytest.NewParameters(variant)
	if err != nil {
		t.Fatalf("keytest.NewParameters(%v) err = %v, want nil", variant, err)
	}
	k, err := keytest.NewKey(secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}), keyID, params)
	if err != nil {
		t.Fatalf("keytest.NewKey(keyBytes, %v, %v) err = %v, want nil", keyID, params, err)
	}
	return k
}

func mustCreateAEAD(t *testing.T, k *keytest.Key) tink.AEAD {
	t.Helper()
	p, err := primitiveregistry.Primitive(k)
	if err != nil {
		t.Fatalf("primitiveregistry.Primitive(%v) err = %v, want nil", k, err)
	}
	a, ok := p.(tink.AEAD)
	if !ok {
		t.Fatalf("primitiveregistry.Primitive(%v) = %T, want tink.AEAD", k, p)
	}
	return a
}

func TestPrimitiveEncryptDecrypt(t *testing.T) {
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	for _, tc := range keyTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			k := mustCreateKey(t, tc.variant, tc.keyID, tc.keyBytes)
			a := mustCreateAEAD(t, k)

			ciphertext, err := a.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("a.Encrypt(%x, %x) err = %v, want nil", plaintext, associatedData, err)
			}
			prefix := k.OutputPrefix()
			if !bytes.HasPrefix(ciphertext, prefix) {
				t.Errorf("ciphertext = %x, want prefix %x", ciphertext, prefix)
			}
			got, err := a.Decrypt(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("a.Decrypt(ciphertext, %x) err = %v, want nil", associatedData, err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("a.Decrypt(ciphertext, %x) = %x, want %x", associatedData, got, plaintext)
			}

			// The payload after the prefix must be a valid DummyAEAD ciphertext.
			dummyAEAD := &testutil.DummyAEAD{Name: hex.EncodeToString(tc.keyBytes)}
			got, err = dummyAEAD.Decrypt(ciphertext[len(prefix):], associatedData)
			if err != nil {
				t.Fatalf("dummyAEAD.Decrypt(ciphertext[%d:], %x) err = %v, want nil", len(prefix), associatedData, err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("dummyAEAD.Decrypt(ciphertext[%d:], %x) = %x, want %x", len(prefix), associatedData, got, plaintext)
			}

			// A DummyAEAD ciphertext with the prefix prepended must decrypt.
			dummyCiphertext, err := dummyAEAD.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("dummyAEAD.Encrypt(%x, %x) err = %v, want nil", plaintext, associatedData, err)
			}
			got, err = a.Decrypt(append(k.OutputPrefix(), dummyCiphertext...), associatedData)
			if err != nil {
				t.Fatalf("a.Decrypt(prefix || dummyCiphertext, %x) err = %v, want nil", associatedData, err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("a.Decrypt(prefix || dummyCiphertext, %x) = %x, want %x", associatedData, got, plaintext)
			}
		})
	}
}

func TestRegisterPrimitiveConstructor(t *testing.T) {
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	k := mustCreateKey(t, keytest.VariantTink, 0x01020304, key128Bits)

	t.Run("empty config fails", func(t *testing.T) {
		emptyConfig := config.NewBuilder().Build()
		if _, err := emptyConfig.PrimitiveFromKey(k, internalapi.Token{}); err == nil {
			t.Errorf("emptyConfig.PrimitiveFromKey(%v) err = nil, want error", k)
		}
	})

	t.Run("registered config succeeds", func(t *testing.T) {
		b := config.NewBuilder()
		if err := keytest.RegisterPrimitiveConstructor(b, internalapi.Token{}); err != nil {
			t.Fatalf("keytest.RegisterPrimitiveConstructor() err = %v, want nil", err)
		}
		c := b.Build()
		p, err := c.PrimitiveFromKey(k, internalapi.Token{})
		if err != nil {
			t.Fatalf("c.PrimitiveFromKey(%v) err = %v, want nil", k, err)
		}
		a, ok := p.(tink.AEAD)
		if !ok {
			t.Fatalf("c.PrimitiveFromKey(%v) = %T, want tink.AEAD", k, p)
		}
		ciphertext, err := a.Encrypt(plaintext, associatedData)
		if err != nil {
			t.Fatalf("a.Encrypt(%x, %x) err = %v, want nil", plaintext, associatedData, err)
		}
		if !bytes.HasPrefix(ciphertext, k.OutputPrefix()) {
			t.Errorf("ciphertext = %x, want prefix %x", ciphertext, k.OutputPrefix())
		}
		got, err := a.Decrypt(ciphertext, associatedData)
		if err != nil {
			t.Fatalf("a.Decrypt(ciphertext, %x) err = %v, want nil", associatedData, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("a.Decrypt(ciphertext, %x) = %x, want %x", associatedData, got, plaintext)
		}
	})
}

func TestPrimitiveConstructorFailsWithWrongKeyType(t *testing.T) {
	b := config.NewBuilder()
	if err := keytest.RegisterPrimitiveConstructor(b, internalapi.Token{}); err != nil {
		t.Fatalf("keytest.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	c := b.Build()
	if _, err := c.PrimitiveFromKey(&stubKey{}, internalapi.Token{}); err == nil {
		t.Errorf("c.PrimitiveFromKey(&stubKey{}) err = nil, want error")
	}
	if _, err := primitiveregistry.Primitive(&stubKey{}); err == nil {
		t.Errorf("primitiveregistry.Primitive(&stubKey{}) err = nil, want error")
	}
}

func TestDecryptFails(t *testing.T) {
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	keyID := uint32(0x01020304)
	tinkKey := mustCreateKey(t, keytest.VariantTink, keyID, key128Bits)
	tinkAEAD := mustCreateAEAD(t, tinkKey)

	mustEncrypt := func(t *testing.T, k *keytest.Key) []byte {
		t.Helper()
		ciphertext, err := mustCreateAEAD(t, k).Encrypt(plaintext, associatedData)
		if err != nil {
			t.Fatalf("Encrypt(%x, %x) err = %v, want nil", plaintext, associatedData, err)
		}
		return ciphertext
	}
	validCiphertext := mustEncrypt(t, tinkKey)
	corruptedPrefix := bytes.Clone(validCiphertext)
	corruptedPrefix[0] ^= 0x01

	for _, tc := range []struct {
		name           string
		ciphertext     []byte
		associatedData []byte
	}{
		{
			name:           "wrong associated data",
			ciphertext:     validCiphertext,
			associatedData: []byte("wrongAssociatedData"),
		},
		{
			name:           "different key bytes",
			ciphertext:     mustEncrypt(t, mustCreateKey(t, keytest.VariantTink, keyID, otherKey128Bits)),
			associatedData: associatedData,
		},
		{
			name:           "different key ID",
			ciphertext:     mustEncrypt(t, mustCreateKey(t, keytest.VariantTink, keyID+1, key128Bits)),
			associatedData: associatedData,
		},
		{
			name:           "crunchy ciphertext",
			ciphertext:     mustEncrypt(t, mustCreateKey(t, keytest.VariantCrunchy, keyID, key128Bits)),
			associatedData: associatedData,
		},
		{
			name:           "no prefix ciphertext",
			ciphertext:     mustEncrypt(t, mustCreateKey(t, keytest.VariantNoPrefix, 0, key128Bits)),
			associatedData: associatedData,
		},
		{
			name:           "ciphertext shorter than prefix",
			ciphertext:     validCiphertext[:3],
			associatedData: associatedData,
		},
		{
			name:           "prefix only",
			ciphertext:     tinkKey.OutputPrefix(),
			associatedData: associatedData,
		},
		{
			name:           "corrupted prefix",
			ciphertext:     corruptedPrefix,
			associatedData: associatedData,
		},
		{
			name:           "empty ciphertext",
			ciphertext:     []byte{},
			associatedData: associatedData,
		},
		{
			name:           "nil ciphertext",
			ciphertext:     nil,
			associatedData: associatedData,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := tinkAEAD.Decrypt(tc.ciphertext, tc.associatedData); err == nil {
				t.Errorf("tinkAEAD.Decrypt(%x, %x) = %x, nil, want error", tc.ciphertext, tc.associatedData, got)
			}
		})
	}
}

func TestEncryptDoesNotModifyPreviousCiphertexts(t *testing.T) {
	plaintextA := []byte("plaintext A")
	plaintextB := []byte("a different, longer plaintext B")
	associatedData := []byte("associatedData")
	for _, tc := range keyTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			a := mustCreateAEAD(t, mustCreateKey(t, tc.variant, tc.keyID, tc.keyBytes))
			ciphertextA, err := a.Encrypt(plaintextA, associatedData)
			if err != nil {
				t.Fatalf("a.Encrypt(%x, %x) err = %v, want nil", plaintextA, associatedData, err)
			}
			wantCiphertextA := bytes.Clone(ciphertextA)
			if _, err := a.Encrypt(plaintextB, associatedData); err != nil {
				t.Fatalf("a.Encrypt(%x, %x) err = %v, want nil", plaintextB, associatedData, err)
			}
			if !bytes.Equal(ciphertextA, wantCiphertextA) {
				t.Errorf("ciphertextA = %x, want %x", ciphertextA, wantCiphertextA)
			}
			got, err := a.Decrypt(ciphertextA, associatedData)
			if err != nil {
				t.Fatalf("a.Decrypt(ciphertextA, %x) err = %v, want nil", associatedData, err)
			}
			if !bytes.Equal(got, plaintextA) {
				t.Errorf("a.Decrypt(ciphertextA, %x) = %x, want %x", associatedData, got, plaintextA)
			}
		})
	}
}

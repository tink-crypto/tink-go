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

package xchacha20poly1305_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/xchacha20poly1305"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	testingaead "github.com/tink-crypto/tink-go/v2/internal/testing/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func mustCreateAEAD(t *testing.T, key *xchacha20poly1305.Key) tink.AEAD {
	t.Helper()
	km := keyset.NewManager()
	keyID, err := km.AddKey(key)
	if err != nil {
		t.Fatalf("km.AddKey(%v) err = %v, want nil", key, err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary(%v) err = %v, want nil", keyID, err)
	}
	h, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}
	a, err := aead.New(h)
	if err != nil {
		t.Fatalf("aead.New() err = %v, want nil", err)
	}
	return a
}

func TestEncryptDecrypt(t *testing.T) {
	for _, tc := range []struct {
		name          string
		variant       xchacha20poly1305.Variant
		idRequirement uint32
		wantPrefix    []byte
	}{
		{
			name:          "TINK",
			variant:       xchacha20poly1305.VariantTink,
			idRequirement: 0x11223344,
			wantPrefix:    []byte{cryptofmt.TinkStartByte, 0x11, 0x22, 0x33, 0x44},
		},
		{
			name:          "CRUNCHY",
			variant:       xchacha20poly1305.VariantCrunchy,
			idRequirement: 0x11223344,
			wantPrefix:    []byte{cryptofmt.LegacyStartByte, 0x11, 0x22, 0x33, 0x44},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := xchacha20poly1305.NewParameters(tc.variant)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			keyBytes, err := secretdata.NewBytesFromRand(32)
			if err != nil {
				t.Fatalf("secretdata.NewBytesFromRand(32) err = %v, want nil", err)
			}
			key, err := xchacha20poly1305.NewKey(keyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewKey() err = %v, want nil", err)
			}
			a := mustCreateAEAD(t, key)
			plaintext := []byte("plaintext")
			associatedData := []byte("associatedData")
			ciphertext, err := a.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("a.Encrypt(%v, %v) err = %v, want nil", plaintext, associatedData, err)
			}
			if got, want := ciphertext[:len(tc.wantPrefix)], tc.wantPrefix; !bytes.Equal(got, want) {
				t.Errorf("ciphertext has wrong prefix: got %x, want %x", got, want)
			}

			// Encryption is not deterministic.
			ciphertext2, err := a.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("a.Encrypt(%v, %v) err = %v, want nil", plaintext, associatedData, err)
			}
			if bytes.Equal(ciphertext, ciphertext2) {
				t.Errorf("a.Encrypt(%v, %v) = %x, want different", plaintext, associatedData, ciphertext)
			}

			decrypted, err := a.Decrypt(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("a.Decrypt(%x, %x) err = %v, want nil", ciphertext, associatedData, err)
			}
			if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
				t.Errorf("a.Decrypt(%x, %x) = %x, want %x", ciphertext, associatedData, got, want)
			}
		})
	}
}

func TestDecryptFailsWithInvalidCiphertext(t *testing.T) {
	for _, tc := range []struct {
		name    string
		variant xchacha20poly1305.Variant
	}{
		{
			name:    "TINK",
			variant: xchacha20poly1305.VariantTink,
		},
		{
			name:    "CRUNCHY",
			variant: xchacha20poly1305.VariantCrunchy,
		},
		{
			name:    "RAW",
			variant: xchacha20poly1305.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := xchacha20poly1305.NewParameters(tc.variant)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			keyBytes, err := secretdata.NewBytesFromRand(32)
			if err != nil {
				t.Fatalf("secretdata.NewBytesFromRand(32) err = %v, want nil", err)
			}
			key, err := xchacha20poly1305.NewKey(keyBytes, 0, params)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewKey() err = %v, want nil", err)
			}
			a := mustCreateAEAD(t, key)
			plaintext := []byte("plaintext")
			associatedData := []byte("associatedData")
			ciphertext, err := a.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("a.Encrypt(%v, %v) err = %v, want nil", plaintext, associatedData, err)
			}

			prefix := ciphertext[:len(key.OutputPrefix())]
			ciphertextNoPrefix := ciphertext[len(prefix):]

			iv := ciphertextNoPrefix[:chacha20poly1305.NonceSizeX]
			ct := ciphertextNoPrefix[chacha20poly1305.NonceSizeX : chacha20poly1305.NonceSizeX+len(plaintext)]
			tag := ciphertextNoPrefix[chacha20poly1305.NonceSizeX+len(plaintext):]

			// Invalid prefix.
			if len(prefix) > 0 {
				wrongPrefix := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
				if _, err := a.Decrypt(slices.Concat(wrongPrefix, iv, ct, tag), associatedData); err == nil {
					t.Errorf("a.Decrypt() err = nil, want error")
				}
			}

			// Invalid IV.
			wrongIV := bytes.Clone(iv)
			wrongIV[0] ^= 1
			if _, err := a.Decrypt(slices.Concat(prefix, wrongIV, ct, tag), associatedData); err == nil {
				t.Errorf("a.Decrypt() err = nil, want error")
			}

			// Invalid ciphertext.
			wrongCiphertext := bytes.Clone(ciphertext)
			wrongCiphertext[0] ^= 1
			if _, err := a.Decrypt(slices.Concat(prefix, iv, wrongCiphertext, tag), associatedData); err == nil {
				t.Errorf("a.Decrypt() err = nil, want error")
			}

			// Invalid tag.
			wrongTag := bytes.Clone(tag)
			wrongTag[0] ^= 1
			if _, err := a.Decrypt(slices.Concat(prefix, iv, ct, wrongTag), associatedData); err == nil {
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
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/xchacha20_poly1305_test.json#L69
	key := secretdata.NewBytesFromData(mustDecodeHex(t, "697c197c9e0023c8eee42ddf08c12c46718a436561b0c66d998c81879f7cb74c"), testonlyinsecuresecretdataaccess.Token())
	iv := "cd78f4533c94648feacd5aef0291b00b454ee3dcdb76dcc8"
	ct := "b0"
	aad := "6384f4714ff18c18"
	tag := "e5e35f5332f91bdd2d28e59d68a0b141"
	for _, tc := range []struct {
		name           string
		variant        xchacha20poly1305.Variant
		idRequirement  uint32
		key            secretdata.Bytes
		plaintext      []byte
		associatedData []byte
		ciphertext     []byte
	}{
		{
			name:           "TINK",
			variant:        xchacha20poly1305.VariantTink,
			idRequirement:  0x11223344,
			key:            key,
			plaintext:      mustDecodeHex(t, "e1"),
			associatedData: mustDecodeHex(t, aad),
			ciphertext:     mustDecodeHex(t, "0111223344"+iv+ct+tag),
		},
		{
			name:           "CRUNCHY",
			variant:        xchacha20poly1305.VariantCrunchy,
			idRequirement:  0x11223344,
			key:            key,
			plaintext:      mustDecodeHex(t, "e1"),
			associatedData: mustDecodeHex(t, aad),
			ciphertext:     mustDecodeHex(t, "0011223344"+iv+ct+tag),
		},
		{
			name:           "NO_PREFIX",
			variant:        xchacha20poly1305.VariantNoPrefix,
			idRequirement:  0,
			key:            key,
			plaintext:      mustDecodeHex(t, "e1"),
			associatedData: mustDecodeHex(t, aad),
			ciphertext:     mustDecodeHex(t, iv+ct+tag),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := xchacha20poly1305.NewParameters(tc.variant)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			key, err := xchacha20poly1305.NewKey(tc.key, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("xchacha20poly1305.NewKey() err = %v, want nil", err)
			}
			a := mustCreateAEAD(t, key)
			decrypted, err := a.Decrypt(tc.ciphertext, tc.associatedData)
			if err != nil {
				t.Fatalf("a.Decrypt(%x, %x) err = %v, want nil", tc.ciphertext, tc.associatedData, err)
			}
			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Errorf("a.Decrypt(%x, %x) = %v, want %v", tc.ciphertext, tc.associatedData, decrypted, tc.plaintext)
			}
		})
	}
}

func TestWycheproofCases(t *testing.T) {
	suite := new(testingaead.WycheproofSuite)
	if err := testutil.PopulateSuite(suite, "xchacha20_poly1305_test.json"); err != nil {
		t.Fatalf("testutil.PopulateSuite(suite, \"xchacha20_poly1305_test.json\") err = %v, want nil", err)
	}
	for _, group := range suite.TestGroups {
		if group.KeySize/8 != chacha20poly1305.KeySize {
			continue
		}
		if group.IvSize/8 != chacha20poly1305.NonceSizeX {
			continue
		}
		for _, test := range group.Tests {
			caseName := fmt.Sprintf("%s-%s:Case-%d", suite.Algorithm, group.Type, test.CaseID)
			t.Run(caseName, func(t *testing.T) { runXChaCha20Poly1305WycheproofCase(t, test) })
		}
	}
}

func runXChaCha20Poly1305WycheproofCase(t *testing.T, tc *testingaead.WycheproofCase) {
	var combinedCt []byte
	combinedCt = append(combinedCt, tc.Iv...)
	combinedCt = append(combinedCt, tc.Ct...)
	combinedCt = append(combinedCt, tc.Tag...)

	params, err := xchacha20poly1305.NewParameters(xchacha20poly1305.VariantNoPrefix)
	if err != nil {
		t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", xchacha20poly1305.VariantNoPrefix, err)
	}
	key, err := xchacha20poly1305.NewKey(secretdata.NewBytesFromData(tc.Key, testonlyinsecuresecretdataaccess.Token()), 0, params)
	if err != nil {
		t.Fatalf("xchacha20poly1305.NewKey() err = %v, want nil", err)
	}
	a := mustCreateAEAD(t, key)
	_, err = a.Encrypt(tc.Msg, tc.Aad)
	if err != nil {
		t.Fatalf("a.Encrypt(%x, %x) err = %v, want nil", tc.Msg, tc.Aad, err)
	}

	decrypted, err := a.Decrypt(combinedCt, tc.Aad)
	switch tc.Result {
	case "valid":
		if err != nil {
			t.Fatalf("a.Decrypt(combinedCt, tc.Aad) err = %v, want nil", err)
		}
		if got, want := decrypted, tc.Msg; !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	case "invalid":
		if err == nil {
			t.Error("a.Decrypt(combinedCt, tc.Aad) err = nil, want non-nil")
		}
	default:
		// Skip other test vectors, if any.
		t.Skipf("Skipping test vector with result %q", tc.Result)
	}
}

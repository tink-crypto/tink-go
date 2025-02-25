// Copyright 2025 Google LLC
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

package aessiv_test

import (
	"bytes"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/daead/aessiv"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/outputprefix"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testing/insecuresecretdataaccesstest"
)

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) failed: %v", s, err)
	}
	return b
}

func mustCreateParameters(t *testing.T, keySize int, variant aessiv.Variant) *aessiv.Parameters {
	t.Helper()
	p, err := aessiv.NewParameters(keySize, variant)
	if err != nil {
		t.Fatalf("aessiv.NewParameters(%v, %v) failed: %v", keySize, variant, err)
	}
	return p
}

func mustCreateKey(t *testing.T, keyBytes []byte, idRequirement uint32, parameters *aessiv.Parameters) *aessiv.Key {
	t.Helper()
	p, err := aessiv.NewKey(secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccesstest.Token()), idRequirement, parameters)
	if err != nil {
		t.Fatalf("aessiv.NewKey(%x, %v) failed: %v", keyBytes, parameters, err)
	}
	return p
}

func TestDeterministicAEAD(t *testing.T) {
	// Test case from
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_siv_cmac_test.json#L2865.
	keyBytes := mustHexDecode(t, "c25cafc6018b98dfbb79a40ec89c575a4f88c4116489bba27707479800c0130235334a45dbe8d8dae3da8dcb45bbe5dce031b0f68ded544fda7eca30d6749442")
	ad := mustHexDecode(t, "deeb0ccf3aef47a296ed1ca8f4ae5907")
	plaintext := mustHexDecode(t, "beec61030fa3d670337196beade6aeaa")
	ciphertext := mustHexDecode(t, "5865208eab9163db85cab9f96d846234a2626aae22f5c17c9aad4b501f4416e4")

	for _, tc := range []struct {
		name           string
		key            *aessiv.Key
		wantCiphertext []byte
	}{
		{
			name:           "No prefix",
			key:            mustCreateKey(t, keyBytes, 0, mustCreateParameters(t, len(keyBytes), aessiv.VariantNoPrefix)),
			wantCiphertext: ciphertext,
		},
		{
			name:           "Tink prefix",
			key:            mustCreateKey(t, keyBytes, 0x01020304, mustCreateParameters(t, len(keyBytes), aessiv.VariantTink)),
			wantCiphertext: slices.Concat(outputprefix.Tink(0x01020304), ciphertext),
		},
		{
			name:           "Crunchy prefix",
			key:            mustCreateKey(t, keyBytes, 0x01020304, mustCreateParameters(t, len(keyBytes), aessiv.VariantCrunchy)),
			wantCiphertext: slices.Concat(outputprefix.Legacy(0x01020304), ciphertext),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			daead, err := aessiv.NewDeterministicAEAD(tc.key, internalapi.Token{})
			if err != nil {
				t.Fatalf("aessiv.NewDeterministicAEAD(%v) failed: %v", tc.key, err)
			}
			ciphertext, err := daead.EncryptDeterministically(plaintext, ad)
			if err != nil {
				t.Fatalf("daead.EncryptDeterministically(%v, %v) failed: %v", plaintext, ad, err)
			}
			if got, want := ciphertext, tc.wantCiphertext; !bytes.Equal(got, want) {
				t.Errorf("daead.EncryptDeterministically(%v, %v) = %x, want %x", plaintext, ad, got, want)
			}
			decrypted, err := daead.DecryptDeterministically(ciphertext, ad)
			if err != nil {
				t.Fatalf("daead.DecryptDeterministically(%v, %v) failed: %v", ciphertext, ad, err)
			}
			if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
				t.Errorf("daead.DecryptDeterministically(%v, %v) = %v, want %v", ciphertext, ad, got, want)
			}
		})
	}
}

func TestDeterministicAEADDecryptFailsWithInvalidCiphertext(t *testing.T) {
	// Test case from
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_siv_cmac_test.json#L2865.
	keyBytes := mustHexDecode(t, "c25cafc6018b98dfbb79a40ec89c575a4f88c4116489bba27707479800c0130235334a45dbe8d8dae3da8dcb45bbe5dce031b0f68ded544fda7eca30d6749442")
	ad := mustHexDecode(t, "deeb0ccf3aef47a296ed1ca8f4ae5907")
	ciphertext := mustHexDecode(t, "5865208eab9163db85cab9f96d846234a2626aae22f5c17c9aad4b501f4416e4")

	for _, tc := range []struct {
		name       string
		key        *aessiv.Key
		ciphertext []byte
	}{
		{
			name:       "No prefix",
			key:        mustCreateKey(t, keyBytes, 0, mustCreateParameters(t, len(keyBytes), aessiv.VariantNoPrefix)),
			ciphertext: ciphertext,
		},
		{
			name:       "Tink prefix",
			key:        mustCreateKey(t, keyBytes, 0x01020304, mustCreateParameters(t, len(keyBytes), aessiv.VariantTink)),
			ciphertext: slices.Concat(outputprefix.Tink(0x01020304), ciphertext),
		},
		{
			name:       "Crunchy prefix",
			key:        mustCreateKey(t, keyBytes, 0x01020304, mustCreateParameters(t, len(keyBytes), aessiv.VariantCrunchy)),
			ciphertext: slices.Concat(outputprefix.Legacy(0x01020304), ciphertext),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := aessiv.NewDeterministicAEAD(tc.key, internalapi.Token{})
			if err != nil {
				t.Fatalf("aessiv.NewDeterministicAEAD(%v) failed: %v", tc.key, err)
			}
			for i := 0; i < len(tc.ciphertext); i++ {
				corruptedCiphertext := slices.Clone(tc.ciphertext)
				corruptedCiphertext[i] ^= 0xff
				if _, err := d.DecryptDeterministically(corruptedCiphertext, ad); err == nil {
					t.Errorf("d.DecryptDeterministically(%v, %v) err = nil, want error", corruptedCiphertext, ad)
				}
			}
		})
	}
}

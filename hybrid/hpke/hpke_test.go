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

package hpke_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/hybrid/hpke"
	"github.com/tink-crypto/tink-go/v2/hybrid"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func TestEncryptDecryptFromWithKeysetFromParameters(t *testing.T) {
	params, err := hpke.NewParameters(hpke.ParametersOpts{
		KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
		KDFID:   hpke.HKDFSHA256,
		AEADID:  hpke.AES256GCM,
		Variant: hpke.VariantTink,
	})
	if err != nil {
		t.Fatalf("hpke.NewParameters() err = %v, want nil", err)
	}

	km := keyset.NewManager()
	keyID, err := km.AddNewKeyFromParameters(params)
	if err != nil {
		t.Fatalf("km.AddNewKeyFromParameters() err = %v, want nil", err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary() err = %v, want nil", err)
	}
	privateKeyHandle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}

	publicKeyHandle, err := privateKeyHandle.Public()
	if err != nil {
		t.Fatalf("privateKeyHandle.Public() err = %v, want nil", err)
	}

	encrypter, err := hybrid.NewHybridEncrypt(publicKeyHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridEncrypt() err = %v, want nil", err)
	}
	decrypter, err := hybrid.NewHybridDecrypt(privateKeyHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridDecrypt() err = %v, want nil", err)
	}

	plaintext := []byte("plaintext")
	contextInfo := []byte("contextInfo")

	ciphertext, err := encrypter.Encrypt(plaintext, contextInfo)
	if err != nil {
		t.Fatalf("encrypter.Encrypt() err = %v, want nil", err)
	}
	gotDecrypted, err := decrypter.Decrypt(ciphertext, contextInfo)
	if err != nil {
		t.Fatalf("decrypter.Decrypt() err = %v, want nil", err)
	}
	if diff := cmp.Diff(gotDecrypted, plaintext); diff != "" {
		t.Errorf("decrypter.Decrypt() returned unexpected diff (-want +got):\n%s", diff)
	}
}

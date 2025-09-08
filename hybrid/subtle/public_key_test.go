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

package subtle_test

import (
	"bytes"
	"testing"

	"github.com/tink-crypto/tink-go/v2/hybrid/hpke"
	"github.com/tink-crypto/tink-go/v2/hybrid"
	"github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestHPKEPublicKeySerialization(t *testing.T) {
	// Obtain private and public keyset handles via key template.
	keyTemplate := hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template()
	privHandle, err := keyset.NewHandle(keyTemplate)
	if err != nil {
		t.Fatalf("NewHandle(%v) err = %v, want nil", keyTemplate, err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("Public() err = %v, want nil", err)
	}

	// Export public key as bytes.
	pubKeyBytes, err := subtle.SerializePrimaryPublicKey(pubHandle, keyTemplate)
	if err != nil {
		t.Fatalf("SerializePrimaryPublicKey(%v) err = %v, want nil", pubHandle, err)
	}

	// Import public key bytes as keyset handle.
	gotPubHandle, err := subtle.KeysetHandleFromSerializedPublicKey(pubKeyBytes, keyTemplate)
	if err != nil {
		t.Fatalf("KeysetHandleFromSerializedPublicKey(%v, %v) err = %v, want nil", pubKeyBytes, keyTemplate, err)
	}

	plaintext := random.GetRandomBytes(200)
	ctxInfo := random.GetRandomBytes(100)

	// Encrypt with public keyset handle constructed from public key bytes.
	enc, err := hybrid.NewHybridEncrypt(gotPubHandle)
	if err != nil {
		t.Fatalf("NewHybridEncrypt(%v) err = %v, want nil", gotPubHandle, err)
	}
	ciphertext, err := enc.Encrypt(plaintext, ctxInfo)
	if err != nil {
		t.Fatalf("Encrypt(%x, %x) err = %v, want nil", plaintext, ctxInfo, err)
	}

	// Decrypt with original private keyset handle.
	dec, err := hybrid.NewHybridDecrypt(privHandle)
	if err != nil {
		t.Fatalf("NewHybridDecrypt(%v) err = %v, want nil", privHandle, err)
	}
	gotPlaintext, err := dec.Decrypt(ciphertext, ctxInfo)
	if err != nil {
		t.Fatalf("Decrypt(%x, %x) err = %v, want nil", plaintext, ctxInfo, err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Errorf("Decrypt(%x, %x) = %x, want %x", plaintext, ctxInfo, gotPlaintext, plaintext)
	}
}

func TestSerializePrimaryPublicKeyInvalidTemplateFails(t *testing.T) {
	keyTemplate := hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template()
	privHandle, err := keyset.NewHandle(keyTemplate)
	if err != nil {
		t.Fatalf("NewHandle(%v) err = %v, want nil", keyTemplate, err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("Public() err = %v, want nil", err)
	}

	tests := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{"AES_128_GCM", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template()},
		{"AES_128_GCM_Raw", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Raw_Key_Template()},
		{"AES_256_GCM", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template()},
		{"AES_256_GCM_Raw", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Raw_Key_Template()},
		{"CHACHA20_POLY1305", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Key_Template()},
		{"invalid type URL", &tinkpb.KeyTemplate{
			TypeUrl:          "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
			Value:            keyTemplate.GetValue(),
			OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := subtle.SerializePrimaryPublicKey(pubHandle, test.template); err == nil {
				t.Errorf("SerializePrimaryPublicKey(%v, %v) err = nil, want error", pubHandle, test.template)
			}
		})
	}
}

func mustCreatePublicKeysetHandle(t *testing.T, opts hpke.ParametersOpts) *keyset.Handle {
	t.Helper()
	params, err := hpke.NewParameters(opts)
	if err != nil {
		t.Fatalf("hpke.NewParameters(%v) err = %v, want nil", opts, err)
	}

	km := keyset.NewManager()
	keyID, err := km.AddNewKeyFromParameters(params)
	if err != nil {
		t.Fatalf("km.AddNewKeyFromParameters(%v) err = %v, want nil", params, err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary(%v) err = %v, want nil", keyID, err)
	}
	kh, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}
	publicHandle, err := kh.Public()
	if err != nil {
		t.Fatalf("kh.Public() err = %v, want nil", err)
	}
	return publicHandle
}

func TestSerializePrimaryPublicKeyInvalidKeyFails(t *testing.T) {
	// Build valid key data.
	keyTemplate := hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template()
	tests := []struct {
		name        string
		keyTemplate *tinkpb.KeyTemplate
		kh          *keyset.Handle
	}{
		{
			name:        "invalid variant",
			keyTemplate: keyTemplate,
			kh: mustCreatePublicKeysetHandle(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.ChaCha20Poly1305,
				Variant: hpke.VariantTink, // Want no prefix.
			}),
		},
		{
			name:        "invalid KEMID",
			keyTemplate: keyTemplate,
			kh: mustCreatePublicKeysetHandle(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P384_HKDF_SHA384, // P384 is not supported.
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.ChaCha20Poly1305,
				Variant: hpke.VariantNoPrefix,
			}),
		},
		{
			name:        "invalid KDFID",
			keyTemplate: keyTemplate,
			kh: mustCreatePublicKeysetHandle(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA384, // SHA384 is not supported.
				AEADID:  hpke.ChaCha20Poly1305,
				Variant: hpke.VariantNoPrefix,
			}),
		},
		{
			name:        "invalid AEADID",
			keyTemplate: keyTemplate,
			kh: mustCreatePublicKeysetHandle(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM, // AES256GCM is not supported.
				Variant: hpke.VariantNoPrefix,
			}),
		},
		{
			name:        "invalid key template",
			keyTemplate: hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Key_Template(), // Want Raw key.
			kh: mustCreatePublicKeysetHandle(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.ChaCha20Poly1305,
				Variant: hpke.VariantNoPrefix,
			}),
		},
		{
			name:        "invalid keyset handle",
			keyTemplate: keyTemplate,
			// Private keyset handle.
			kh: func() *keyset.Handle {
				kh, err := keyset.NewHandle(keyTemplate)
				if err != nil {
					t.Fatalf("NewHandle(%v) err = %v, want nil", keyTemplate, err)
				}
				return kh
			}(),
		},
		{
			name:        "nil keyset handle",
			keyTemplate: keyTemplate,
			kh:          nil,
		},
		{
			name:        "nil template",
			keyTemplate: nil,
			kh: mustCreatePublicKeysetHandle(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.ChaCha20Poly1305,
				Variant: hpke.VariantNoPrefix,
			}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := subtle.SerializePrimaryPublicKey(test.kh, test.keyTemplate); err == nil {
				t.Errorf("SerializePrimaryPublicKey() err = nil, want error")
			} else {
				t.Logf("SerializePrimaryPublicKey() err = %v", err)
			}
		})
	}
}

func TestSerializePrimaryPublicKeyFailsWithEmptyHandle(t *testing.T) {
	handle := &keyset.Handle{}
	keyTemplate := hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template()
	if _, err := subtle.SerializePrimaryPublicKey(handle, keyTemplate); err == nil {
		t.Errorf("SerializePrimaryPublicKey(%v, %v) err = nil, want error", handle, keyTemplate)
	}
}

func TestKeysetHandleFromSerializedPublicKeyInvalidTemplateFails(t *testing.T) {
	keyTemplate := hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template()
	privHandle, err := keyset.NewHandle(keyTemplate)
	if err != nil {
		t.Fatalf("NewHandle(%v) err = %v, want nil", keyTemplate, err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("Public() err = %v, want nil", err)
	}
	pubKeyBytes, err := subtle.SerializePrimaryPublicKey(pubHandle, keyTemplate)
	if err != nil {
		t.Fatalf("SerializePrimaryPublicKey(%v) err = %v, want nil", pubHandle, err)
	}

	tests := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{"AES_128_GCM", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template()},
		{"AES_128_GCM_Raw", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Raw_Key_Template()},
		{"AES_256_GCM", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template()},
		{"AES_256_GCM_Raw", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Raw_Key_Template()},
		{"CHACHA20_POLY1305", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Key_Template()},
		{"invalid type URL", &tinkpb.KeyTemplate{
			TypeUrl:          "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
			Value:            keyTemplate.GetValue(),
			OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := subtle.KeysetHandleFromSerializedPublicKey(pubKeyBytes, test.template); err == nil {
				t.Errorf("KeysetHandleFromSerializedPublicKey(%v, %v) err = nil, want error", pubKeyBytes, test.template)
			}
		})
	}
}

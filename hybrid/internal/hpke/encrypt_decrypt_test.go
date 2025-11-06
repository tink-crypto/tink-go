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

package hpke

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/subtle"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
)

func TestNewEncryptMissingPubKeyBytes(t *testing.T) {
	if _, err := NewEncrypt(nil, P256HKDFSHA256, HKDFSHA256, AES256GCM); err == nil {
		t.Error("NewEncrypt() err = nil, want err")
	}
	if _, err := NewEncrypt([]byte{}, P256HKDFSHA256, HKDFSHA256, AES256GCM); err == nil {
		t.Error("NewEncrypt() err = nil, want err")
	}
}

func TestNewDecryptMissingPrivKeyBytes(t *testing.T) {
	if _, err := NewDecrypt(secretdata.NewBytesFromData(nil, testonlyinsecuresecretdataaccess.Token()), P256HKDFSHA256, HKDFSHA256, AES256GCM); err == nil {
		t.Error("NewDecrypt() err = nil, want err")
	}
	if _, err := NewDecrypt(secretdata.NewBytesFromData([]byte{}, testonlyinsecuresecretdataaccess.Token()), P256HKDFSHA256, HKDFSHA256, AES256GCM); err == nil {
		t.Error("NewDecrypt() err = nil, want err")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	aeadIDs := []AEADID{AES128GCM, AES256GCM, ChaCha20Poly1305}
	for _, aeadID := range aeadIDs {
		t.Run(aeadID.String(), func(t *testing.T) {
			pubKey, privKey := pubPrivKeys(t)
			enc, err := NewEncrypt(pubKey, X25519HKDFSHA256, HKDFSHA256, aeadID)
			if err != nil {
				t.Fatalf("NewEncrypt() err %q", err)
			}
			dec, err := NewDecrypt(privKey, X25519HKDFSHA256, HKDFSHA256, aeadID)
			if err != nil {
				t.Fatalf("NewDecrypt() err %q", err)
			}

			wantPT := random.GetRandomBytes(200)
			ctxInfo := random.GetRandomBytes(100)
			ct, err := enc.Encrypt(wantPT, ctxInfo)
			if err != nil {
				t.Fatalf("Encrypt() err %q", err)
			}
			gotPT, err := dec.Decrypt(ct, ctxInfo)
			if err != nil {
				t.Fatalf("Decrypt() err %q", err)
			}
			if !bytes.Equal(gotPT, wantPT) {
				t.Errorf("Decrypt: got %q, want %q", gotPT, wantPT)
			}
		})
	}
}

func TestDecryptModifiedCiphertextOrContextInfo(t *testing.T) {
	pubKey, privKey := pubPrivKeys(t)
	enc, err := NewEncrypt(pubKey, X25519HKDFSHA256, HKDFSHA256, AES256GCM)
	if err != nil {
		t.Fatalf("NewEncrypt() err %q", err)
	}
	dec, err := NewDecrypt(privKey, X25519HKDFSHA256, HKDFSHA256, AES256GCM)
	if err != nil {
		t.Fatalf("NewDecrypt() err %q", err)
	}

	wantPT := random.GetRandomBytes(200)
	ctxInfo := random.GetRandomBytes(100)
	ct, err := enc.Encrypt(wantPT, ctxInfo)
	if err != nil {
		t.Fatalf("Encrypt() err %q", err)
	}
	gotPT, err := dec.Decrypt(ct, ctxInfo)
	if err != nil {
		t.Fatalf("Decrypt() err %q", err)
	}
	if !bytes.Equal(gotPT, wantPT) {
		t.Errorf("Decrypt: got %q, want %q", gotPT, wantPT)
	}

	tests := []struct {
		name    string
		ct      []byte
		ctxInfo []byte
	}{
		{"extended ct", append(ct, []byte("hi there")...), ctxInfo},
		{"flip byte ct", flipRandByte(t, ct), ctxInfo},
		{"short ct", ct[:len(ct)-5], ctxInfo},
		{"empty ct", []byte{}, ctxInfo},
		{"extended ctxInfo", ct, append(ctxInfo, []byte("hi there")...)},
		{"flip byte ctxInfo", ct, flipRandByte(t, ctxInfo)},
		{"short ctxInfo", ct, ctxInfo[:len(ctxInfo)-5]},
		{"empty ctxInfo", ct, []byte{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := dec.Decrypt(test.ct, test.ctxInfo); err == nil {
				t.Error("Decrypt: got success, want err")
			}
		})
	}
}

func TestEncryptDecryptEmptyContextInfo(t *testing.T) {
	pubKey, privKey := pubPrivKeys(t)
	enc, err := NewEncrypt(pubKey, X25519HKDFSHA256, HKDFSHA256, AES256GCM)
	if err != nil {
		t.Fatalf("NewEncrypt() err = %q", err)
	}
	dec, err := NewDecrypt(privKey, X25519HKDFSHA256, HKDFSHA256, AES256GCM)
	if err != nil {
		t.Fatalf("NewDecrypt() err = %q", err)
	}

	wantPT := random.GetRandomBytes(200)
	ctxInfo := []byte{}
	ct, err := enc.Encrypt(wantPT, ctxInfo)
	if err != nil {
		t.Fatalf("Encrypt: err %q", err)
	}
	gotPT, err := dec.Decrypt(ct, ctxInfo)
	if err != nil {
		t.Fatalf("Decrypt: err %q", err)
	}
	if !bytes.Equal(gotPT, wantPT) {
		t.Errorf("Decrypt: got %q, want %q", gotPT, wantPT)
	}
}

// TestDecryptEncapsulatedKeyWithFlippedMSB checks that ciphertexts with its
// encapsulated key MSB flipped fails to decrypt. See details at b/213886185.
func TestDecryptEncapsulatedKeyWithFlippedMSB(t *testing.T) {
	pubKey, privKey := pubPrivKeys(t)
	enc, err := NewEncrypt(pubKey, X25519HKDFSHA256, HKDFSHA256, AES256GCM)
	if err != nil {
		t.Fatalf("NewEncrypt() err = %q", err)
	}
	dec, err := NewDecrypt(privKey, X25519HKDFSHA256, HKDFSHA256, AES256GCM)
	if err != nil {
		t.Fatalf("NewDecrypt() err = %q", err)
	}

	wantPT := random.GetRandomBytes(200)
	ctxInfo := random.GetRandomBytes(100)
	ct, err := enc.Encrypt(wantPT, ctxInfo)
	if err != nil {
		t.Fatalf("Encrypt: err %q", err)
	}
	gotPT, err := dec.Decrypt(ct, ctxInfo)
	if err != nil {
		t.Fatalf("Decrypt: err %q", err)
	}
	if !bytes.Equal(gotPT, wantPT) {
		t.Errorf("Decrypt: got %q, want %q", gotPT, wantPT)
	}

	// Flip the MSB of the encapsulated key, which is the first 32 bytes of ct.
	ct[31] = ct[31] ^ 128
	if _, err := dec.Decrypt(ct, ctxInfo); err == nil {
		t.Error("Decrypt with encapsulated key MSB flipped: got success, want err")
	}
}

func pubPrivKeys(t *testing.T) ([]byte, secretdata.Bytes) {
	t.Helper()
	priv, err := subtle.GeneratePrivateKeyX25519()
	if err != nil {
		t.Fatalf("GeneratePrivateKeyX25519: err %q", err)
	}
	pub, err := subtle.PublicFromPrivateX25519(priv)
	if err != nil {
		t.Fatalf("PublicFromPrivateX25519: err %q", err)
	}
	return pub, secretdata.NewBytesFromData(priv, testonlyinsecuresecretdataaccess.Token())
}

func flipRandByte(t *testing.T, b []byte) []byte {
	t.Helper()
	ret := make([]byte, len(b))
	copy(ret, b)
	randByte := rand.Intn(len(b))
	ret[randByte] = ret[randByte] ^ 255
	return ret
}

func TestNewEncryptNewDecrypt_InvalidIDs(t *testing.T) {
	pub, priv := pubPrivKeys(t)
	t.Run("Invalid KEM ID", func(t *testing.T) {
		if _, err := NewEncrypt(pub, UnknownKEMID, HKDFSHA256, AES256GCM); err == nil {
			t.Error("NewEncrypt() err = nil, want err")
		}
		if _, err := NewDecrypt(priv, UnknownKEMID, HKDFSHA256, AES256GCM); err == nil {
			t.Error("NewDecrypt() err = nil, want err")
		}
	})
	t.Run("Invalid KDF ID", func(t *testing.T) {
		if _, err := NewEncrypt(pub, X25519HKDFSHA256, UnknownKDFID, AES256GCM); err == nil {
			t.Error("NewEncrypt() err = nil, want err")
		}
		if _, err := NewDecrypt(priv, X25519HKDFSHA256, UnknownKDFID, AES256GCM); err == nil {
			t.Error("NewDecrypt() err = nil, want err")
		}
	})
	t.Run("Invalid AEAD ID", func(t *testing.T) {
		if _, err := NewEncrypt(pub, X25519HKDFSHA256, HKDFSHA256, UnknownAEADID); err == nil {
			t.Error("NewEncrypt() err = nil, want err")
		}
		if _, err := NewDecrypt(priv, X25519HKDFSHA256, HKDFSHA256, UnknownAEADID); err == nil {
			t.Error("NewDecrypt() err = nil, want err")
		}
	})
}

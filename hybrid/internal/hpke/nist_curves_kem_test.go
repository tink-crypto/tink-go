// Copyright 2021 Google LLC
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
	"crypto/ecdh"
	"fmt"
	"io"
	"testing"
)

func TestKEMEncapsulateBoringSSLVectors(t *testing.T) {
	i := 0
	// TODO: b/235861932 - Add test vectors for P-384.
	vecs := hpkeBaseModeVectors(t)
	for key, vec := range vecs {
		if key.mode != baseMode ||
			(key.kemID != P256HKDFSHA256 && key.kemID != P384HKDFSHA384 && key.kemID != P521HKDFSHA512) ||
			(key.kdfID != HKDFSHA256 && key.kdfID != HKDFSHA384 && key.kdfID != HKDFSHA512) ||
			(key.aeadID != AES128GCM && key.aeadID != AES256GCM && key.aeadID != ChaCha20Poly1305) {
			continue
		}

		i++
		t.Run(fmt.Sprintf("%d", key.id), func(t *testing.T) {
			kem, err := newKEM(key.kemID)
			if err != nil {
				t.Fatal(err)
			}
			kem.(*nistCurvesKEM).generatePrivateKey = func(rand io.Reader) (*ecdh.PrivateKey, error) {
				return kem.(*nistCurvesKEM).curve.NewPrivateKey(vec.senderPrivKey)
			}

			secret, enc, err := kem.encapsulate(vec.recipientPubKey)
			if err != nil {
				t.Errorf("encapsulate for vector %v: got err %q, want success", key, err)
			}
			if !bytes.Equal(secret, vec.sharedSecret) {
				t.Errorf("encapsulate for vector %v: got shared secret %v, want %v", key, secret, vec.sharedSecret)
			}
			if !bytes.Equal(enc, vec.encapsulatedKey) {
				t.Errorf("encapsulate for vector %v: got encapsulated key %v, want %v", key, enc, vec.encapsulatedKey)
			}
		})
	}
	// Verify that we actually tested something.
	// If no vectors match the filter, then the test should fail because nothing was tested.
	if i == 0 {
		t.Error("no vectors were tested")
	}
}

func rfcVectorTestCases(t *testing.T) []struct {
	name   string
	kemID  KEMID
	vector vector
} {
	t.Helper()
	p256HPKEID, p256Vector := rfcVectorA3(t)
	// TODO: b/235861932 - Add test vectors for P-384.
	p521HPKEID, p521Vector := rfcVectorA6(t)
	return []struct {
		name   string
		kemID  KEMID
		vector vector
	}{
		{
			name:   "P-256",
			kemID:  p256HPKEID.kemID,
			vector: p256Vector,
		},
		{
			name:   "P-521",
			kemID:  p521HPKEID.kemID,
			vector: p521Vector,
		},
	}
}

func TestKEMEncapsulateBadRecipientPubKey(t *testing.T) {
	for _, test := range rfcVectorTestCases(t) {
		t.Run(test.name, func(t *testing.T) {
			kem, err := newKEM(test.kemID)
			if err != nil {
				t.Fatal(err)
			}
			badRecipientPubKey := append(test.vector.recipientPubKey, []byte("hello")...)
			if _, _, err := kem.encapsulate(badRecipientPubKey); err == nil {
				t.Error("encapsulate: got success, want err")
			}
		})
	}
}

func TestKEMDecapsulateBoringSSLVectors(t *testing.T) {
	i := 0
	// TODO: b/235861932 - Add test vectors for P-384.
	vecs := hpkeBaseModeVectors(t)
	for key, vec := range vecs {
		if key.mode != baseMode ||
			(key.kemID != P256HKDFSHA256 && key.kemID != P384HKDFSHA384 && key.kemID != P521HKDFSHA512) ||
			(key.kdfID != HKDFSHA256 && key.kdfID != HKDFSHA384 && key.kdfID != HKDFSHA512) ||
			(key.aeadID != AES128GCM && key.aeadID != AES256GCM && key.aeadID != ChaCha20Poly1305) {
			continue
		}

		i++
		t.Run(fmt.Sprintf("%d", key.id), func(t *testing.T) {
			kem, err := newKEM(key.kemID)
			if err != nil {
				t.Fatal(err)
			}
			secret, err := kem.decapsulate(vec.encapsulatedKey, vec.recipientPrivKey)
			if err != nil {
				t.Errorf("decapsulate for vector %v: got err %q, want success", key, err)
			}
			if !bytes.Equal(secret, vec.sharedSecret) {
				t.Errorf("decapsulate for vector %v: got shared secret %v, want %v", key, secret, vec.sharedSecret)
			}
		})
	}
	// Verify that we actually tested something.
	// If no vectors match the filter, then the test should fail because nothing was tested.
	if i == 0 {
		t.Error("no vectors were tested")
	}
}

// TestKEMDecapsulateEncapsulatedKeyPrefixesLargerSlice checks--if the
// encapsulated key is part of a larger slice, as in HPKE Encrypt
// https://github.com/tink-crypto/tink-go/blob/d25153b336507a5cc37555d3c1ed36ba41cb3f30/hybrid/internal/hpke/encrypt.go#L58
// --that decapsulate does not modify the larger slice.
func TestKEMDecapsulateEncapsulatedKeyPrefixesLargerSlice(t *testing.T) {
	for _, test := range rfcVectorTestCases(t) {
		t.Run(test.name, func(t *testing.T) {
			kem, err := newKEM(test.kemID)
			if err != nil {
				t.Fatal(err)
			}

			largerSlice := make([]byte, 3*len(test.vector.encapsulatedKey))
			suffix := largerSlice[len(test.vector.encapsulatedKey):]
			zeroedSlice := make([]byte, len(suffix))
			if !bytes.Equal(suffix, zeroedSlice) {
				t.Errorf("suffix: got %x, want %x", suffix, zeroedSlice)
			}

			copy(largerSlice, test.vector.encapsulatedKey)
			if !bytes.Equal(suffix, zeroedSlice) {
				t.Errorf("suffix: got %x, want %x", suffix, zeroedSlice)
			}

			encapsulatedKey := largerSlice[:len(test.vector.encapsulatedKey)]
			if _, err := kem.decapsulate(encapsulatedKey, test.vector.recipientPrivKey); err != nil {
				t.Errorf("decapsulate: got err %q, want success", err)
			}
			if !bytes.Equal(suffix, zeroedSlice) {
				t.Errorf("suffix: got %x, want %x", suffix, zeroedSlice)
			}
		})
	}
}

func TestKEMDecapsulateBadEncapsulatedKey(t *testing.T) {
	for _, test := range rfcVectorTestCases(t) {
		t.Run(test.name, func(t *testing.T) {
			kem, err := newKEM(test.kemID)
			if err != nil {
				t.Fatal(err)
			}
			badEncapsulatedKey := append(test.vector.encapsulatedKey, []byte("hello")...)
			if _, err := kem.decapsulate(badEncapsulatedKey, test.vector.recipientPrivKey); err == nil {
				t.Error("decapsulate: got success, want err")
			}
		})
	}
}

func TestKEMDecapsulateBadRecipientPrivKey(t *testing.T) {
	for _, test := range rfcVectorTestCases(t) {
		t.Run(test.name, func(t *testing.T) {
			kem, err := newKEM(test.kemID)
			if err != nil {
				t.Fatal(err)
			}
			badRecipientPrivKey := append(test.vector.recipientPrivKey, []byte("hello")...)
			if _, err := kem.decapsulate(test.vector.encapsulatedKey, badRecipientPrivKey); err == nil {
				t.Error("decapsulate: got success, want err")
			}
		})
	}
}

func TestKEMEncapsulatedKeyLength(t *testing.T) {
	tests := []struct {
		name  string
		kemID KEMID
		want  int
	}{
		{
			name:  "P-256",
			kemID: P256HKDFSHA256,
			want:  kemLengths[P256HKDFSHA256].nEnc,
		},
		{
			name:  "P-384",
			kemID: P384HKDFSHA384,
			want:  kemLengths[P384HKDFSHA384].nEnc,
		},
		{
			name:  "P-521",
			kemID: P521HKDFSHA512,
			want:  kemLengths[P521HKDFSHA512].nEnc,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kem, err := newKEM(test.kemID)
			if err != nil {
				t.Fatal(err)
			}
			if kem.encapsulatedKeyLength() != test.want {
				t.Errorf("encapsulatedKeyLength: got %d, want %d", kem.encapsulatedKeyLength(), test.want)
			}
		})
	}
}

func TestNewNISTCurvesKEM_UnknownKEMID(t *testing.T) {
	if _, err := newNISTCurvesKEM(UnknownKEMID); err == nil {
		t.Errorf("newPrimitives() err = nil, want error")
	}
}

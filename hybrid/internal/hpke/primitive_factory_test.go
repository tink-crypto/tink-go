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
	"fmt"
	"testing"
)

var kems = []struct {
	name  string
	kemID KEMID
}{
	{name: "DHKEM_P256_HKDF_SHA256", kemID: P256HKDFSHA256},
	{name: "DHKEM_P384_HKDF_SHA384", kemID: P384HKDFSHA384},
	{name: "DHKEM_P521_HKDF_SHA512", kemID: P521HKDFSHA512},
	{name: "DHKEM_X25519_HKDF_SHA256", kemID: X25519HKDFSHA256},
}

func TestNewKEM(t *testing.T) {
	for _, k := range kems {
		t.Run(k.name, func(t *testing.T) {
			kem, err := newKEM(k.kemID)
			if err != nil {
				t.Fatal(err)
			}
			if kem.id() != k.kemID {
				t.Errorf("id: got %d, want %d", kem.id(), k.kemID)
			}
		})
	}
}

func TestNewKEMUnsupportedID(t *testing.T) {
	if _, err := newKEM(0x0021 /*= DHKEM(X448, HKDF-SHA512)*/); err == nil {
		t.Fatal("newKEM(unsupported ID): got success, want err")
	}
}

var kdfs = []struct {
	name  string
	kdfID KDFID
}{
	{name: "HKDF_SHA256", kdfID: HKDFSHA256},
	{name: "HKDF_SHA384", kdfID: HKDFSHA384},
	{name: "HKDF_SHA512", kdfID: HKDFSHA512},
}

func TestNewKDF(t *testing.T) {
	for _, k := range kdfs {
		t.Run(k.name, func(t *testing.T) {
			kdf, err := newKDF(k.kdfID)
			if err != nil {
				t.Fatal(err)
			}
			if kdf.id() != k.kdfID {
				t.Errorf("id: got %d, want %d", kdf.id(), k.kdfID)
			}
		})
	}
}

func TestNewKDFUnsupportedID(t *testing.T) {
	if _, err := newKDF(0x0000 /*= Reserved*/); err == nil {
		t.Fatal("newKDF(unsupported ID): got success, want err")
	}
}

var aeads = []struct {
	name   string
	aeadID AEADID
}{
	{name: "AES-128-GCM", aeadID: AES128GCM},
	{name: "AES-256-GCM", aeadID: AES256GCM},
	{name: "ChaCha20Poly1305", aeadID: ChaCha20Poly1305},
}

func TestNewAEAD(t *testing.T) {
	for _, a := range aeads {
		t.Run(a.name, func(t *testing.T) {
			aead, err := newAEAD(a.aeadID)
			if err != nil {
				t.Fatal(err)
			}
			if aead.id() != a.aeadID {
				t.Errorf("id: got %d, want %d", aead.id(), a.aeadID)
			}
		})
	}
}

func TestNewAEADUnsupportedID(t *testing.T) {
	if _, err := newAEAD(0xFFFF /*= Export-only*/); err == nil {
		t.Fatal("newAEAD(unsupported ID): got success, want err")
	}
}

func TestNewPrimitivesFromProto(t *testing.T) {
	for _, kem := range kems {
		for _, kdf := range kdfs {
			for _, aead := range aeads {
				t.Run(fmt.Sprintf("%s %s %s", kem.name, kdf.name, aead.name), func(t *testing.T) {
					gotKEM, gotKDF, gotAEAD, err := newPrimitives(kem.kemID, kdf.kdfID, aead.aeadID)
					if err != nil {
						t.Fatalf("newPrimitives: %v", err)
					}
					if gotKEM.id() != kem.kemID {
						t.Errorf("kem.id: got %d, want %d", gotKEM.id(), kem.kemID)
					}
					if gotKDF.id() != kdf.kdfID {
						t.Errorf("kdf.id: got %d, want %d", gotKDF.id(), kdf.kdfID)
					}
					if gotAEAD.id() != aead.aeadID {
						t.Errorf("aead.id: got %d, want %d", gotAEAD.id(), aead.aeadID)
					}
				})
			}
		}
	}
}

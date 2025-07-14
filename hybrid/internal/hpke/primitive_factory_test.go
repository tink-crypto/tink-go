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

	pb "github.com/tink-crypto/tink-go/v2/proto/hpke_go_proto"
)

var kems = []struct {
	name  string
	proto pb.HpkeKem
	id    KEMID
}{
	{name: "DHKEM_P256_HKDF_SHA256", proto: pb.HpkeKem_DHKEM_P256_HKDF_SHA256, id: P256HKDFSHA256},
	{name: "DHKEM_P384_HKDF_SHA384", proto: pb.HpkeKem_DHKEM_P384_HKDF_SHA384, id: P384HKDFSHA384},
	{name: "DHKEM_P521_HKDF_SHA512", proto: pb.HpkeKem_DHKEM_P521_HKDF_SHA512, id: P521HKDFSHA512},
	{name: "DHKEM_X25519_HKDF_SHA256", proto: pb.HpkeKem_DHKEM_X25519_HKDF_SHA256, id: X25519HKDFSHA256},
}

func TestNewKEM(t *testing.T) {
	for _, k := range kems {
		t.Run(k.name, func(t *testing.T) {
			kemID, err := kemIDFromProto(k.proto)
			if err != nil {
				t.Fatal(err)
			}
			if kemID != k.id {
				t.Errorf("kemID: got %d, want %d", kemID, k.id)
			}

			kem, err := newKEM(k.id)
			if err != nil {
				t.Fatal(err)
			}
			if kem.id() != k.id {
				t.Errorf("id: got %d, want %d", kem.id(), k.id)
			}
		})
	}
}

func TestNewKEMUnsupportedID(t *testing.T) {
	if _, err := newKEM(0x0021 /*= DHKEM(X448, HKDF-SHA512)*/); err == nil {
		t.Fatal("newKEM(unsupported ID): got success, want err")
	}
}

func TestKEMIDFromProtoUnsupportedID(t *testing.T) {
	if _, err := kemIDFromProto(pb.HpkeKem_KEM_UNKNOWN); err == nil {
		t.Fatal("kemIDFromProto(unsupported ID): got success, want err")
	}
}

var kdfs = []struct {
	name  string
	proto pb.HpkeKdf
	id    KDFID
}{
	{name: "HKDF_SHA256", proto: pb.HpkeKdf_HKDF_SHA256, id: HKDFSHA256},
	{name: "HKDF_SHA384", proto: pb.HpkeKdf_HKDF_SHA384, id: HKDFSHA384},
	{name: "HKDF_SHA512", proto: pb.HpkeKdf_HKDF_SHA512, id: HKDFSHA512},
}

func TestNewKDF(t *testing.T) {
	for _, k := range kdfs {
		t.Run(k.name, func(t *testing.T) {
			kdfID, err := kdfIDFromProto(k.proto)
			if err != nil {
				t.Fatal(err)
			}
			if kdfID != k.id {
				t.Errorf("kdfID: got %d, want %d", kdfID, k.id)
			}

			kdf, err := newKDF(k.id)
			if err != nil {
				t.Fatal(err)
			}
			if kdf.id() != k.id {
				t.Errorf("id: got %d, want %d", kdf.id(), k.id)
			}
		})
	}
}

func TestNewKDFUnsupportedID(t *testing.T) {
	if _, err := newKDF(0x0000 /*= Reserved*/); err == nil {
		t.Fatal("newKDF(unsupported ID): got success, want err")
	}
}

func TestKDFIDFromProtoUnsupportedID(t *testing.T) {
	if _, err := kdfIDFromProto(pb.HpkeKdf_KDF_UNKNOWN); err == nil {
		t.Fatal("kdfIDFromProto(unsupported ID): got success, want err")
	}
}

var aeads = []struct {
	name  string
	proto pb.HpkeAead
	id    AEADID
}{
	{name: "AES-128-GCM", proto: pb.HpkeAead_AES_128_GCM, id: AES128GCM},
	{name: "AES-256-GCM", proto: pb.HpkeAead_AES_256_GCM, id: AES256GCM},
	{name: "ChaCha20Poly1305", proto: pb.HpkeAead_CHACHA20_POLY1305, id: ChaCha20Poly1305},
}

func TestNewAEAD(t *testing.T) {
	for _, a := range aeads {
		t.Run(a.name, func(t *testing.T) {
			aeadID, err := aeadIDFromProto(a.proto)
			if err != nil {
				t.Fatal(err)
			}
			if aeadID != a.id {
				t.Errorf("aeadID: got %d, want %d", aeadID, a.id)
			}

			aead, err := newAEAD(aeadID)
			if err != nil {
				t.Fatal(err)
			}
			if aead.id() != a.id {
				t.Errorf("id: got %d, want %d", aead.id(), a.id)
			}
		})
	}
}

func TestNewAEADUnsupportedID(t *testing.T) {
	if _, err := newAEAD(0xFFFF /*= Export-only*/); err == nil {
		t.Fatal("newAEAD(unsupported ID): got success, want err")
	}
}

func TestAEADIDFromProtoUnsupportedID(t *testing.T) {
	if _, err := aeadIDFromProto(pb.HpkeAead_AEAD_UNKNOWN); err == nil {
		t.Fatal("aeadIDFromProto(unsupported ID): got success, want err")
	}
}

func TestNewPrimitivesFromProto(t *testing.T) {
	for _, kem := range kems {
		for _, kdf := range kdfs {
			for _, aead := range aeads {
				t.Run(fmt.Sprintf("%s %s %s", kem.name, kdf.name, aead.name), func(t *testing.T) {
					params := &pb.HpkeParams{
						Kem:  kem.proto,
						Kdf:  kdf.proto,
						Aead: aead.proto,
					}
					gotKEM, gotKDF, gotAEAD, err := newPrimitivesFromProto(params)
					if err != nil {
						t.Fatalf("newPrimitivesFromProto: %v", err)
					}

					if gotKEM.id() != kem.id {
						t.Errorf("kem.id: got %d, want %d", gotKEM.id(), kem.id)
					}
					if gotKDF.id() != kdf.id {
						t.Errorf("kdf.id: got %d, want %d", gotKDF.id(), kdf.id)
					}
					if gotAEAD.id() != aead.id {
						t.Errorf("aead.id: got %d, want %d", gotAEAD.id(), aead.id)
					}
				})
			}
		}
	}
}

func TestNewPrimitivesFromProtoUnsupportedID(t *testing.T) {
	tests := []struct {
		name   string
		params *pb.HpkeParams
	}{
		{
			"KEM",
			&pb.HpkeParams{
				Kem:  pb.HpkeKem_KEM_UNKNOWN,
				Kdf:  pb.HpkeKdf_HKDF_SHA256,
				Aead: pb.HpkeAead_AES_256_GCM,
			},
		},
		{"KDF",
			&pb.HpkeParams{
				Kem:  pb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
				Kdf:  pb.HpkeKdf_KDF_UNKNOWN,
				Aead: pb.HpkeAead_AES_256_GCM,
			},
		},
		{"AEAD",
			&pb.HpkeParams{
				Kem:  pb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
				Kdf:  pb.HpkeKdf_HKDF_SHA256,
				Aead: pb.HpkeAead_AEAD_UNKNOWN,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, _, err := newPrimitivesFromProto(test.params); err == nil {
				t.Error("newPrimitivesFromProto: got success, want err")
			}
		})
	}
}

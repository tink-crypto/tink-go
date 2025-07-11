// Copyright 2019 Google LLC
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

package ecies_test

import (
	"bytes"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/hybrid/internal/ecies"
	"github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func basicMultipleEncrypts(t *testing.T, c string, keyTemplate *tinkpb.KeyTemplate) {
	t.Helper()
	curve, err := subtle.GetCurve(c)
	if err != nil {
		t.Fatalf("subtle.GetCurve(%s) err = %v, want nil", c, err)
	}
	pvt, err := subtle.GenerateECDHKeyPair(curve)
	if err != nil {
		t.Fatalf("subtle.GenerateECDHKeyPair() err = %v, want nil", err)
	}
	salt := []byte("some salt")
	pt := random.GetRandomBytes(20)
	context := []byte("context info")

	parameters, err := protoserialization.ParseParameters(keyTemplate)
	if err != nil {
		t.Fatalf("protoserialization.ParseParameters() err = %v, want nil", err)
	}
	rDem, err := ecies.NewDEMHelper(parameters)
	if err != nil {
		t.Fatalf("ecies.NewDEMHelper() err = %v, want nil", err)
	}
	e, err := subtle.NewECIESAEADHKDFHybridEncrypt(&pvt.PublicKey, salt, "SHA256", "UNCOMPRESSED", rDem)
	if err != nil {
		t.Fatalf("subtle.NewECIESAEADHKDFHybridEncrypt() err = %v, want nil", err)
	}
	d, err := subtle.NewECIESAEADHKDFHybridDecrypt(pvt, salt, "SHA256", "UNCOMPRESSED", rDem)
	if err != nil {
		t.Fatalf("subtle.NewECIESAEADHKDFHybridDecrypt() err = %v, want nil", err)
	}
	cl := [][]byte{}
	for i := 0; i < 8; i++ {
		ct, err := e.Encrypt(pt, context)
		if err != nil {
			t.Fatalf("e.Encrypt() err = %v, want nil", err)
		}
		for _, c := range cl {
			if bytes.Equal(ct, c) {
				t.Fatalf("encryption is not randomized")
			}
		}
		cl = append(cl, ct)
		dt, err := d.Decrypt(ct, context)
		if err != nil {
			t.Fatalf("d.Decrypt() err = %v, want nil", err)
		}
		if !bytes.Equal(dt, pt) {
			t.Fatalf("d.Decrypt() = %v, want %v", dt, pt)
		}
	}
	if len(cl) != 8 {
		t.Errorf("len(cl) = %v, want 8", len(cl))
	}
}

func TestECAESCTRHMACSHA256Encrypt(t *testing.T) {
	basicMultipleEncrypts(t, "NIST_P256", aead.AES256CTRHMACSHA256KeyTemplate())
	basicMultipleEncrypts(t, "NIST_P384", aead.AES256CTRHMACSHA256KeyTemplate())
	basicMultipleEncrypts(t, "NIST_P521", aead.AES256CTRHMACSHA256KeyTemplate())
	basicMultipleEncrypts(t, "NIST_P224", aead.AES256CTRHMACSHA256KeyTemplate())

	basicMultipleEncrypts(t, "NIST_P256", aead.AES128CTRHMACSHA256KeyTemplate())
	basicMultipleEncrypts(t, "NIST_P384", aead.AES128CTRHMACSHA256KeyTemplate())
	basicMultipleEncrypts(t, "NIST_P521", aead.AES128CTRHMACSHA256KeyTemplate())
	basicMultipleEncrypts(t, "NIST_P224", aead.AES128CTRHMACSHA256KeyTemplate())
}

func TestECAES256GCMEncrypt(t *testing.T) {
	basicMultipleEncrypts(t, "NIST_P256", aead.AES256GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P384", aead.AES256GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P521", aead.AES256GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P224", aead.AES256GCMKeyTemplate())

	basicMultipleEncrypts(t, "NIST_P256", aead.AES128GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P384", aead.AES128GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P521", aead.AES128GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P224", aead.AES128GCMKeyTemplate())
}

func TestECAESSIVEncrypt(t *testing.T) {
	basicMultipleEncrypts(t, "NIST_P256", daead.AESSIVKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P384", daead.AESSIVKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P521", daead.AESSIVKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P224", daead.AESSIVKeyTemplate())
}

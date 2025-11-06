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

package streamingaeadconfig_test

import (
	"bytes"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/internal/config/streamingaeadconfig"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesctrhmac"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesgcmhkdf"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestConfigV0StreamingAEADFailsIfKeyNotStreamingAEAD(t *testing.T) {
	configV0 := streamingaeadconfig.V0()
	aesGCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
		IVSizeInBytes:  12,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	keyMaterial := secretdata.NewBytesFromData([]byte("12345678901234567890123456789012"), testonlyinsecuresecretdataaccess.Token())
	aesGCMKey, err := aesgcm.NewKey(keyMaterial, 0, aesGCMParams)
	if err != nil {
		t.Fatalf("aesgcm.NewKey() err = %v, want nil", err)
	}
	if _, err := configV0.PrimitiveFromKey(aesGCMKey, internalapi.Token{}); err == nil {
		t.Errorf("configV0.PrimitiveFromKey() err = nil, want error")
	}
}

func TestConfigV0StreamingAEAD(t *testing.T) {
	configV0 := streamingaeadconfig.V0()

	// AES-CTR-HMAC
	aesCTRHMACParams, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		KeySizeInBytes:        32,
		HkdfHashType:          aesctrhmac.SHA256,
		DerivedKeySizeInBytes: 32,
		HmacHashType:          aesctrhmac.SHA256,
		HmacTagSizeInBytes:    16,
		SegmentSizeInBytes:    1024,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
	}
	keyMaterialCTRHMAC := secretdata.NewBytesFromData([]byte("12345678901234567890123456789012"), testonlyinsecuresecretdataaccess.Token())
	aesCTRHMACKey, err := aesctrhmac.NewKey(aesCTRHMACParams, keyMaterialCTRHMAC)
	if err != nil {
		t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
	}

	// AES-GCM-HKDF
	aesGCMHKDFParams, err := aesgcmhkdf.NewParameters(aesgcmhkdf.ParametersOpts{
		KeySizeInBytes:        32,
		DerivedKeySizeInBytes: 32,
		SegmentSizeInBytes:    1024,
		HKDFHashType:          aesgcmhkdf.SHA256,
	})
	if err != nil {
		t.Fatalf("aesgcmhkdf.NewParameters() err = %v, want nil", err)
	}
	keyMaterialGCMHKDF := secretdata.NewBytesFromData([]byte("12345678901234567890123456789012"), testonlyinsecuresecretdataaccess.Token())
	aesGCMHKDFKey, err := aesgcmhkdf.NewKey(aesGCMHKDFParams, keyMaterialGCMHKDF)
	if err != nil {
		t.Fatalf("aesgcmhkdf.NewKey() err = %v, want nil", err)
	}

	for _, test := range []struct {
		name string
		key  key.Key
	}{
		{
			name: "AES-CTR-HMAC",
			key:  aesCTRHMACKey,
		},
		{
			name: "AES-GCM-HKDF",
			key:  aesGCMHKDFKey,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ps, err := protoserialization.SerializeKey(test.key)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey() err = %v, want nil", err)
			}
			if _, err := configV0.PrimitiveFromKeyData(ps.KeyData(), internalapi.Token{}); err == nil {
				t.Fatalf("configV0.PrimitiveFromKeyData() err = nil, want error")
			}

			p, err := configV0.PrimitiveFromKey(test.key, internalapi.Token{})
			if err != nil {
				t.Fatalf("configV0.PrimitiveFromKey() err = %v, want nil", err)
			}
			sa, ok := p.(tink.StreamingAEAD)
			if !ok {
				t.Fatalf("p was of type %v, want tink.StreamingAEAD", reflect.TypeOf(p))
			}

			plaintext := []byte("some plaintext")
			aad := []byte("some associated data")

			ctBuf := &bytes.Buffer{}
			w, err := sa.NewEncryptingWriter(ctBuf, aad)
			if err != nil {
				t.Fatalf("sa.NewEncryptingWriter() err = %v, want nil", err)
			}
			if _, err := w.Write(plaintext); err != nil {
				t.Fatalf("w.Write() err = %v, want nil", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("w.Close() err = %v, want nil", err)
			}
			ciphertext := ctBuf.Bytes()

			r, err := sa.NewDecryptingReader(bytes.NewReader(ciphertext), aad)
			if err != nil {
				t.Fatalf("sa.NewDecryptingReader() err = %v, want nil", err)
			}
			got, err := ioutil.ReadAll(r)
			if err != nil {
				t.Fatalf("ioutil.ReadAll() err = %v, want nil", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("r.Read() = %v, want %v", got, plaintext)
			}
		})
	}
}

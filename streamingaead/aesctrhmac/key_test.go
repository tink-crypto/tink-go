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

package aesctrhmac_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesctrhmac"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestNewKey_Fails(t *testing.T) {
	params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		KeySizeInBytes:        32,
		DerivedKeySizeInBytes: 32,
		HkdfHashType:          aesctrhmac.SHA256,
		HmacHashType:          aesctrhmac.SHA256,
		HmacTagSizeInBytes:    32,
		SegmentSizeInBytes:    4096,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name       string
		keyBytes   secretdata.Bytes
		parameters *aesctrhmac.Parameters
	}{
		{
			name:       "nil parameters",
			keyBytes:   secretdata.NewBytesFromData([]byte("0123456789abcdef0123456789abcdef"), testonlyinsecuresecretdataaccess.Token()),
			parameters: nil,
		},
		{
			name:       "invalid key size",
			keyBytes:   secretdata.NewBytesFromData([]byte("0123456789abcdef"), testonlyinsecuresecretdataaccess.Token()),
			parameters: params,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := aesctrhmac.NewKey(tc.parameters, tc.keyBytes); err == nil {
				t.Errorf("aesctrhmac.NewKey() err = nil, want error")
			}
		})
	}
}

func TestNewKey_Success(t *testing.T) {
	keyBytes := []byte("0123456789abcdef0123456789abcdef")
	for _, tc := range getParametersTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			params, err := aesctrhmac.NewParameters(tc.parameterOpts)
			if err != nil {
				t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
			}
			secretKeyBytes := secretdata.NewBytesFromData(keyBytes[:tc.parameterOpts.KeySizeInBytes], testonlyinsecuresecretdataaccess.Token())
			k, err := aesctrhmac.NewKey(params, secretKeyBytes)
			if err != nil {
				t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
			}
			if diff := cmp.Diff(params, k.Parameters()); diff != "" {
				t.Errorf("k.Parameters() returned unexpected diff (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(secretKeyBytes, k.KeyBytes()); diff != "" {
				t.Errorf("k.KeyBytes() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

type stubKey struct{}

var _ key.Key = (*stubKey)(nil)

func (k *stubKey) Parameters() key.Parameters    { return nil }
func (k *stubKey) Equal(other key.Key) bool      { return true }
func (k *stubKey) IDRequirement() (uint32, bool) { return 0, false }

func TestKeyEqual_FalseIfDifferent(t *testing.T) {
	params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		KeySizeInBytes:        32,
		DerivedKeySizeInBytes: 32,
		HkdfHashType:          aesctrhmac.SHA256,
		HmacHashType:          aesctrhmac.SHA256,
		HmacTagSizeInBytes:    32,
		SegmentSizeInBytes:    4096,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
	}
	keyBytes := secretdata.NewBytesFromData([]byte("0123456789abcdef0123456789abcdef"), testonlyinsecuresecretdataaccess.Token())
	k, err := aesctrhmac.NewKey(params, keyBytes)
	if err != nil {
		t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name string
		key  key.Key
	}{
		{
			name: "different_key_size",
			key: func() *aesctrhmac.Key {
				params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
					KeySizeInBytes:        16,
					DerivedKeySizeInBytes: 16,
					HkdfHashType:          aesctrhmac.SHA256,
					HmacHashType:          aesctrhmac.SHA256,
					HmacTagSizeInBytes:    32,
					SegmentSizeInBytes:    4096,
				},
				)
				if err != nil {
					t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
				}
				keyBytes := secretdata.NewBytesFromData([]byte("0123456789abcdef"), testonlyinsecuresecretdataaccess.Token())
				k, err := aesctrhmac.NewKey(params, keyBytes)
				if err != nil {
					t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
				}
				return k
			}(),
		},
		{
			name: "different_key_bytes",
			key: func() *aesctrhmac.Key {
				params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
					KeySizeInBytes:        32,
					DerivedKeySizeInBytes: 32,
					HkdfHashType:          aesctrhmac.SHA256,
					HmacHashType:          aesctrhmac.SHA256,
					HmacTagSizeInBytes:    32,
					SegmentSizeInBytes:    4096,
				},
				)
				if err != nil {
					t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
				}
				keyBytes := secretdata.NewBytesFromData([]byte("fedcba9876543210fedcba9876543210"), testonlyinsecuresecretdataaccess.Token())
				k, err := aesctrhmac.NewKey(params, keyBytes)
				if err != nil {
					t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
				}
				return k
			}(),
		},
		{
			name: "different_key_type",
			key:  &stubKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.key, k); diff == "" {
				t.Errorf("k.Equal(k2) = true, want false, diff: %v", diff)
			}
		})
	}
}

func TestKeyCreator(t *testing.T) {
	params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		KeySizeInBytes:        32,
		DerivedKeySizeInBytes: 32,
		HkdfHashType:          aesctrhmac.SHA256,
		HmacHashType:          aesctrhmac.SHA256,
		HmacTagSizeInBytes:    32,
		SegmentSizeInBytes:    4096,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
	}

	key, err := keygenregistry.CreateKey(params, 0)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey(%v, 0) err = %v, want nil", params, err)
	}
	aesGCMKey, ok := key.(*aesctrhmac.Key)
	if !ok {
		t.Fatalf("keygenregistry.CreateKey(%v, 0) returned key of type %T, want %T", params, key, (*aesctrhmac.Key)(nil))
	}

	idRequirement, hasIDRequirement := aesGCMKey.IDRequirement()
	if hasIDRequirement || idRequirement != 0 {
		t.Errorf("aesGCMKey.IDRequirement() (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 0, true)
	}
	if got := aesGCMKey.KeyBytes().Len(); got != params.KeySizeInBytes() {
		t.Errorf("aesGCMKey.KeyBytes().Len() = %d, want 32", aesGCMKey.KeyBytes().Len())
	}
	if diff := cmp.Diff(aesGCMKey.Parameters(), params); diff != "" {
		t.Errorf("aesGCMKey.Parameters() diff (-want +got):\n%s", diff)
	}

	config := &registryconfig.RegistryConfig{}
	p, err := config.PrimitiveFromKey(key, internalapi.Token{})
	if err != nil {
		t.Fatalf("config.PrimitiveFromKey(%v, %v) err = %v, want nil", key, internalapi.Token{}, err)
	}
	streamingAEAD, ok := p.(tink.StreamingAEAD)
	if !ok {
		t.Errorf("config.PrimitiveFromKey(%v, %v) did not return a AESCTRHMAC primitive", key, internalapi.Token{})
	}

	// Encrypt and decrypt some data.
	plaintext := []byte("plaintext")
	ciphertextBuffer := bytes.NewBuffer(nil)
	writer, err := streamingAEAD.NewEncryptingWriter(ciphertextBuffer, []byte("aad"))
	if err != nil {
		t.Fatalf("streamingAEAD.NewEncryptingWriter() err = %v, want nil", err)
	}
	if _, err := io.Copy(writer, bytes.NewBuffer(plaintext)); err != nil {
		t.Fatalf("io.Copy() err = %v, want nil", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close() err = %v, want nil", err)
	}
	reader, err := streamingAEAD.NewDecryptingReader(ciphertextBuffer, []byte("aad"))
	if err != nil {
		t.Fatalf("streamingAEAD.NewDecryptingReader() err = %v, want nil", err)
	}
	decryptedBuffer := bytes.NewBuffer(nil)
	if _, err := io.Copy(decryptedBuffer, reader); err != nil {
		t.Fatalf("io.Copy() err = %v, want nil", err)
	}
	if diff := cmp.Diff(plaintext, decryptedBuffer.Bytes()); diff != "" {
		t.Errorf("decryptedBuffer.Bytes() diff (-want +got):\n%s", diff)
	}
}

func TestKeyCreator_FailsIfUnsupportedParamValues(t *testing.T) {
	for _, tc := range []struct {
		name       string
		parameters *aesctrhmac.Parameters
	}{
		{
			name: "unsupported key size",
			parameters: mustCreateParameters(t, aesctrhmac.ParametersOpts{
				KeySizeInBytes:        33,
				DerivedKeySizeInBytes: 32,
				HkdfHashType:          aesctrhmac.SHA256,
				HmacHashType:          aesctrhmac.SHA256,
				HmacTagSizeInBytes:    32,
				SegmentSizeInBytes:    4096,
			}),
		},
		{
			name: "unsupported HKDF hash type",
			parameters: mustCreateParameters(t, aesctrhmac.ParametersOpts{
				KeySizeInBytes:        32,
				DerivedKeySizeInBytes: 32,
				HkdfHashType:          aesctrhmac.SHA1,
				HmacHashType:          aesctrhmac.SHA256,
				HmacTagSizeInBytes:    32,
				SegmentSizeInBytes:    4096,
			}),
		},
		{
			name: "unsupported HMAC hash type",
			parameters: mustCreateParameters(t, aesctrhmac.ParametersOpts{
				KeySizeInBytes:        32,
				DerivedKeySizeInBytes: 32,
				HkdfHashType:          aesctrhmac.SHA256,
				HmacHashType:          aesctrhmac.SHA1,
				HmacTagSizeInBytes:    20,
				SegmentSizeInBytes:    4096,
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := keygenregistry.CreateKey(tc.parameters, 0); err == nil {
				t.Fatalf("keygenregistry.CreateKey(%v, 0) err = nil, want error", tc.parameters)
			} else {
				t.Logf("keygenregistry.CreateKey(%v, 0) err = %v", tc.parameters, err)
			}
		})
	}
}

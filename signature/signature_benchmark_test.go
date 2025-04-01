// Copyright 2024 Google LLC
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

package signature_test

import (
	"testing"

	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// Benchmarks for Signature algorithms.

const benchmarkDataSize = 16 * 1024

func mustCreateECDSAParams(curveType ecdsa.CurveType, hashType ecdsa.HashType, encoding ecdsa.SignatureEncoding, variant ecdsa.Variant) key.Parameters {
	params, err := ecdsa.NewParameters(curveType, hashType, encoding, variant)
	if err != nil {
		panic(err)
	}
	return params
}

var benchmarkTestCases = []struct {
	name     string
	template *tinkpb.KeyTemplate
	params   key.Parameters
}{
	{
		name:     "RSA_SSA_PKCS1_3072",
		template: signature.RSA_SSA_PKCS1_3072_SHA256_F4_Key_Template(),
	}, {
		name:     "RSA_SSA_PSS_3072",
		template: signature.RSA_SSA_PSS_3072_SHA256_32_F4_Key_Template(),
	}, {
		name:     "RSA_SSA_PKCS1_4096",
		template: signature.RSA_SSA_PKCS1_4096_SHA512_F4_Key_Template(),
	}, {
		name:     "RSA_SSA_PSS_4096",
		template: signature.RSA_SSA_PSS_4096_SHA512_64_F4_Key_Template(),
	}, {
		name:   "ECDSA_P256",
		params: mustCreateECDSAParams(ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantTink),
	}, {
		name:   "ECDSA_P256_RAW",
		params: mustCreateECDSAParams(ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantNoPrefix),
	}, {
		name:   "ECDSA_P256_LEGACY",
		params: mustCreateECDSAParams(ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantLegacy),
	}, {
		name:   "ECDSA_P384",
		params: mustCreateECDSAParams(ecdsa.NistP384, ecdsa.SHA384, ecdsa.DER, ecdsa.VariantTink),
	}, {
		name:   "ECDSA_P521",
		params: mustCreateECDSAParams(ecdsa.NistP521, ecdsa.SHA512, ecdsa.DER, ecdsa.VariantTink),
	}, {
		name:     "ED25519",
		template: signature.ED25519KeyTemplate(),
	},
}

func mustCreateKeyset(b *testing.B, template *tinkpb.KeyTemplate, params key.Parameters) *keyset.Handle {
	km := keyset.NewManager()
	var keyID uint32
	var err error
	if params != nil {
		keyID, err = km.AddNewKeyFromParameters(params)
	} else {
		keyID, err = km.Add(template)
	}
	if err != nil {
		b.Fatal(err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		b.Fatal(err)
	}
	handle, err := km.Handle()
	if err != nil {
		b.Fatal(err)
	}
	return handle
}

func BenchmarkSign(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle := mustCreateKeyset(b, tc.template, tc.params)
			primitive, err := signature.NewSigner(handle)
			if err != nil {
				b.Fatal(err)
			}
			data := random.GetRandomBytes(benchmarkDataSize)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err = primitive.Sign(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle := mustCreateKeyset(b, tc.template, tc.params)
			signer, err := signature.NewSigner(handle)
			if err != nil {
				b.Fatal(err)
			}
			data := random.GetRandomBytes(benchmarkDataSize)
			sig, err := signer.Sign(data)
			if err != nil {
				b.Fatal(err)
			}
			publicHandle, err := handle.Public()
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := signature.NewVerifier(publicHandle)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err = primitive.Verify(sig, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

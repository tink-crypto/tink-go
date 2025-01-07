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

package aead_test

import (
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// Benchmarks for AEAD algorithms.

type testCase struct {
	name          string
	template      *tinkpb.KeyTemplate
	plaintextSize uint32
}

func testCases() []testCase {
	tcs := []testCase{}
	for _, plaintextSize := range []uint32{
		1,               // 1 Byte
		1 * 1024,        // 1 KByte,
		1 * 1024 * 1024, // 1 MByte
	} {
		tcs = append(tcs, testCase{
			name:          fmt.Sprintf("AES128_GCM-%d", plaintextSize),
			template:      aead.AES128GCMKeyTemplate(),
			plaintextSize: plaintextSize,
		})
		tcs = append(tcs, testCase{
			name:          fmt.Sprintf("AES256_GCM-%d", plaintextSize),
			template:      aead.AES256GCMKeyTemplate(),
			plaintextSize: plaintextSize,
		})
		tcs = append(tcs, testCase{
			name:          fmt.Sprintf("CHACHA20_POLY1305-%d", plaintextSize),
			template:      aead.ChaCha20Poly1305KeyTemplate(),
			plaintextSize: plaintextSize,
		})
		tcs = append(tcs, testCase{
			name:          fmt.Sprintf("XCHACHA20_POLY1305-%d", plaintextSize),
			template:      aead.XChaCha20Poly1305KeyTemplate(),
			plaintextSize: plaintextSize,
		})
		tcs = append(tcs, testCase{
			name:          fmt.Sprintf("AES128_CTR_HMAC-%d", plaintextSize),
			template:      aead.AES128CTRHMACSHA256KeyTemplate(),
			plaintextSize: plaintextSize,
		})
		tcs = append(tcs, testCase{
			name:          fmt.Sprintf("AES256_CTR_HMAC-%d", plaintextSize),
			template:      aead.AES256CTRHMACSHA256KeyTemplate(),
			plaintextSize: plaintextSize,
		})
		tcs = append(tcs, testCase{
			name:          fmt.Sprintf("AES128_GCM_SIV-%d", plaintextSize),
			template:      aead.AES128GCMSIVKeyTemplate(),
			plaintextSize: plaintextSize,
		})
		tcs = append(tcs, testCase{
			name:          fmt.Sprintf("AES256_GCM_SIV-%d", plaintextSize),
			template:      aead.AES256GCMSIVKeyTemplate(),
			plaintextSize: plaintextSize,
		})
		tcs = append(tcs, testCase{
			name:          fmt.Sprintf("XAES256_GCM-%d", plaintextSize),
			template:      aead.XAES256GCM192BitNonceKeyTemplate(),
			plaintextSize: plaintextSize,
		})
	}
	return tcs
}

func BenchmarkEncrypt(b *testing.B) {
	const associatedDataSize = 256
	for _, tc := range testCases() {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := aead.New(handle)
			if err != nil {
				b.Fatal(err)
			}
			plaintext := random.GetRandomBytes(tc.plaintextSize)
			associatedData := random.GetRandomBytes(associatedDataSize)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := primitive.Encrypt(plaintext, associatedData)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	const associatedDataSize = 256
	for _, tc := range testCases() {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := aead.New(handle)
			if err != nil {
				b.Fatal(err)
			}
			plaintext := random.GetRandomBytes(tc.plaintextSize)
			associatedData := random.GetRandomBytes(associatedDataSize)
			ciphertext, err := primitive.Encrypt(plaintext, associatedData)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err = primitive.Decrypt(ciphertext, associatedData); err != nil {
					b.Error(err)
				}
			}
		})
	}
}

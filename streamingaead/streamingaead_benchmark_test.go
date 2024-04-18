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

package streamingaead_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// Benchmarks for Steaming AEAD algorithms.

func BenchmarkEncryptDecrypt(b *testing.B) {
	const (
		blockSize          = 16 * 1024 // amount of data written/read in each operation.
		operations         = 1024      // number of operations.
		plaintextSize      = blockSize * operations
		associatedDataSize = 256
	)

	testCases := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "AES128_GCM_HKDF_4KB",
			template: streamingaead.AES128GCMHKDF4KBKeyTemplate(),
		}, {
			name:     "AES128_GCM_HKDF_1MB",
			template: streamingaead.AES128GCMHKDF1MBKeyTemplate(),
		}, {
			name:     "AES256_GCM_HKDF_4KB",
			template: streamingaead.AES256GCMHKDF4KBKeyTemplate(),
		}, {
			name:     "AES256_GCM_HKDF_1MB",
			template: streamingaead.AES256GCMHKDF1MBKeyTemplate(),
		}, {
			name:     "AES128_CTR_HMAC_SHA256_4KB",
			template: streamingaead.AES128CTRHMACSHA256Segment4KBKeyTemplate(),
		}, {
			name:     "AES128_CTR_HMAC_SHA256_1MB",
			template: streamingaead.AES128CTRHMACSHA256Segment1MBKeyTemplate(),
		}, {
			name:     "AES256_CTR_HMAC_SHA256_4KB",
			template: streamingaead.AES256CTRHMACSHA256Segment4KBKeyTemplate(),
		}, {
			name:     "AES256_CTR_HMAC_SHA256_1MB",
			template: streamingaead.AES256CTRHMACSHA256Segment1MBKeyTemplate(),
		},
	}
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := streamingaead.New(handle)
			if err != nil {
				b.Fatal(err)
			}
			plaintextBlock := random.GetRandomBytes(blockSize)
			associatedData := random.GetRandomBytes(associatedDataSize)
			// Make ciphertextBuf large enough so that buffer doesn't need to re-allocate data.
			ciphertextBufferSize := 2*plaintextSize + 128
			ciphertextBuf := make([]byte, ciphertextBufferSize)
			decryptedBuf := make([]byte, blockSize)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buffer := bytes.NewBuffer(ciphertextBuf[:0])

				w, err := primitive.NewEncryptingWriter(buffer, associatedData)
				if err != nil {
					b.Fatal(err)
				}

				totalWritten := 0
				for i := 0; i < operations; i++ {
					n, err := w.Write(plaintextBlock)
					if err != nil {
						b.Fatal(err)
					}
					if n != blockSize {
						b.Fatalf("w.Write(plaintextBlock) = %d, want %d", n, blockSize)
					}
					totalWritten += n
				}
				if err := w.Close(); err != nil {
					b.Fatal(err)
				}
				if totalWritten != plaintextSize {
					b.Fatalf("totalWritten = %d, want %d", totalWritten, plaintextSize)
				}

				r, err := primitive.NewDecryptingReader(buffer, associatedData)
				if err != nil {
					b.Fatal(err)
				}

				totalRead := 0
				for {
					n, err := r.Read(decryptedBuf)
					if err == io.EOF {
						break
					}
					if err != nil {
						b.Fatal(err)
					}
					totalRead += n
				}
				if totalRead != plaintextSize {
					b.Fatalf("totalRead = %d, want %d", totalRead, plaintextSize)
				}
				if cap(buffer.Bytes()) != ciphertextBufferSize {
					b.Fatalf(
						"want that buffer to uses at most %d memory, but it now has capacity %d",
						ciphertextBufferSize, cap(buffer.Bytes()))
				}
			}
		})
	}
}

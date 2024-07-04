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
//
// //////////////////////////////////////////////////////////////////////////////

package keyset_test

import (
	"math/rand"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// newTestKeysetHandle creates a keyset handle with numKeys keys of the given
// key template. The last key is the primary.
func newTestKeysetHandle(b *testing.B, kt *tinkpb.KeyTemplate, numKeys int) *keyset.Handle {
	manager := keyset.NewManager()
	for i := 0; i < numKeys; i++ {
		keyID, err := manager.Add(kt)
		if err != nil {
			b.Fatalf("%v", err)
		}
		if err = manager.SetPrimary(keyID); err != nil {
			b.Fatalf("%v", err)
		}
	}
	h, err := manager.Handle()
	if err != nil {
		b.Fatalf("%v", err)
	}
	return h
}

var benchmarkTestCases = []struct {
	name    string
	numKeys int
}{
	{
		name:    "single key",
		numKeys: 1,
	},
	{
		name:    "medium size keyset",
		numKeys: 10,
	},
	{
		name:    "large size keyset",
		numKeys: 100,
	},
}

func BenchmarkNewHandleWithNoSecrets(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			h := newTestKeysetHandle(b, signature.ECDSAP256KeyTemplate(), tc.numKeys)
			publicHandle, err := h.Public()
			if err != nil {
				b.Fatalf("%v", err)
			}
			publicKeyset := testkeyset.KeysetMaterial(publicHandle)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := keyset.NewHandleWithNoSecrets(publicKeyset); err != nil {
					b.Fatalf("%v", err)
				}
			}
		})
	}
}

func BenchmarkHandlePrimitives(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			h := newTestKeysetHandle(b, aead.AES128GCMKeyTemplate(), tc.numKeys)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := h.Primitives(); err != nil {
					b.Fatalf("%v", err)
				}
			}
		})
	}
}

func BenchmarkHandleEntry(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			h := newTestKeysetHandle(b, aead.AES128GCMKeyTemplate(), tc.numKeys)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				i := rand.Intn(h.Len())
				if _, err := h.Entry(i); err != nil {
					b.Fatalf("%v", err)
				}
			}
		})
	}
}

func BenchmarkHandlePrimary(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			h := newTestKeysetHandle(b, aead.AES128GCMKeyTemplate(), tc.numKeys)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := h.Primary(); err != nil {
					b.Fatalf("%v", err)
				}
			}
		})
	}
}

func BenchmarkHandlePublic(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			h := newTestKeysetHandle(b, signature.ECDSAP256KeyTemplate(), tc.numKeys)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := h.Public(); err != nil {
					b.Fatalf("%v", err)
				}
			}
		})
	}
}

func BenchmarkHandleKeysetInfo(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			h := newTestKeysetHandle(b, aead.AES128GCMKeyTemplate(), tc.numKeys)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if h.KeysetInfo() == nil {
					b.Fatalf("KeysetInfo is nil")
				}
			}
		})
	}
}

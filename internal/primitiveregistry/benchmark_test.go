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

package primitiveregistry_test

import (
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveregistry"

	_ "github.com/tink-crypto/tink-go/v2/aead"           // To register primitives.
	_ "github.com/tink-crypto/tink-go/v2/mac"             // To register primitives.
	_ "github.com/tink-crypto/tink-go/v2/signature" // To register primitives.
)

func BenchmarkPrimitive(b *testing.B) {
	aesGCMKeyParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantTink,
	})
	if err != nil {
		b.Fatalf("%v", err)
	}
	aesGCMKey, err := keygenregistry.CreateKey(aesGCMKeyParams, 0x1234)
	if err != nil {
		b.Fatalf("%v", err)
	}
	b.Run("Primitive", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := primitiveregistry.Primitive(aesGCMKey); err != nil {
				b.Fatalf("%v", err)
			}
		}
	})
}

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

package mldsa

import (
	"math/rand"
	"testing"
)

const benchmarkDataSize = 16 * 1024

var benchmarkTestCases = []struct {
	name       string
	parameters *params
}{
	{
		name:       "ML_DSA_44",
		parameters: MLDSA44,
	},
	{
		name:       "ML_DSA_65",
		parameters: MLDSA65,
	},
	{
		name:       "ML_DSA_87",
		parameters: MLDSA87,
	},
}

func BenchmarkKeyGen(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tc.parameters.KeyGen()
			}
		})
	}
}

func BenchmarkSign(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			_, secretKey := tc.parameters.KeyGen()
			data := make([]byte, benchmarkDataSize)
			rand.Read(data)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := secretKey.Sign(data, []byte{}); err != nil {
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
			publicKey, secretKey := tc.parameters.KeyGen()
			data := make([]byte, benchmarkDataSize)
			rand.Read(data)
			sig, err := secretKey.Sign(data, []byte{})
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err = publicKey.Verify(data, sig, []byte{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

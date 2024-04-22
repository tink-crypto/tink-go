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

package jwt_test

import (
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// Benchmarks for JWT MAC algorithms.

var macBenchmarkTestCases = []struct {
	name     string
	template *tinkpb.KeyTemplate
}{
	{
		name:     "JWT_HS256",
		template: jwt.HS256Template(),
	}, {
		name:     "JWT_HS384",
		template: jwt.HS384Template(),
	}, {
		name:     "JWT_HS512",
		template: jwt.HS512Template(),
	},
}

func BenchmarkComputeMAC(b *testing.B) {
	for _, tc := range macBenchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := jwt.NewMAC(handle)
			if err != nil {
				b.Fatal(err)
			}

			expiresAt := time.Now().Add(time.Hour)
			audience := "example audience"
			subject := "example subject"
			rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{
				Audience:  &audience,
				Subject:   &subject,
				ExpiresAt: &expiresAt,
			})
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err = primitive.ComputeMACAndEncode(rawJWT); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerifyMAC(b *testing.B) {
	for _, tc := range macBenchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := jwt.NewMAC(handle)
			if err != nil {
				b.Fatal(err)
			}
			expiresAt := time.Now().Add(time.Hour)
			audience := "example audience"
			subject := "example subject"
			rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{
				Audience:  &audience,
				Subject:   &subject,
				ExpiresAt: &expiresAt,
			})
			if err != nil {
				b.Fatal(err)
			}
			token, err := primitive.ComputeMACAndEncode(rawJWT)
			if err != nil {
				b.Fatal(err)
			}
			validator, err := jwt.NewValidator(&jwt.ValidatorOpts{ExpectedAudience: &audience})
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := primitive.VerifyMACAndDecode(token, validator); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

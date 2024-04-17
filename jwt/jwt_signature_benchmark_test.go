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

// Benchmarks for JWT Signature algorithms.

var signatureBenchmarkTestCases = []struct {
	name     string
	template *tinkpb.KeyTemplate
}{
	{
		name:     "JWT_RS256_2048",
		template: jwt.RS256_2048_F4_Key_Template(),
	}, {
		name:     "JWT_RS256_3072",
		template: jwt.RS256_3072_F4_Key_Template(),
	}, {
		name:     "JWT_RS384_3072",
		template: jwt.RS384_3072_F4_Key_Template(),
	}, {
		name:     "JWT_RS512_4096",
		template: jwt.RS512_4096_F4_Key_Template(),
	}, {
		name:     "JWT_PS256_2048",
		template: jwt.PS256_2048_F4_Key_Template(),
	}, {
		name:     "JWT_PS256_3072",
		template: jwt.PS256_3072_F4_Key_Template(),
	}, {
		name:     "JWT_PS384_3072",
		template: jwt.PS384_3072_F4_Key_Template(),
	}, {
		name:     "JWT_PS512_4096",
		template: jwt.PS512_4096_F4_Key_Template(),
	}, {
		name:     "JWT_ES256",
		template: jwt.ES256Template(),
	}, {
		name:     "JWT_ES384",
		template: jwt.ES384Template(),
	}, {
		name:     "JWT_ES512",
		template: jwt.ES512Template(),
	},
}

func BenchmarkSign(b *testing.B) {
	for _, tc := range signatureBenchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := jwt.NewSigner(handle)
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
				if _, err = primitive.SignAndEncode(rawJWT); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	for _, tc := range signatureBenchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			signer, err := jwt.NewSigner(handle)
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
			token, err := signer.SignAndEncode(rawJWT)
			if err != nil {
				b.Fatal(err)
			}
			publicHandle, err := handle.Public()
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := jwt.NewVerifier(publicHandle)
			if err != nil {
				b.Fatal(err)
			}
			validator, err := jwt.NewValidator(&jwt.ValidatorOpts{ExpectedAudience: &audience})
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := primitive.VerifyAndDecode(token, validator); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

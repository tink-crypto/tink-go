// Copyright 2022 Google LLC
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

package jwt

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/tinkerror"
	jepb "github.com/tink-crypto/tink-go/v2/proto/jwt_ecdsa_go_proto"
	jwtmacpb "github.com/tink-crypto/tink-go/v2/proto/jwt_hmac_go_proto"
	jrsppb "github.com/tink-crypto/tink-go/v2/proto/jwt_rsa_ssa_pkcs1_go_proto"
	jrpsspb "github.com/tink-crypto/tink-go/v2/proto/jwt_rsa_ssa_pss_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func createJWTHMACKeyTemplate(keySize uint32, algorithm jwtmacpb.JwtHmacAlgorithm, outputPrefixType tinkpb.OutputPrefixType) *tinkpb.KeyTemplate {
	format := &jwtmacpb.JwtHmacKeyFormat{
		KeySize:   keySize,
		Version:   0,
		Algorithm: algorithm,
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          jwtHMACTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: outputPrefixType,
	}
}

func createJWTECDSAKeyTemplate(algorithm jepb.JwtEcdsaAlgorithm, outputPrefixType tinkpb.OutputPrefixType) *tinkpb.KeyTemplate {
	format := &jepb.JwtEcdsaKeyFormat{
		Version:   0,
		Algorithm: algorithm,
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          jwtECDSASignerTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: outputPrefixType,
	}
}

func createJWTRSKeyTemplate(algorithm jrsppb.JwtRsaSsaPkcs1Algorithm, modulusSizeInBits uint32, outputPrefixType tinkpb.OutputPrefixType) *tinkpb.KeyTemplate {
	format := &jrsppb.JwtRsaSsaPkcs1KeyFormat{
		Version:           0,
		Algorithm:         algorithm,
		ModulusSizeInBits: modulusSizeInBits,
		PublicExponent:    []byte{0x01, 0x00, 0x01},
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          jwtJWTRSASSAPKCS1SignerTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: outputPrefixType,
	}
}

func createJWTPSKeyTemplate(algorithm jrpsspb.JwtRsaSsaPssAlgorithm, modulusSizeInBits uint32, outputPrefixType tinkpb.OutputPrefixType) *tinkpb.KeyTemplate {
	format := &jrpsspb.JwtRsaSsaPssKeyFormat{
		Version:           0,
		Algorithm:         algorithm,
		PublicExponent:    []byte{0x01, 0x00, 0x01},
		ModulusSizeInBits: modulusSizeInBits,
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          jwtJWTRSASSAPSSSignerTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: outputPrefixType,
	}
}

// HS256Template creates a JWT key template for JWA algorithm "HS256", which is a
// HMAC-SHA256 with a 32 byte key. It will set a key ID header "kid" in the token.
func HS256Template() *tinkpb.KeyTemplate {
	return createJWTHMACKeyTemplate(32, jwtmacpb.JwtHmacAlgorithm_HS256, tinkpb.OutputPrefixType_TINK)
}

// RawHS256Template creates a JWT key template for JWA algorithm "HS256", which is a
// HMAC-SHA256 with a 32 byte key. It will not set a key ID header "kid" in the token.
func RawHS256Template() *tinkpb.KeyTemplate {
	return createJWTHMACKeyTemplate(32, jwtmacpb.JwtHmacAlgorithm_HS256, tinkpb.OutputPrefixType_RAW)
}

// HS384Template creates a JWT key template for JWA algorithm "HS384", which is a
// HMAC-SHA384 with a 48 byte key. It will set a key ID header "kid" in the token.
func HS384Template() *tinkpb.KeyTemplate {
	return createJWTHMACKeyTemplate(48, jwtmacpb.JwtHmacAlgorithm_HS384, tinkpb.OutputPrefixType_TINK)
}

// RawHS384Template creates a JWT key template for JWA algorithm "HS384", which is a
// HMAC-SHA384 with a 48 byte key. It will not set a key ID header "kid" in the token.
func RawHS384Template() *tinkpb.KeyTemplate {
	return createJWTHMACKeyTemplate(48, jwtmacpb.JwtHmacAlgorithm_HS384, tinkpb.OutputPrefixType_RAW)
}

// HS512Template creates a JWT key template for JWA algorithm "HS512", which is a
// HMAC-SHA512 with a 64 byte key. It will set a key ID header "kid" in the token.
func HS512Template() *tinkpb.KeyTemplate {
	return createJWTHMACKeyTemplate(64, jwtmacpb.JwtHmacAlgorithm_HS512, tinkpb.OutputPrefixType_TINK)
}

// RawHS512Template creates a JWT key template for JWA algorithm "HS512", which is a
// HMAC-SHA512 with a 64 byte key. It will not set a key ID header "kid" in the token.
func RawHS512Template() *tinkpb.KeyTemplate {
	return createJWTHMACKeyTemplate(64, jwtmacpb.JwtHmacAlgorithm_HS512, tinkpb.OutputPrefixType_RAW)
}

// ES256Template creates a JWT key template for JWA algorithm "ES256", which is digital
// signature with the NIST P-256 curve. It will set a key ID header "kid" in the token.
func ES256Template() *tinkpb.KeyTemplate {
	return createJWTECDSAKeyTemplate(jepb.JwtEcdsaAlgorithm_ES256, tinkpb.OutputPrefixType_TINK)
}

// RawES256Template creates a JWT key template for JWA algorithm "ES256", which is digital
// signature with the NIST P-256 curve. It will not set a key ID header "kid" in the token.
func RawES256Template() *tinkpb.KeyTemplate {
	return createJWTECDSAKeyTemplate(jepb.JwtEcdsaAlgorithm_ES256, tinkpb.OutputPrefixType_RAW)
}

// ES384Template creates a JWT key template for JWA algorithm "ES384", which is digital
// signature with the NIST P-384 curve. It will set a key ID header "kid" in the token.
func ES384Template() *tinkpb.KeyTemplate {
	return createJWTECDSAKeyTemplate(jepb.JwtEcdsaAlgorithm_ES384, tinkpb.OutputPrefixType_TINK)
}

// RawES384Template creates a JWT key template for JWA algorithm "ES384", which is digital
// signature with the NIST P-384 curve. It will not set a key ID header "kid" in the token.
func RawES384Template() *tinkpb.KeyTemplate {
	return createJWTECDSAKeyTemplate(jepb.JwtEcdsaAlgorithm_ES384, tinkpb.OutputPrefixType_RAW)
}

// ES512Template creates a JWT key template for JWA algorithm "ES512", which is digital
// signature with the NIST P-521 curve. It will set a key ID header "kid" in the token.
func ES512Template() *tinkpb.KeyTemplate {
	return createJWTECDSAKeyTemplate(jepb.JwtEcdsaAlgorithm_ES512, tinkpb.OutputPrefixType_TINK)
}

// RawES512Template creates a JWT key template for JWA algorithm "ES512", which is digital
// signature with the NIST P-521 curve. It will not set a key ID header "kid" in the token.
func RawES512Template() *tinkpb.KeyTemplate {
	return createJWTECDSAKeyTemplate(jepb.JwtEcdsaAlgorithm_ES512, tinkpb.OutputPrefixType_RAW)
}

// RS256_2048_F4_Key_Template creates a JWT key template for JWA algorithm "RS256", which is digital
// signature with RSA-SSA-PKCS1 and SHA256. It will set a key ID header "kid" in the token.
func RS256_2048_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTRSKeyTemplate(jrsppb.JwtRsaSsaPkcs1Algorithm_RS256, 2048, tinkpb.OutputPrefixType_TINK)
}

// RawRS256_2048_F4_Key_Template creates a JWT key template for JWA algorithm "RS256", which is digital
// signature with RSA-SSA-PKCS1 and SHA256. It will not set a key ID header "kid" in the token.
func RawRS256_2048_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTRSKeyTemplate(jrsppb.JwtRsaSsaPkcs1Algorithm_RS256, 2048, tinkpb.OutputPrefixType_RAW)
}

// RS256_3072_F4_Key_Template creates a JWT key template for JWA algorithm "RS256", which is digital
// signature with RSA-SSA-PKCS1 and SHA256. It will set a key ID header "kid" in the token.
func RS256_3072_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTRSKeyTemplate(jrsppb.JwtRsaSsaPkcs1Algorithm_RS256, 3072, tinkpb.OutputPrefixType_TINK)
}

// RawRS256_3072_F4_Key_Template creates a JWT key template for JWA algorithm "RS256", which is digital
// signature with RSA-SSA-PKCS1 and SHA256. It will not set a key ID header "kid" in the token.
func RawRS256_3072_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTRSKeyTemplate(jrsppb.JwtRsaSsaPkcs1Algorithm_RS256, 3072, tinkpb.OutputPrefixType_RAW)
}

// RS384_3072_F4_Key_Template creates a JWT key template for JWA algorithm "RS384", which is digital
// signature with RSA-SSA-PKCS1 and SHA384. It will set a key ID header "kid" in the token.
func RS384_3072_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTRSKeyTemplate(jrsppb.JwtRsaSsaPkcs1Algorithm_RS384, 3072, tinkpb.OutputPrefixType_TINK)
}

// RawRS384_3072_F4_Key_Template creates a JWT key template for JWA algorithm "RS384", which is digital
// signature with RSA-SSA-PKCS1 and SHA384. It will not set a key ID header "kid" in the token.
func RawRS384_3072_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTRSKeyTemplate(jrsppb.JwtRsaSsaPkcs1Algorithm_RS384, 3072, tinkpb.OutputPrefixType_RAW)
}

// RS512_4096_F4_Key_Template creates a JWT key template for JWA algorithm "RS512", which is digital
// signature with RSA-SSA-PKCS1 and SHA512. It will set a key ID header "kid" in the token.
func RS512_4096_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTRSKeyTemplate(jrsppb.JwtRsaSsaPkcs1Algorithm_RS512, 4096, tinkpb.OutputPrefixType_TINK)
}

// RawRS512_4096_F4_Key_Template creates a JWT key template for JWA algorithm "RS512", which is digital
// signature with RSA-SSA-PKCS1 and SHA512. It will not set a key ID header "kid" in the token.
func RawRS512_4096_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTRSKeyTemplate(jrsppb.JwtRsaSsaPkcs1Algorithm_RS512, 4096, tinkpb.OutputPrefixType_RAW)
}

// PS256_2048_F4_Key_Template creates a JWT key template for JWA algorithm "PS256", which is digital
// signature with RSA-SSA-PSS, a 2048 bit modulus, and SHA256. It will set a key ID header "kid" in the token.
func PS256_2048_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTPSKeyTemplate(jrpsspb.JwtRsaSsaPssAlgorithm_PS256, 2048, tinkpb.OutputPrefixType_TINK)
}

// RawPS256_2048_F4_Key_Template creates a JWT key template for JWA algorithm "PS256", which is digital
// signature with RSA-SSA-PSS, a 2048 bit modulus, and SHA256. It will not set a key ID header "kid" in the token.
func RawPS256_2048_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTPSKeyTemplate(jrpsspb.JwtRsaSsaPssAlgorithm_PS256, 2048, tinkpb.OutputPrefixType_RAW)
}

// PS256_3072_F4_Key_Template creates a JWT key template for JWA algorithm "PS256", which is digital
// signature with RSA-SSA-PSS, a 3072 bit modulus, and SHA256. It will set a key ID header "kid" in the token.
func PS256_3072_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTPSKeyTemplate(jrpsspb.JwtRsaSsaPssAlgorithm_PS256, 3072, tinkpb.OutputPrefixType_TINK)
}

// RawPS256_3072_F4_Key_Template creates a JWT key template for JWA algorithm "PS256", which is digital
// signature with RSA-SSA-PSS, a 3072 bit modulus, and SHA256. It will not set a key ID header "kid" in the token.
func RawPS256_3072_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTPSKeyTemplate(jrpsspb.JwtRsaSsaPssAlgorithm_PS256, 3072, tinkpb.OutputPrefixType_RAW)
}

// PS384_3072_F4_Key_Template creates a JWT key template for JWA algorithm "PS384", which is digital
// signature with RSA-SSA-PSS, a 3072 bit modulus, and SHA384. It will set a key ID header "kid" in the token.
func PS384_3072_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTPSKeyTemplate(jrpsspb.JwtRsaSsaPssAlgorithm_PS384, 3072, tinkpb.OutputPrefixType_TINK)
}

// RawPS384_3072_F4_Key_Template creates a JWT key template for JWA algorithm "PS384", which is digital
// signature with RSA-SSA-PSS, a 3072 bit modulus, and SHA384. It will not set a key ID header "kid" in the token.
func RawPS384_3072_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTPSKeyTemplate(jrpsspb.JwtRsaSsaPssAlgorithm_PS384, 3072, tinkpb.OutputPrefixType_RAW)
}

// PS512_4096_F4_Key_Template creates a JWT key template for JWA algorithm "PS512", which is digital
// signature with RSA-SSA-PSS, a 4096 bit modulus, and SHA512. It will set a key ID header "kid" in the token.
func PS512_4096_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTPSKeyTemplate(jrpsspb.JwtRsaSsaPssAlgorithm_PS512, 4096, tinkpb.OutputPrefixType_TINK)
}

// RawPS512_4096_F4_Key_Template creates a JWT key template for JWA algorithm "PS512", which is digital
// signature with RSA-SSA-PSS, a 4096 bit modulus, and SHA512. It will not set a key ID header "kid" in the token.
func RawPS512_4096_F4_Key_Template() *tinkpb.KeyTemplate {
	return createJWTPSKeyTemplate(jrpsspb.JwtRsaSsaPssAlgorithm_PS512, 4096, tinkpb.OutputPrefixType_RAW)
}

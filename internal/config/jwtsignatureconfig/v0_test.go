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

package jwtsignatureconfig_test

import (
	"encoding/base64"
	"encoding/hex"
	"slices"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/config/jwtsignatureconfig"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtecdsa"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtmldsa"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapss"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

func TestConfigV0JWTSignatureFailsIfKeyNotSignature(t *testing.T) {
	configV0 := jwtsignatureconfig.V0()
	aesGCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
		IVSizeInBytes:  12,
	})
	if err != nil {
		t.Fatalf("aessiv.NewParameters() err = %v, want nil", err)
	}
	aesGCMKey, err := aesgcm.NewKey(secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{}), 0, aesGCMParams)
	if err != nil {
		t.Fatalf(" aessiv.NewKey() err = %v, want nil", err)
	}
	if _, err := configV0.PrimitiveFromKey(aesGCMKey, internalapi.Token{}); err == nil {
		t.Errorf("configV0.PrimitiveFromKey() err = nil, want error")
	}
}

func mustHexDecode(t *testing.T, hexStr string) []byte {
	t.Helper()
	keyBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", hexStr, err)
	}
	return keyBytes
}

func mustBase64Decode(t *testing.T, in string) []byte {
	t.Helper()
	d, err := base64.RawURLEncoding.DecodeString(in)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString(%q) failed: %v", in, err)
	}
	return d
}

const (
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_2048_test.json#L13
	n2048Base64    = "s1EKK81M5kTFtZSuUFnhKy8FS2WNXaWVmi_fGHG4CLw98-Yo0nkuUarVwSS0O9pFPcpc3kvPKOe9Tv-6DLS3Qru21aATy2PRqjqJ4CYn71OYtSwM_ZfSCKvrjXybzgu-sBmobdtYm-sppbdL-GEHXGd8gdQw8DDCZSR6-dPJFAzLZTCdB-Ctwe_RXPF-ewVdfaOGjkZIzDoYDw7n-OHnsYCYozkbTOcWHpjVevipR-IBpGPi1rvKgFnlcG6d_tj0hWRl_6cS7RqhjoiNEtxqoJzpXs_Kg8xbCxXbCchkf11STA8udiCjQWuWI8rcDwl69XMmHJjIQAqhKvOOQ8rYTQ"
	d2048Base64    = "GlAtDupse2niHVg5EB9wVFbtDvhS-0f-IQcfVMXzPIzrBmxi1yfjLSbFgTcyn4nTGVMlt5UmTBldhUcvdQfb0JYdKVH5NaJrNPCsJNFUkOESiptxOJFbx9v6j-OWNXExxUOunJhQc2jZzrCMHGGYo-2nrqGFoOl2zULCLQDwA9nxnZbqTJr8v-FEHMyALPsGifWdgExqTk9ATBUXR0XtbLi8iO8LM7oNKoDjXkO8kPNQBS5yAW51sA01ejgcnA1GcGnKZgiHyYd2Y0n8xDRgtKpRa84Hnt2HuhZDB7dSwnftlSitO6C_GHc0ntO3lmpsJAEQQJv00PreDGj9rdhH_Q"
	p2048Base64    = "7BJc834xCi_0YmO5suBinWOQAF7IiRPU-3G9TdhWEkSYquupg9e6K9lC5k0iP-t6I69NYF7-6mvXDTmv6Z01o6oV50oXaHeAk74O3UqNCbLe9tybZ_-FdkYlwuGSNttMQBzjCiVy0-y0-Wm3rRnFIsAtd0RlZ24aN3bFTWJINIs"
	q2048Base64    = "wnQqvNmJe9SwtnH5c_yCqPhKv1cF_4jdQZSGI6_p3KYNxlQzkHZ_6uvrU5V27ov6YbX8vKlKfO91oJFQxUD6lpTdgAStI3GMiJBJIZNpyZ9EWNSvwUj28H34cySpbZz3s4XdhiJBShgy-fKURvBQwtWmQHZJ3EGrcOI7PcwiyYc"
	dp2048Base64   = "lql5jSUCY0ALtidzQogWJ-B87N-RGHsBuJ_0cxQYinwg-ySAAVbSyF1WZujfbO_5-YBN362A_1dn3lbswCnHK_bHF9-fZNqvwprPnceQj5oK1n4g6JSZNsy6GNAhosT-uwQ0misgR8SQE4W25dDGkdEYsz-BgCsyrCcu8J5C-tU"
	dq2048Base64   = "BVT0GwuH9opFcis74M9KseFlA0wakQAquPKenvni2rb-57JFW6-0IDfp0vflM_NIoUdBL9cggL58JjP12ALJHDnmvOzj5nXlmZUDPFVzcCDa2eizDQS4KK37kwStVKEaNaT1BwmHasWxGCNrp2pNfJopHdlgexad4dGCOFaRmZ8"
	qInv2048Base64 = "HGQBidm_6MYjgzIQp2xCDG9E5ddg4lmRbOwq4rFWRWlg_ZXidHZgw4lWIlDwVQSc-rflwwOVSThKeiquscgk069wlIKoz5tYcCKgCx8HIttQ8zyybcIN0iRdUmXfYe4pg8k4whZ9zuEh_EtEecI35yjPYzq2CowOzQT85-O6pVk"

	mldsa44SeedHex      = "dddaccfaa05b0332b3fd7269c7d42de6cbe370735431f735346ccb6be7ad3174"
	mldsa44PublicKeyHex = "6e17b61b6c7881ab6d39ee703ab4ab4888d2134e54bb0195bfd0573c03d60bb8445f3a2045029da4fef83f7c55869c46d73dd641bc81baf1e713cdeec5116f24338a565c4a54d9d7acf4413ea505e00f294e48b1c7f9a391d2f070a6a741f12c0ed605a3e9ac6bcb5b5819703b17dcd331f08d987d50e2aa0df091c1a182ddd5ffd19a2b9ef27a5355d962229aa9451397569917e3325b44a7f040f6fbea8e69dbcf42d2d0b7af204368ebed1ba6be5ecb503a8d8bd3325dcc8dbf07b64ea9884b114f394cc17dcf4f80c58c1dced81a3f8ef8f201605e5f3306d436e9697a68a2b62a3fc5478e7113a070f5aa69385a8076d522652d6926b114838cb2e5578edba7488c1cfeabe41fdcf477aecf74755d1a67384c896e22a22f1106e0a1684838642afb76c3ebee45f48139fcef99afc885b2a51b519a3d59804b6a1a6a7077edd82705d1551bf12a215ef7053b57d2789f532ef1d5736ab088629cc09f536030cdb4b89b2bdf547b874913cc5d62fcf98f1e537e4252315a3768710972a14066f12cc01548bd9de6a59425b161d1441d3f6c2abafef11e8f35756d27a7754004e449a95eb698dc66463bfe3b3f8ca47e7340e10b69b42b105b39d9dced186d09595e9d65ce6227c039c8c6c6f9e45d17d5a2834b073e4b7cf0f1ce12a9453da2ba3ebb5bc0ffac14243af76517ad7d6fbd319c54391334e97d899b04bc91a31adad7cc7a056b5987fbc818075966814776aefca64381b1d3c5d01e933dc354f63bb79d9aafec70927972cbf9252b96e2b02770b6c4956021a6e1552ac0258d4245e1f9de76e523377d87d57ba7d8f442ab52b86f180040d47b8620feeaed7d543b0f38af35127013e5e8a32813f3eb7182ab3b154734b48ffd31fda285873312b59713b59d1bdce3147237b9ccbdd0a9e1394f02c3636b4739d00f2251572d455d8ffb45d43270e42c132f96e99cfac1186e4bb27cd0510536d742f7394259207f332a2df9a7740bebf66c03bbe5380c0c2daa1c736c4b0c938ed12884464d6f069d9cff3e3e8cc93fea8f5e2c707e53d24f2d2a69623a23a456447aad4bbeab468949c8006facd119c0c3ce6f4166495b5d10395d6c55adf87a08c379110e0811899eb97fb6168633a487db9ffa3a3dcf6bad9870493731acc4d4ba3280c197d7ce2f550294349ff8d5ba196ac50f45f9c6a62fcaede31f9068a90830e89f50cd5b11adc90cefc3a33a96e03400346e595866fad098b5e001a3cf7579b45da72aae543c7cfb4a78aded527aa266b98f4ce11038bb50698d02407c4a698bf502d4222c912d90462a4cea4abf2b4434fa0f72687dcad38e43292b843da6273cdf2da4f430253b99bdd39b2913416ff13c366387db72738061d3269c4c3bb5518ea53da32112d0681f750772cc517b48263e44348a2575c745eb1fa43c44a3c19ae2e2b373c6d048849df1b9f09ea59167b07d8611e96d7d297a55ae13ec4f82c825d661607b39b5f820b9be55e5f0b28e28b064f8faf5117eb462588e91003c0fed30d313fc4ef996f7598946714e2849580510c1496c91821bf16c7329c6cba46a013e40e2a5c0f9e8cd3e6830641ce8013212aa7bea6e9073c138bec6b7814458cc16b78b8a84fcee22c18b73976b11b22749bab5852411de427b0abbce118a0f204289ad0983bce87f99dea31e7172774ad3827c85165bf68aee7a983558aaa2792ddbc95bc748d4af646991ceda2b095c0f35bcc0e45e8608f71cfc69fc01170b6f9c7c83adda58d3efcc340a67d54ca9f0099f999cce42947499253bf798b5207c03f3c44c41da57f06ba761e029e1c768f2d77034552e2ae2a67fc956"
)

func TestConfigV0WithJWTSignatureKey(t *testing.T) {
	iss := "joe"
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer: &iss,
		FixedNow:       time.Unix(1300819380, 0).Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}

	// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
	jwtECDSAParams, err := jwtecdsa.NewParameters(jwtecdsa.IgnoredKID, jwtecdsa.ES256)
	if err != nil {
		t.Fatalf("jwtecdsa.NewParameters() err = %v, want nil", err)
	}
	jwtECDSAPublicKey, err := jwtecdsa.NewPublicKey(jwtecdsa.PublicKeyOpts{
		Parameters:    jwtECDSAParams,
		PublicPoint:   slices.Concat([]byte{4}, mustBase64Decode(t, "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"), mustBase64Decode(t, "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")),
		IDRequirement: 0,
	})
	if err != nil {
		t.Fatalf("jwtecdsa.NewPublicKey() err = %v, want nil", err)
	}
	secretDataKeyValue := secretdata.NewBytesFromData(mustBase64Decode(t, "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"), insecuresecretdataaccess.Token{})
	jwtECDSAPrivateKey, err := jwtecdsa.NewPrivateKeyFromPublicKey(secretDataKeyValue, jwtECDSAPublicKey)
	if err != nil {
		t.Fatalf("jwtecdsa.NewPrivateKeyFromPublicKey() err = %v, want nil", err)
	}
	ecdsaJWT := "eyJhbGciOiJFUzI1NiJ9" +
		"." +
		// {"iss":"joe",
		//  "exp":1300819380,
		//  "http://example.com/is_root":true}
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
		"pmWQxfKTUJqPP3-Kg6NU1Q"

	jwtRSASSAPKCS1Params, err := jwtrsassapkcs1.NewParameters(jwtrsassapkcs1.ParametersOpts{
		ModulusSizeInBits: 2048,
		PublicExponent:    0x10001,
		Algorithm:         jwtrsassapkcs1.RS256,
		KidStrategy:       jwtrsassapkcs1.IgnoredKID,
	})
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewParameters() err = %v, want nil", err)
	}
	jwtRSASSAPKCS1PublicKey, err := jwtrsassapkcs1.NewPublicKey(jwtrsassapkcs1.PublicKeyOpts{
		Parameters:    jwtRSASSAPKCS1Params,
		IDRequirement: 0,
		Modulus:       mustBase64Decode(t, n2048Base64),
	})
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewPublicKey() err = %v, want nil", err)
	}
	jwtRSASSAPKCS1PrivateKey, err := jwtrsassapkcs1.NewPrivateKey(jwtrsassapkcs1.PrivateKeyOpts{
		PublicKey: jwtRSASSAPKCS1PublicKey,
		D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
		P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
		Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
	})
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewPrivateKey() err = %v, want nil", err)
	}
	rsaSSAPKCS1JWT := "eyJhbGciOiJSUzI1NiJ9" +
		"." +
		// {"iss":"joe",
		//  "exp":1300819380,
		//  "http://example.com/is_root":true}
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"F_h14Jj1TXhtO6DzWk5Ecei4h7I-" +
		"y9aCLUn8wMzFaIQ76MbE5qjkvLGyVpf5zwhrEx8WGmQTjufQ1kIFiu45O9qg0ZnDvRunMi" +
		"73F80PxXOdbWIUfY1QF1JCO-TqFHfymG8xShpQEm6R-WeF-" +
		"LeWxa6GWaNrJcvM4aggotdGKhgHC7SwYXVYjPhmH4r8jaUuGzCIO_iQb31n-" +
		"aR05XR16xti54pIgWlxXNgLhZ13umDeohZ6xkSny4HFvsJ2j08zo1CXtGOPdd34IKv4Y5S" +
		"xKJ5YwXVLukyGqvPLy8PNCkQlh32N5kjh9IGdg25OgR08ADQjRKinVjO_UxROv0bj4Q"

	jwtRSASSAPSSParams, err := jwtrsassapss.NewParameters(jwtrsassapss.ParametersOpts{
		ModulusSizeInBits: 2048,
		PublicExponent:    0x10001,
		Algorithm:         jwtrsassapss.PS256,
		KidStrategy:       jwtrsassapss.IgnoredKID,
	})
	if err != nil {
		t.Fatalf("jwtrsassapss.NewParameters() err = %v, want nil", err)
	}
	jwtRSASSAPSSPublicKey, err := jwtrsassapss.NewPublicKey(jwtrsassapss.PublicKeyOpts{
		Parameters:    jwtRSASSAPSSParams,
		IDRequirement: 0,
		Modulus:       mustBase64Decode(t, n2048Base64),
	})
	if err != nil {
		t.Fatalf("jwtrsassapss.NewPublicKey() err = %v, want nil", err)
	}
	jwtRSASSAPSSPrivateKey, err := jwtrsassapss.NewPrivateKey(jwtrsassapss.PrivateKeyOpts{
		PublicKey: jwtRSASSAPSSPublicKey,
		D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
		P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
		Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
	})
	if err != nil {
		t.Fatalf("jwtrsassapss.NewPrivateKey() err = %v, want nil", err)
	}
	rsaSSAPSSJWT := "eyJhbGciOiJQUzI1NiJ9" +
		"." +
		// {"iss":"joe",
		//  "exp":1300819380,
		//  "http://example.com/is_root":true}
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"WeMZxYgxDNYFbVm2-pt3uxlj1fIS540KIz1mUMwBfcWunpduvtzj_fWPJv_" +
		"bqRC78GdqUaOju01Sega8ECcVsg_8guRyJOl_" +
		"BmE9c6kxzSiPyZJ9f1xUjx9WfQ5kcoYMNMVJ_" +
		"gUO9QbWin23UiHBBs61rolzn0M6xfNS6MkaYXfsa8aYOWAmsLU_" +
		"6WOQtN645bSyoyHDIah2dHXZXQBc6SkqLP8fW1oiTLU4PcVr6SzQIHfK0kS674lqqmdFVK" +
		"QfyIakLEhGsQuZ0XzKRE-RbUrQGelKiC1q5Jz3Gq0nAGqOSPkFMA_" +
		"5TK1TQhykfbIuXYAClbt1tM74ee27sb2uuQ"

	jwtMLDSAParams, err := jwtmldsa.NewParameters(jwtmldsa.IgnoredKID, jwtmldsa.MLDSA44)
	if err != nil {
		t.Fatalf("jwtmldsa.NewParameters() err = %v, want nil", err)
	}
	jwtMLDSAPublicKey, err := jwtmldsa.NewPublicKey(jwtmldsa.PublicKeyOpts{
		Parameters:    jwtMLDSAParams,
		IDRequirement: 0,
		KeyBytes:      mustHexDecode(t, mldsa44PublicKeyHex),
	})
	if err != nil {
		t.Fatalf("jwtmldsa.NewPublicKey() err = %v, want nil", err)
	}
	jwtMLDSAPrivateKey, err := jwtmldsa.NewPrivateKeyFromPublicKey(secretdata.NewBytesFromData(mustHexDecode(t, mldsa44SeedHex), insecuresecretdataaccess.Token{}), jwtMLDSAPublicKey)
	if err != nil {
		t.Fatalf("jwtmldsa.NewPrivateKeyFromPublicKey() err = %v, want nil", err)
	}
	mldsaJWT := "eyJhbGciOiJNTC1EU0EtNDQifQ" +
		"." +
		"eyJleHAiOjEzMDA4MTkzODAsImlzcyI6ImpvZSJ9" +
		"." +
		"JLNjFGPMrRCM5mvX1CKmZsx4kxbdj0mcaS-seRt05MXR2-Ul13_LWK39C9kCZZmuYY6xpmFCa4KUhNokBJQWF1JguyPpi_5TMBuwxWdjb5fFwi-SAnEi3ltSJqVKH8YoIqi33Y2VBz2GZ49L2Cpq6iofKWdXQw5dNI1wjtjoUO6O6LOhiuB9g7r3AympFFJz6Sq7PpV2EOUIRLMOwlEjOVlupOpZLn_3Y_0ONCQLZ5hU7lFZFeCItgCR6_nrHgBLLipoL_WTvD6sA-tVqrVHXB9_H8Zay-f86Bgfbc_zwQ14aKSBMMJyX7NSVSQmZPB-TObA8jcxOa2aU8S23haEgzCl5VeVYnpCY5uWZHhmKUcjHfixSd06E8iOJ9VrxnrN3Q7MyCyQs593-4JzP79XQ96hr8822bMEefq-8x0OJd3dkuX7Mr11u6tLMAUhiF_XxL4t1N5XX6UsYgEY11Z8snIPZ0d-gniV2lqKqh9a813XFtV_n9aqpAQrcAVSIJ1DF_fQgBfOmwEC3TqZ0r_SfEcmN0ZZqvXlyd51BhkbUa2lKvl5fK8gZAX1TVLy_Pw8yvqyALjGEohe4fz1YBCk82XitMMTggD0URTt5SgqOg7fTxEtodCIp6d2VYJfeFxMBsIpwEyWLGp3iFlNU_KwwcfgdpYbOCMHYfifbIXXkouQTDjeD04oA5xkQ7TY7hXd6xW2J92bQukegssXnGJItphwXIs_gUzD3LYOIVbTUVBnOBCK8u2BB8FZzdJt9diHjGGcKuHakVWVHwYXnqCUD196nOPbDheimnyMN3czEHLuuYjzvs9F_a11JKPIZ08krQIC1idS_M1RK5EZ7TtrSiz9WlPdPAs9ww_nlo7qMnYEdsX3mPopyTaPZADLfBshMg2dd6WJLYWq0D4YTY_inFa0WpBBCoxJ-1AXaPYufiEfYSnVlocb0I7ow--pMKSN9h-ZqVlAcrlL4uwVHGdYijpr1zino_iP4PI1G8CnxFZ0x4k-rgzpzMEuyuNCTr3io9elkrNt0JoNCeQIzMSoIn2rqoDuucyDsERo5RdcdMdaVNIIspYUfySvpqT3WPWR9ZfTjRn47UGsbYRp7JrcWVdCBn-SN8nvf25v2uymEviOCB16ZxHgnVyeQCyBlbpx6pLURka8dCcm_t54OZVddT0JjsCOLWsSdMzgi3hGstZqt1kzAy0e5xIUYmp4G5UqMuVCBaFC-1FQ-EoAvgpY2YRIsRdXs3LJ3hTPUo-AUUZi5FSXjU-eLnjeD85l7GGoNn4_b5LtDb-4Dnn_ATTW5xTH1E2jCrctaKk844tp_SEwnQp8Zbz2WJrfUQ91C6BDVTy_lYUpS8vy6Ff5dkI5B2O-Pd-YaYimWMwIfG-fXNiJVwPWWSaP-6QDevM2dP_2ijbNKp4pwyIzA0Wzu74phPVKE7ne5i7mh1ZNYTTMHUpzYgBhPIlD1WR_ccQKa8wLc4yAEjnooGBIl8rW7LN55qMSI1atN1NOQNE-EimDC460HiPdyKgaSmEe1UjDpp7_Cc7FH7vC9bubH71VpsgivKzDLsaBi-KWg3PkPXp_cbsHCpBtwcGlF7JRPqxuQ4A1xInFhN3uQyVpEgJLbL1vebQY73mvaDmDOVHEfw6v2jjq3d9LcZFi-vsVS4zYfDgyPh1hUlX6oR3mN8Sv-CDJGb_jQT0xRXfcsnwlr1xs3Mxfde6IuhmwimvqJUhGgKkB51tOEflZNc557q49NzQU44YwESuOpgKWxpaclvLLf9hQgL6pwRjtGMc_Vv8s-0vq7F_ZugcTmFC-JWqf61bh-i6gj8kjqvbG4I267iSoUrbB8lRa-eNNmaNzVFlm3jjBvnJkJyOIl6Q1KEkpfrBp9CSazdtZ8x2Kredpa3oBQhwn2CZ_5rMn60VEMAoXFCJseys-Ts60rF4pE33Q0Y9IVC-OR-ifxumg8Wl0LZG0TKmrK_P8dDJnpU3itPlbwyAHsKVPJmkAIlf2jJNYslhchtCQjn1W2LSW9iwPLlehtc2f1B0n4XUPP7vnDuUB6-33UPx9s09DxM1k5OPje_17yLbwrf2hrtNzr1wxOi7F4GFbFfAqihdQhfJElpL3nmnGtokvQsV-m3HSjnzACg7-KzQNRf00psBeghAwy6mmKUDQ2XnLQ5MfTAJZH6hZ_gNra5dRc6gAmHqWRAwmIYDddbsAyEErYllixSAp7n18vHHRlXfE5Cv6SYoVikFBEILYSaf0avyajY2WeOj5wgNGSuj7fJ4qdt1YnRM9NdHedEUj3WBQU3AajPQ1-5BlaHv7hgWaJ_1_3Gouoglpb2i8z7Vaj8Qhh1SgOLrTS-4de1iUq5H1Z00ekshZEuU-VkBtqvi7ccWjHcE-k6knIJH7ExW1LCdbHxRngtwRV9rHQXagRw0H4lNiK2h-vl_w5DcoCT_161Sxcvuc790l0qBLbTJJXjahTBUnzezBDBD-SJtmHZzAGJaEU1o7gPqQd1APhJdY2bW7DEmFE93324wAhk74LjtDJqGgJFFUND_GjT0ExVRJqRy3yxu9XVvy0qv7_1egQSs9qdMCw0IP94kPv47SEqrl9Pe86ctB9qnoUvTLeDVtTu0ts3BTXNLHHPzLMmFHecAQ2w4cvIeWnTtoRfr7h5F9sTVIsDTMflmmJsj_JEzSehLQHUGpLyVGn4ll32ex7YFhEvxsWmzWmqOeYnzOpbaHhUabtnXPcEM55n0_GPaTDepvxy0W7snaBFdRdG32AHRofhJGDTzq4BvO97G-Jk1lKAKokVoAd7F_eFJo9up2dkfPUV5WxuiLtacNsMFsdYtmdnMCUp46k_TKwkvsfLtmSuQltJbTGz0jQEDO2hPMqwBCz2RxG8xV7OGRIfr-Vj2oPpOVg1nb3KpmRlCdklglCsnI-mzvcOCeFyU7FiGaEOhk1SjngAGePjouULv0F5x7qTaFvw08FZTPikEzbd6cgRsjB0GOcZIxOEE6ZLgkXOAnv0usYx1Kdv3_pW8Rp8ulBhum93F4p8Gx3KyDN0zFGjrL5kuU7_Xh7wkhL1IFdvPO23_yhL62ZHMYblZkx3dFBvkUizuo882kNtxon8nQlzbOAXqE4ZcXFCgGFCYoKSs5Tp6f09Tn6xMUHCAqKzY5R3SfrLC4wsrpDBEeL0Vae4WbntTcEx0gKC05PE5SWXCVq-X4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4fKzo"

	for _, tc := range []struct {
		name       string
		jwt        string
		privateKey key.Key
		publicKey  key.Key
	}{
		{
			name:       "jwtecdsa",
			publicKey:  jwtECDSAPublicKey,
			privateKey: jwtECDSAPrivateKey,
			jwt:        ecdsaJWT,
		},
		{
			name:       "jwtrsassapkcs1",
			publicKey:  jwtRSASSAPKCS1PublicKey,
			privateKey: jwtRSASSAPKCS1PrivateKey,
			jwt:        rsaSSAPKCS1JWT,
		},
		{
			name:       "jwtrsassapss",
			publicKey:  jwtRSASSAPSSPublicKey,
			privateKey: jwtRSASSAPSSPrivateKey,
			jwt:        rsaSSAPSSJWT,
		},
		{
			name:       "jwtmldsa",
			publicKey:  jwtMLDSAPublicKey,
			privateKey: jwtMLDSAPrivateKey,
			jwt:        mldsaJWT,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configV0 := jwtsignatureconfig.V0()
			p1, err := configV0.PrimitiveFromKey(tc.publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("configV0.PrimitiveFromKey() err = %v, want nil", err)
			}
			verifier, ok := p1.(jwt.Verifier)
			if !ok {
				t.Fatalf("primitive is of type %T, want jwt.Verifier", p1)
			}
			p2, err := configV0.PrimitiveFromKey(tc.privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("configV0.PrimitiveFromKey() err = %v, want nil", err)
			}
			signer, ok := p2.(jwt.Signer)
			if !ok {
				t.Fatalf("primitive is of type %T, want jwt.Signer", p2)
			}

			// Verify the JWTs test vector.
			if _, err := verifier.VerifyAndDecode(tc.jwt, validator); err != nil {
				t.Errorf("verifier.VerifyAndDecode() err = %v, want nil", err)
			}

			// Sign and verify
			iss := "issuer"
			rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{
				Issuer:            &iss,
				WithoutExpiration: true,
			})
			if err != nil {
				t.Fatalf("NewRawJWT() = %v, want nil", err)
			}
			signedJWT, err := signer.SignAndEncode(rawJWT)
			if err != nil {
				t.Fatalf("signer.SignAndEncode() = %v, want nil", err)
			}
			validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
				ExpectedIssuer:         &iss,
				AllowMissingExpiration: true,
			})
			if err != nil {
				t.Fatalf("NewValidator() = %v, want nil", err)
			}
			if _, err := verifier.VerifyAndDecode(signedJWT, validator); err != nil {
				t.Errorf("verifier.VerifyAndDecode() = %v, want nil", err)
			}
		})
	}
}

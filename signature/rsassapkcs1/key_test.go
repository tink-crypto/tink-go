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

package rsassapkcs1_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/big"
	"math/bits"
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
)

const (
	f4 = 65537
)

func TestNewParametersInvalidValues(t *testing.T) {
	testCases := []struct {
		name            string
		modulusSizeBits int
		hashType        rsassapkcs1.HashType
		publicExponent  int
		variant         rsassapkcs1.Variant
	}{
		{
			name:            "small public exponent",
			modulusSizeBits: 2048,
			hashType:        rsassapkcs1.SHA256,
			publicExponent:  f4 - 1,
			variant:         rsassapkcs1.VariantTink,
		},
		{
			name:            "even public exponent",
			modulusSizeBits: 2048,
			hashType:        rsassapkcs1.SHA256,
			publicExponent:  f4 + 1,
			variant:         rsassapkcs1.VariantTink,
		},
		{
			name:            "unknown hash",
			modulusSizeBits: 2048,
			hashType:        rsassapkcs1.UnknownHashType,
			publicExponent:  f4,
			variant:         rsassapkcs1.VariantTink,
		},
		{
			name:            "unknown variant",
			modulusSizeBits: 2048,
			hashType:        rsassapkcs1.SHA256,
			publicExponent:  f4,
			variant:         rsassapkcs1.VariantUnknown,
		},
		{
			name:            "invalid modulus size (too small)",
			modulusSizeBits: 1024,
			hashType:        rsassapkcs1.SHA256,
			publicExponent:  f4,
			variant:         rsassapkcs1.VariantTink,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rsassapkcs1.NewParameters(tc.modulusSizeBits, tc.hashType, tc.publicExponent, tc.variant); err == nil {
				t.Errorf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = nil, want error", tc.modulusSizeBits, tc.hashType, tc.publicExponent, tc.variant)
			}
		})
	}
	// On 32 bit platforms, the public exponent cannot be larger than 1<<31.
	if bits.UintSize == 64 {
		expVal := 1 << (bits.UintSize/2 - 1)
		t.Run("exponent too larrge", func(t *testing.T) {
			if _, err := rsassapkcs1.NewParameters(2048, rsassapkcs1.SHA256, expVal, rsassapkcs1.VariantTink); err == nil {
				t.Errorf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = nil, want error", 2048, rsassapkcs1.SHA256, expVal, rsassapkcs1.VariantTink)
			}
		})
	}
}

func TestNewParameters(t *testing.T) {
	for _, hashType := range []rsassapkcs1.HashType{rsassapkcs1.SHA256, rsassapkcs1.SHA384, rsassapkcs1.SHA512} {
		for _, variant := range []rsassapkcs1.Variant{rsassapkcs1.VariantTink, rsassapkcs1.VariantCrunchy, rsassapkcs1.VariantLegacy, rsassapkcs1.VariantNoPrefix} {
			for _, modulusSizeBits := range []int{2048, 3072, 4096} {
				for _, publicExponent := range []int{f4, 1<<31 - 1} {
					t.Run(fmt.Sprintf("modulusSizeBits:%v_hashType:%v_publicExponent:%v_variant:%v", modulusSizeBits, hashType, publicExponent, variant), func(t *testing.T) {
						params, err := rsassapkcs1.NewParameters(modulusSizeBits, hashType, publicExponent, variant)
						if err != nil {
							t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", modulusSizeBits, hashType, publicExponent, variant, err)
						}
						if got, want := params.ModulusSizeBits(), modulusSizeBits; got != want {
							t.Errorf("params.ModulusSizeBits() = %v, want %v", got, want)
						}
						if got, want := params.HashType(), hashType; got != want {
							t.Errorf("params.HashType() = %v, want %v", got, want)
						}
						if got, want := params.PublicExponent(), publicExponent; got != want {
							t.Errorf("params.PublicExponent() = %v, want %v", got, want)
						}
						if got, want := params.Variant(), variant; got != want {
							t.Errorf("params.Variant() = %v, want %v", got, want)
						}
						if got, want := params.HasIDRequirement(), variant != rsassapkcs1.VariantNoPrefix; got != want {
							t.Errorf("params.HasIDRequirement() = %v, want %v", got, want)
						}
						other, err := rsassapkcs1.NewParameters(modulusSizeBits, hashType, publicExponent, variant)
						if err != nil {
							t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", modulusSizeBits, hashType, publicExponent, variant, err)
						}
						if !params.Equal(other) {
							t.Errorf("params.Equal(other) = false, want true")
						}
					})
				}
			}
		}
	}
}

type testParams struct {
	modulusSizeBits int
	hashType        rsassapkcs1.HashType
	publicExponent  int
	variant         rsassapkcs1.Variant
}

func TestNewParametersDifferentParameters(t *testing.T) {
	for _, tc := range []struct {
		name string
		this testParams
		that testParams
	}{
		{
			name: "different modulus size",
			this: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
			that: testParams{
				modulusSizeBits: 3072,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
		},
		{
			name: "different hash type",
			this: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
			that: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA384,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
		},
		{
			name: "different public exponent",
			this: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
			that: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  1<<31 - 1,
				variant:         rsassapkcs1.VariantTink,
			},
		},
		{
			name: "different variant",
			this: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
			that: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  1<<31 - 1,
				variant:         rsassapkcs1.VariantNoPrefix,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			this, err := rsassapkcs1.NewParameters(tc.this.modulusSizeBits, tc.this.hashType, tc.this.publicExponent, tc.this.variant)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", tc.this.modulusSizeBits, tc.this.hashType, tc.this.publicExponent, tc.this.variant, err)
			}
			that, err := rsassapkcs1.NewParameters(tc.that.modulusSizeBits, tc.that.hashType, tc.that.publicExponent, tc.that.variant)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", tc.that.modulusSizeBits, tc.that.hashType, tc.that.publicExponent, tc.that.variant, err)
			}
			if this.Equal(that) {
				t.Errorf("this.Equal(that) = true, want false")
			}
		})
	}
}

const (
	// Taken from:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_2048_test.json#L13
	n2048Base64    = "s1EKK81M5kTFtZSuUFnhKy8FS2WNXaWVmi_fGHG4CLw98-Yo0nkuUarVwSS0O9pFPcpc3kvPKOe9Tv-6DLS3Qru21aATy2PRqjqJ4CYn71OYtSwM_ZfSCKvrjXybzgu-sBmobdtYm-sppbdL-GEHXGd8gdQw8DDCZSR6-dPJFAzLZTCdB-Ctwe_RXPF-ewVdfaOGjkZIzDoYDw7n-OHnsYCYozkbTOcWHpjVevipR-IBpGPi1rvKgFnlcG6d_tj0hWRl_6cS7RqhjoiNEtxqoJzpXs_Kg8xbCxXbCchkf11STA8udiCjQWuWI8rcDwl69XMmHJjIQAqhKvOOQ8rYTQ"
	d2048Base64    = "GlAtDupse2niHVg5EB9wVFbtDvhS-0f-IQcfVMXzPIzrBmxi1yfjLSbFgTcyn4nTGVMlt5UmTBldhUcvdQfb0JYdKVH5NaJrNPCsJNFUkOESiptxOJFbx9v6j-OWNXExxUOunJhQc2jZzrCMHGGYo-2nrqGFoOl2zULCLQDwA9nxnZbqTJr8v-FEHMyALPsGifWdgExqTk9ATBUXR0XtbLi8iO8LM7oNKoDjXkO8kPNQBS5yAW51sA01ejgcnA1GcGnKZgiHyYd2Y0n8xDRgtKpRa84Hnt2HuhZDB7dSwnftlSitO6C_GHc0ntO3lmpsJAEQQJv00PreDGj9rdhH_Q"
	p2048Base64    = "7BJc834xCi_0YmO5suBinWOQAF7IiRPU-3G9TdhWEkSYquupg9e6K9lC5k0iP-t6I69NYF7-6mvXDTmv6Z01o6oV50oXaHeAk74O3UqNCbLe9tybZ_-FdkYlwuGSNttMQBzjCiVy0-y0-Wm3rRnFIsAtd0RlZ24aN3bFTWJINIs"
	q2048Base64    = "wnQqvNmJe9SwtnH5c_yCqPhKv1cF_4jdQZSGI6_p3KYNxlQzkHZ_6uvrU5V27ov6YbX8vKlKfO91oJFQxUD6lpTdgAStI3GMiJBJIZNpyZ9EWNSvwUj28H34cySpbZz3s4XdhiJBShgy-fKURvBQwtWmQHZJ3EGrcOI7PcwiyYc"
	dp2048Base64   = "lql5jSUCY0ALtidzQogWJ-B87N-RGHsBuJ_0cxQYinwg-ySAAVbSyF1WZujfbO_5-YBN362A_1dn3lbswCnHK_bHF9-fZNqvwprPnceQj5oK1n4g6JSZNsy6GNAhosT-uwQ0misgR8SQE4W25dDGkdEYsz-BgCsyrCcu8J5C-tU"
	dq2048Base64   = "BVT0GwuH9opFcis74M9KseFlA0wakQAquPKenvni2rb-57JFW6-0IDfp0vflM_NIoUdBL9cggL58JjP12ALJHDnmvOzj5nXlmZUDPFVzcCDa2eizDQS4KK37kwStVKEaNaT1BwmHasWxGCNrp2pNfJopHdlgexad4dGCOFaRmZ8"
	qInv2048Base64 = "HGQBidm_6MYjgzIQp2xCDG9E5ddg4lmRbOwq4rFWRWlg_ZXidHZgw4lWIlDwVQSc-rflwwOVSThKeiquscgk069wlIKoz5tYcCKgCx8HIttQ8zyybcIN0iRdUmXfYe4pg8k4whZ9zuEh_EtEecI35yjPYzq2CowOzQT85-O6pVk"

	// Values generated on an Android phone. Taken from:
	// https://github.com/tink-crypto/tink-java/blob/6e771bc8116cb2ae88b8184af2a678f470df4790/src/test/java/com/google/crypto/tink/signature/RsaSsaPkcs1PrivateKeyTest.java#L347
	n2048BigInt16    = "b3795dceabcbd81fc437fd1bef3f441fb3e795e0def5dcb6c84d1136f1f5c552bcb549fc925a0bd84fba5014565a46e89c1b0f198323ddd6c74931eef6551414651d224965e880136a1ef0f58145aa1d801cf9abe8afcd79d18b71e992a440dac72e020622d707e39ef02422b3b5b60eee19e39262bef2c83384370d5af82208c905341cf3445357ebed8534e5d09e7e3faab0029eb72c4d67b784023dc3853601f46d8a76640c0cb70e32a7e1a915f64418b9872f90639e07c9c58cb6da7138ec00edceb95871f25b6d58541df81a05c20336ecb03d68f118e758fc8399c5afa965de8b3e6e2cffe05368c0c2e8f8d7651bc0595c315ad5ffc5e9181226a5d5"
	d2048BigInt10    = "3221514782158521239046688407258406330028553231891834758638194651218489349712866325521438421714836367531316613927931498512071990193965798572643232627837201196644319517052327671563822639251731918047441576305607916660284178027387674162132050160094809919355636813793351064368082273962217034909172344404581974193241939373282144264114913662260588365672363893632683074989847367188654224412555194872230331733391324889200933302437700487142724975686901108577545454632839147323098141162449990768306604007013959695761622579370899486808808004842820432382650026507647986123784123174922931280866259315314620233905351359011687391313"
	p2048BigInt10    = "158774943353490113489753012135278111098541279368787638170427666092698662171983127156976037521575652098385551704113475827318417186165950163951987243985985522595184323477005539699476104661027759513072140468348507403972716866975866335912344241205454260491734974839813729609658331285715361068926273165265719385439"
	q2048BigInt10    = "142695718417290075651435513804876109623436685476916701891113040095977093917632889732962474426931910603260254832314306994757612331416172717945809235744856009131743301134864401372069413649983267047705657073804311818666915219978411279698814772814372316278090214109479349638211641740638165276131916195227128960331"
	dp2048BigInt10   = "54757332036492112014516953480958174268721943273163834138395198270094376648475863100263551887676471134286132102726288671270440594499638457751236945367826491626048737037509791541992445756573377184101446798993133105644007913505173122423833934109368405566843064243548986322802349874418093456823956331253120978221"
	dq2048BigInt10   = "4123864239778253555759629875435789731400416288406247362280362206719572392388981692085858775418603822002455447341246890276804213737312222527570116003185334716198816124470652855618955238309173562847773234932715360552895882122146435811061769377762503120843231541317940830596042685151421106138423322302824087933"
	qInv2048BigInt10 = "43369284071361709125656993969231593842392884522437628906059039642593092160995429320609799019215633408868044592180219813214250943675517000006014828230986217788818608645218728222984926523616075543476651226972790298584420864753413872673062587182578776079528269917000933056174453680725934830997227408181738889955"

	// Taken from:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_3072_test.json#L21
	n3072Base64    = "3I94gGcvDPnWNheopYvdJxoQm63aD6gm-UuKeVUmtqSagFZMyrqKlJGpNaU-3q4dmntUY9ni7z7gznv_XUtsgUe1wHPC8iBRXVMdVaNmh6bePDR3XC8VGRrAp0LXNCIoyNkQ_mu8pDlTnEhd68vQ7g5LrjF1A7g87oEArHu0WHRny8Q3PEvaLu33xBYx5QkitYD1vOgdJLIIyrzS11_P6Z91tJPf_Fyb2ZD3_Dvy7-OS_srjbz5O9EVsG13pnMdFFzOpELaDS2HsKSdNmGvjdSw1CxOjJ9q8CN_PZWVJmtJuhTRGYz6tspcMqVvPa_Bf_bwqgEN412mFpx8G-Ql5-f73FsNqpiWkW17t9QglpT6dlDWyPKq55cZNOP06dn4YWtdyfW4V-em6svQYTWSHaV25ommMZysugjQQ2-8dk_5AydNX7p_Hf4Sd4RNj9YOvjM9Rgcoa65RMQiUWy0AelQkj5L2IFDn6EJPHdYK_4axZk2dHALZDQzngJFMV2G_L"
	d3072Base64    = "BQEgW9F7iNDWYm3Q_siYoP1_aPjd3MMU900WfEBJW5WKh-TtYyAuasaPT09LiOPsegfYV1enRYRot2aq2aQPdzN4VUCLKNFA51wuazYE6okHu9f46VeMJACuZF0o4t7vi_cY4pzxL8y5L--YafQ67lvWrcIjhI0WnNbCfCdmZSdm_4GZOz4BWlU97O4P_cFiTzn42Wtu1dlQR8FXC1n6LrPWiN1eFKzJQHuAlPGLRpQkTrGtzWVdhz9X_5r25P7EcL4ja687IMIECrNg11nItOYYv4vU4OxmmPG3LHFg7QUhyCtRdrYPtjUD0K4j9uL7emCTBbCvYhULkhrFP03omWZssB2wydi2UHUwFcG25oLmvzggTln3QJw4CMDlPyVJNVQKOBqWPCwad8b5h_BqB6BXJobtIogtvILngjzsCApY1ysJ0AzB0kXPFY_0nMQFmdOvcZ3DAbSqf1sDYproU-naq-KE24bVxB0EARQ98rRZPvTjdHIJxSP1p_gPAtAR"
	p3072Base64    = "_sahC_xJtYoshQ6v69uZdkmpVXWgwXYxsBHLINejICMqgVua9gQNe_I9Jn5eBjBMM-BMhebUgUQvAQqXWLoINkpwA175npyY7rQxUFsq-2d50ckdDqL7CmXcOR557Np9Uv191pkjsl365EjKzoKeusprPIo8tkqBgAYUQ0iVd4wg1imxJbafQpRfZrZE84QLz6b842EHQlbFCGPsyiznVrSp-36ZPQ8fpIssxIW36qYUBfvvFQ51Y8IVCBF2feD5"
	q3072Base64    = "3Z7BzubYqXGxZpAsRKTwLvN6YgU7QSiKHYc9OZy8nnvTBu2QZIfaL0m8HBgJwNTYgQbWh5UY7ZJf62aq1f88K4NGbFVO2XuWq-9Vs7AjFPUNA4WgodikauA-j86RtBISDwoQ3GgVcPpWS2hzus2Ze2FrK9dzP7cjreI7wQidoy5QlYNDbx40SLV5-yGyQGINIEWNCPD5lauswKOY8KtqZ8n1vPfgMvsdZo_mmNgDJ1ma4_3zqqqxm68XY5RDGUvj"
	dp3072Base64   = "8b-0DNVlc5cay162WwzSv0UCIo8s7KWkXDdmEVHL_bCgooIztgD-cn_WunHp8eFeTVMmCWCQf-Ac4dYU6iILrMhRJUG3hmN9UfM1X9RCIq97Di7RHZRUtPcWUjSy6KYhiN_zye8hyhwW9wqDNhUHXKK5woZBOY_U9Y_PJlD3Uqpqdgy1hN2WnOyA4ctN_etr8au4BmGJK899wopeozCcis9_A56K9T8mfVF6NzfS3hqcoVj-8XH4vaHppvA7CRKx"
	dq3072Base64   = "Pjwq6NNi3JKU4txx0gUPfd_Z6lTVwwKDZq9nvhoJzeev5y4nclPELatjK_CELKaY9gLZk9GG4pBMZ2q5Zsb6Oq3uxNVgAyr1sOrRAljgQS5frTGFXm3cHjdC2leECzFX6OlGut5vxv5F5X87oKXECCXfVrx2HNptJpN1fEvTGNQUxSfLdBTjUdfEnYVk7TebwAhIBs7FCAbhyGcot80rYGISpDJnv2lNZFPcyec_W3mKSaQzHSY6IiIVS12DSkNJ"
	qInv3072Base64 = "GMyXHpGG-GwUTRQM6rvJriLJTo2FdTVvtqSgM5ke8hC6-jmkzRq_qZszL96eVpVa8XlFmnI2pwC3_R2ICTkG9hMK58qXQtntDVxj5qnptD302LJhwS0sL5FIvAZp8WW4uIGHnD7VjUps1aPxGT6avSeEYJwB-5CUx8giUyrXrsKgiu6eJjCVrQQmRVy1kljH_Tcxyone4xgA0ZHtcklyHCUmZlDEbcv7rjBwYE0uAJkUouJpoBuvpb34u6McTztg"

	// Taken from:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_4096_test.json#L21
	n4096Base64    = "9gG-DczQSqQLEvPxka4XwfnIwLaOenfhS-JcPHkHyx0zpu9BjvQYUvMsmDkrxcmu2RwaFQHFA-q4mz7m9PjrLg_PxBvQNgnPao6zqm8PviMYezPbTTS2bRKKiroKKr9Au50T2OJVRWmlerHYxhuMrS3IhZmuDaU0bhXazhuse_aXN8IvCDvptGu4seq1lXstp0AnXpbIcZW5b-EUUhWdr8_ZFs7l10mne8OQWl69OHrkRej-cPFumghmOXec7_v9QVV72Zrqajcaa0sWBhWhoSvGlY00vODIWty9g5L6EM7KUiCdVhlro9JzziKPHxERkqqS3ioDl5ihe87LTcYQDm-K6MJkPyrnaLIlXwgsl46VylUVVfEGCCMc-AA7v4B5af_x5RkUuajJuPRWRkW55dcF_60pZj9drj12ZStCLkPxPmwUkQkIBcLRJop0olEXdCfjOpqRF1w2cLkXRgCLzh_SMebk8q1wy0OspfB2AKbTHdApFSQ9_dlDoCFl2jZ6a35Nrh3S6Lg2kDCAeV0lhQdswcFd2ejS5eBHUmVpsb_TldlX65_eMl00LRRCbnHv3BiHUV5TzepYNJIfkoYp50ju0JesQCTivyVdcEEfhzc5SM-Oiqfv-isKtH1RZgkeGu3sYFaLFVvZwnvFXz7ONfg9Y2281av0hToFHblNUEU"
	d4096Base64    = "01Gb2G7fXb6cZKN4FxPdBJt0f1ZR_ZGMzoqbgLbWovtqqzNKtWmom1iYLgquNzCQKZ-iJ_llK4AtI-5cpoJMQz0B1AuwRzsWGQqL-xN8CnBLT0m0UBW_vuH2cERvB1lSWdcMfXmulfmyVDsBYuu3Y-u4HEtu3_nRl97eHb5X5ARm0VbU39XXY0xFU0-yu70b8leBehc8B5X9vMUzl29KDQQWDyma9dwnKoFLNtW65RFrlUIXjx1VTKt6ZFMDVIK5ga3UvY_9XVAIObI-MOvT84aPB1hMvRK6CJMlmChg9p8r3HB3tsYPWKInKCM3nhAjcEFl98FPZKGP1bJFoYFJt-2jOFpWup55UConvxOGXN41vhXeA9BqpvCLFyt-60tzy8FXAZxdkzWEqNGt1ht9vKOyU8oM-T3JqKOqwvUCJwIuaS97R2dVZiDMko1j4xB4w2Diq0txqRfhnn6wk4BILltOqIIChxwqKcpvZrL-MEr2CVIOT4HWTCZ2i7gSqGZ5NmYR9M9uieK9HZ1-KHKcfw5OMVLXrX8Yb6MvAeFp_wahIAG8F539DclCy6vFVfZ_X9BD4KM1Q0D6SQ0vEjNnvpJus-Hf_nDDFRyHRQ8yF9wqoLWnBpxaF9VWFMmZQTn3s3tJ6f54CvZaDoni5Y_qr_4WO8nRnq_ZzSmw7zzvPQE"
	p4096Base64    = "_CG4VcWtTKK2lwUWQG9xxuee_EEm5lmHctseCC3msN3aqiopUfBBSOhuC94oITt_YA-YcwgwHqzqE0Biuww932KNqav5PvHOPnWwlTpITb01VL1cBkmTPdd-UnVj6Q8FqAE_3ayVjDKTeOlDA7MEvl-d8f5bBDp_3ZRwCj8LHLvQUWt82UxXypbZ_SqMqXOZEhjLozocI9gQ91GdH3cCq3Kv_bP4ShsqiBFuQDO8TQz8eYnGV-D-lOlkR2rli65reHbzbAnTKxpj-MR8lKdMku7fdfwnz_4PhFI2PkvI92U_PLVer2k87HDRPIdd6TWosgQ5q36T92mBxZV_xbtE2Q"
	q4096Base64    = "-cf3SKUF0j7O-ahfgJfIz31wKO9skOIqM2URWC0sw2NuNOrTcgTb0i8UKj-x1fhXsDEMekM_Ua4U1GCLAbQ6qMeuZ4Nff74LnZeUiznpui06FoftuLVu5w_wU22rTQVR9x7Q2u6eQSRJ9fCZvMFeTvBVTcefh_7FoN6nF8cFQ5K_REYTk3QBu-88Ivv35zjFh3m5gWCaH5wR3W8LvpmW4nc0WeTO8kewKp_CEpasV6WxBWGCQxDPvezJDgZZg3DjaYcT_b4lKOxO89zKrnAe7cPlStbnr05o47Ob0ul6yRGZNsZHpQNRHLKD35hM_XwH8PVqqK4xZpSO8_QbCFmTTQ"
	dp4096Base64   = "gVSGqrCgiWv5fxPj6x9_XEkZW0nMO2J3QSo2iHmLGPRkIt9HnLlBs7VOJZZKPWm4l7zINVFg5YtK8p8XRd0sq7Zw9jS5wFjms1FJR_LCfeXtQk9zseHxvkoYiRGgMz86Zohliz7o4yZaUS5N6srcRw7jBOu1IkEjr7RhmE_oUk_gtrMNMqWfbtLcdKlrx8v9G7ROWKcJIjXF1icuEqLIYsuMjPXRCapPscZHKHWhRGDB7VIHxLIrxJTHlH63ymOoyv0xNh0ADd8WotefE92RQNl5FJtIjL9ElFpbaq8TIhv0SR67t_yifKIOIh9Jw8N7ifzy3A4stj-Pipt6FCJQWQ"
	dq4096Base64   = "th2E_5NKTkN7Fu4bS5_fSuEzcLU4W956VGShI8A0PfV1-eEo7535RCMNOcyc9dwO2yi350C2nvAkwb_uOfzVNA_66gAQFgxTXcCSDnzYG-Uz0A-lVKH8TT4CxGFWn158p4fxUV7fRbGWt1mITeZSw41ZNM-SUk6Ae007WQvDm8QX7kiFp2HSjdrc5sj9s7lh0-f9SAZN-TQKln-LeZl0OIQfSFeaR23bVQiMMI9o8rKdAcZZelp8jQZihPY-N6aMOHnDKqODZnX9DrJxmIOpGURWHp3X6KprsXFX8IxI-Ob65cPlortrXVgO7GyX3c2b4KSe8oOnAxrXq6jUON9OlQ"
	qInv4096Base64 = "IvuOX82bdnEE5xJE21MFjBgGHhsNH2O3Pi1ZqV4qEM2HQmoz2hPCh83vgTbl5H6T-5swrZJiintUP0jrARqGNWqzy0gPJ-ORsBjKGH2Xrz2C4xhh7K-mY9t4qonDvUaOaq3vs6Q_eLwAuAFMldtU6dIaAX6PIfZxVF7d6all6jLf_0XNo3_KGqUTL2yO7SIr0B_tWm59Y5WAxZVXd6hlRMLEyTm9uLTEht2lMHKGGgM0NZvbN1hHXknZDQU5lE54z8_Y__Vbsxoc68ZbKPUeeQcBsveRIYiYTwNObpbhxSUeM_44-yIbznqQqGhXxfVrbKdzB8RdUpCx8Iit4IKzSQ"
)

func mustDecodeBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(value)
	if err != nil {
		t.Fatalf("base64 decoding failed: %v", err)
	}
	return decoded
}

func TestNewPublicKeyInvalidValues(t *testing.T) {
	modulus2048 := mustDecodeBase64(t, n2048Base64)
	tinkParams, err := rsassapkcs1.NewParameters(2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v) = %v, want nil", 2048, rsassapkcs1.SHA256, rsassapkcs1.VariantTink, err)
	}
	noPrefixParams, err := rsassapkcs1.NewParameters(2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantNoPrefix)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v) = %v, want nil", 2048, rsassapkcs1.SHA256, rsassapkcs1.VariantNoPrefix, err)
	}
	// Valid modules are [2^2047, 2^2048).
	minModulus := new(big.Int).Exp(big.NewInt(2), big.NewInt(2047), nil)
	maxModulus := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(2048), nil), big.NewInt(1))
	// The bytes size of the slice is correct, but the value is too small or too big.
	tooSmallModulus := make([]byte, 256)
	tooSmallModulusInt := new(big.Int).Sub(minModulus, big.NewInt(1))
	tooSmallModulusInt.FillBytes(tooSmallModulus)
	for _, tc := range []struct {
		name          string
		modulus       []byte
		idRequirement uint32
		parameters    *rsassapkcs1.Parameters
	}{
		{
			name:          "empty params",
			modulus:       modulus2048,
			idRequirement: 123,
			parameters:    &rsassapkcs1.Parameters{},
		},
		{
			name:          "nil modulus",
			modulus:       nil,
			idRequirement: 123,
			parameters:    tinkParams,
		},
		{
			name:          "modulus slice too small",
			modulus:       tooSmallModulus[:255],
			idRequirement: 123,
			parameters:    tinkParams,
		},
		{
			name:          "modulus value too small",
			modulus:       tooSmallModulus,
			idRequirement: 123,
			parameters:    tinkParams,
		},
		{
			name:          "modulus too big",
			modulus:       new(big.Int).Add(maxModulus, big.NewInt(1)).Bytes(),
			idRequirement: 123,
			parameters:    tinkParams,
		},
		{
			name:          "invalid ID requirement",
			modulus:       modulus2048,
			idRequirement: 123,
			parameters:    noPrefixParams,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rsassapkcs1.NewPublicKey(tc.modulus, tc.idRequirement, tc.parameters); err == nil {
				t.Errorf("rsassapkcs1.NewPublicKey(%v, %d, %v) = nil, want error", tc.modulus, tc.idRequirement, tc.parameters)
			}
		})
	}
}

type testCase struct {
	name            string
	modulusSizeBits int
	hashType        rsassapkcs1.HashType
	publicExponent  int
	variant         rsassapkcs1.Variant
	modulus         []byte
	idRequirement   uint32
}

func testCases(t *testing.T) []testCase {
	t.Helper()
	testCases := []testCase{}
	for _, hashType := range []rsassapkcs1.HashType{rsassapkcs1.SHA256, rsassapkcs1.SHA384, rsassapkcs1.SHA512} {
		for _, variant := range []rsassapkcs1.Variant{rsassapkcs1.VariantTink, rsassapkcs1.VariantCrunchy, rsassapkcs1.VariantLegacy, rsassapkcs1.VariantNoPrefix} {
			for _, modulusSizeBits := range []int{2048, 3072, 4096} {
				idRequirement := 123
				if variant == rsassapkcs1.VariantNoPrefix {
					idRequirement = 0
				}
				var modulus []byte
				switch modulusSizeBits {
				case 2048:
					modulus = mustDecodeBase64(t, n2048Base64)
				case 3072:
					modulus = mustDecodeBase64(t, n3072Base64)
				case 4096:
					modulus = mustDecodeBase64(t, n4096Base64)
				default:
					t.Fatalf("invalid modulus size: %v", modulusSizeBits)
				}
				testCases = append(testCases, testCase{
					name:            fmt.Sprintf("%v-SHA%v-%v-minModule", modulusSizeBits, hashType, variant),
					modulusSizeBits: modulusSizeBits,
					hashType:        hashType,
					publicExponent:  f4,
					variant:         variant,
					modulus:         modulus,
					idRequirement:   uint32(idRequirement),
				})
			}
		}
	}

	return testCases
}

func TestNewPublicKey(t *testing.T) {
	for _, tc := range testCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			params, err := rsassapkcs1.NewParameters(tc.modulusSizeBits, tc.hashType, tc.publicExponent, tc.variant)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", tc.modulusSizeBits, tc.hashType, tc.publicExponent, tc.variant, err)
			}
			key, err := rsassapkcs1.NewPublicKey(tc.modulus, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewPublicKey(%v, %d, %v) = %v, want nil", tc.modulus, tc.idRequirement, params, err)
			}
			if got, want := key.Parameters(), params; !got.Equal(want) {
				t.Errorf("key.Parameters() = %v, want %v", got, want)
			}
			idRequirement, required := key.IDRequirement()
			if idRequirement != tc.idRequirement {
				t.Errorf("key.IDRequirement() = %v, want %v", idRequirement, tc.idRequirement)
			}
			if required != key.Parameters().HasIDRequirement() {
				t.Errorf("key.IDRequirement() = %v, want %v", required, key.Parameters().HasIDRequirement())
			}
			if got, want := idRequirement, tc.idRequirement; got != want {
				t.Errorf("key.IDRequirement() = %v, want %v", got, want)
			}
			if got, want := key.Modulus(), tc.modulus; !bytes.Equal(got, want) {
				t.Errorf("key.Modulus() = %v, want %v", got, want)
			}
			otherKey, err := rsassapkcs1.NewPublicKey(tc.modulus, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewPublicKey(%v, %d, %v) = %v, want nil", tc.modulus, tc.idRequirement, params, err)
			}
			if !key.Equal(otherKey) {
				t.Errorf("key.Equal(otherKey) = false, want true")
			}
		})
	}
}

func TestNewPublicKeyMinMaxValues(t *testing.T) {
	// Valid values: [2^(n-1), 2^n).
	minModulus2048 := new(big.Int).Exp(big.NewInt(2), big.NewInt(2047), nil)
	maxModulus2048 := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(2048), nil), big.NewInt(1))
	minModulus3072 := new(big.Int).Exp(big.NewInt(2), big.NewInt(3071), nil)
	maxModulus3072 := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(3072), nil), big.NewInt(1))
	minModulus4096 := new(big.Int).Exp(big.NewInt(2), big.NewInt(4095), nil)
	maxModulus4096 := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(4096), nil), big.NewInt(1))
	for _, tc := range []struct {
		name   string
		module []byte
		params *rsassapkcs1.Parameters
	}{
		{
			name:   "min module 2048 bit",
			module: minModulus2048.Bytes(),
			params: mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink),
		},
		{
			name:   "max module 2048 bit",
			module: maxModulus2048.Bytes(),
			params: mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink),
		},
		{
			name:   "min module 3072 bit",
			module: minModulus3072.Bytes(),
			params: mustCreateParameters(t, 3072, rsassapkcs1.SHA384, f4, rsassapkcs1.VariantTink),
		},
		{
			name:   "max module 3072 bit",
			module: maxModulus3072.Bytes(),
			params: mustCreateParameters(t, 3072, rsassapkcs1.SHA384, f4, rsassapkcs1.VariantTink),
		},
		{
			name:   "min module 4096 bit",
			module: minModulus4096.Bytes(),
			params: mustCreateParameters(t, 4096, rsassapkcs1.SHA512, f4, rsassapkcs1.VariantTink),
		},
		{
			name:   "max module 4096 bit",
			module: maxModulus4096.Bytes(),
			params: mustCreateParameters(t, 4096, rsassapkcs1.SHA512, f4, rsassapkcs1.VariantTink),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rsassapkcs1.NewPublicKey(tc.module, 123, tc.params); err != nil {
				t.Errorf("rsassapkcs1.NewPublicKey(%v, %d, %v) err = %v, want nil", tc.module, 123, tc.params, err)
			}
		})
	}
}

func mustCreateParameters(t *testing.T, modulusSizeBits int, hashType rsassapkcs1.HashType, publicExponent int, variant rsassapkcs1.Variant) *rsassapkcs1.Parameters {
	t.Helper()
	params, err := rsassapkcs1.NewParameters(modulusSizeBits, hashType, publicExponent, variant)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", modulusSizeBits, hashType, publicExponent, variant, err)
	}
	return params
}

func mustCreatePublicKey(t *testing.T, modulus []byte, idRequirement uint32, parameters *rsassapkcs1.Parameters) *rsassapkcs1.PublicKey {
	t.Helper()
	key, err := rsassapkcs1.NewPublicKey(modulus, idRequirement, parameters)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewPublicKey(%v, %d, %v) = %v, want nil", modulus, idRequirement, parameters, err)
	}
	return key
}

func TestNewPublicKeyEqualFailsIfDifferentKeys(t *testing.T) {
	validModulus2048 := mustDecodeBase64(t, n2048Base64)
	// From:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_2048_test.json#L353
	otherN2048Base64 := "3ZBFkDl4CMQxQyliPZATRThDJRsTuLPE_vVFmBEq8-sxxxEDxiWZUWdOU72Tp-NtGUcuR06-gChobZUpSE2Lr-pKBLoZVVZnYWyEeGcFlACcm8aj7-UidMumTHJHR9ftwZTk_t3jKjKJ2Uwxk25-ehXXVvVISS9bNFuSfoxhi91VCsshoXrhSDBDg9ubPHuqPkyL2OhEqITao-GNVpmMsy-brk1B1WoY3dQxPICJt16du5EoRwusmwh_thkoqw-MTIk2CwIImQCNCOi9MfkHqAfoBWrWgA3_357Z2WSpOefkgRS4SXhVGsuFyd-RlvPv9VKG1s1LOagiqKd2Ohggjw"
	otherValidModulus2048 := mustDecodeBase64(t, otherN2048Base64)
	validModulus3072 := mustDecodeBase64(t, n3072Base64)
	for _, tc := range []struct {
		name string
		this *rsassapkcs1.PublicKey
		that *rsassapkcs1.PublicKey
	}{
		{
			name: "different modulus",
			this: mustCreatePublicKey(t, validModulus2048, 123, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)),
			that: mustCreatePublicKey(t, otherValidModulus2048, 123, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)),
		},
		{
			name: "different parameters",
			this: mustCreatePublicKey(t, validModulus2048, 123, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)),
			that: mustCreatePublicKey(t, validModulus2048, 123, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantCrunchy)),
		},
		{
			name: "different ID requirement",
			this: mustCreatePublicKey(t, validModulus2048, 123, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)),
			that: mustCreatePublicKey(t, validModulus2048, 234, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)),
		},
		{
			name: "different modulus size",
			this: mustCreatePublicKey(t, validModulus2048, 123, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)),
			that: mustCreatePublicKey(t, validModulus3072, 123, mustCreateParameters(t, 3072, rsassapkcs1.SHA384, f4, rsassapkcs1.VariantTink)),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.this.Equal(tc.that) {
				t.Errorf("tc.this.Equal(tc.that) = true, want false")
			}
			if tc.that.Equal(tc.this) {
				t.Errorf("tc.that.Equal(tc.this) = true, want false")
			}
		})
	}
}

func TestPublicKeyOutputPrefix(t *testing.T) {
	validModulus2048 := mustDecodeBase64(t, n2048Base64)
	for _, tc := range []struct {
		name          string
		variant       rsassapkcs1.Variant
		idRequirement uint32
		want          []byte
	}{
		{
			name:          "Tink",
			variant:       rsassapkcs1.VariantTink,
			idRequirement: uint32(0x01020304),
			want:          []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:          "Crunchy",
			variant:       rsassapkcs1.VariantCrunchy,
			idRequirement: uint32(0x01020304),
			want:          []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:          "Legacy",
			variant:       rsassapkcs1.VariantLegacy,
			idRequirement: uint32(0x01020304),
			want:          []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:          "NoPrefix",
			variant:       rsassapkcs1.VariantNoPrefix,
			idRequirement: 0,
			want:          nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := rsassapkcs1.NewParameters(2048, rsassapkcs1.SHA256, f4, tc.variant)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v) = %v, want nil", 2048, rsassapkcs1.SHA256, tc.variant, err)
			}
			pubKey, err := rsassapkcs1.NewPublicKey(validModulus2048, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewPublicKey(%v, %v, %v) err = %v, want nil", validModulus2048, tc.idRequirement, params, err)
			}
			if got, want := pubKey.OutputPrefix(), tc.want; !bytes.Equal(got, want) {
				t.Errorf("pubKey.OutputPrefix() = %v, want %v", got, want)
			}
		})
	}
}

func TestNewPrivateKeyInvalidValues(t *testing.T) {
	n := mustDecodeBase64(t, n2048Base64)
	d := mustDecodeBase64(t, d2048Base64)
	p := mustDecodeBase64(t, p2048Base64)
	q := mustDecodeBase64(t, q2048Base64)
	privateKeyValues := rsassapkcs1.PrivateKeyValues{
		P: secretdata.NewBytesFromData(p, insecuresecretdataaccess.Token{}),
		Q: secretdata.NewBytesFromData(q, insecuresecretdataaccess.Token{}),
		D: secretdata.NewBytesFromData(d, insecuresecretdataaccess.Token{}),
	}
	params, err := rsassapkcs1.NewParameters(2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink, err)
	}
	publicKey, err := rsassapkcs1.NewPublicKey(n, 0x11223344, params)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewPublicKey(%v, %v, %v) = %v, want nil", n, 0x11223344, params, err)
	}
	invalidD := mustDecodeBase64(t, d2048Base64)
	invalidD[0]++
	invalidP := mustDecodeBase64(t, p2048Base64)
	invalidP[0]++
	invalidQ := mustDecodeBase64(t, q2048Base64)
	invalidQ[0]++

	// From:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_2048_test.json#L353
	differentN2048Base64 := "3ZBFkDl4CMQxQyliPZATRThDJRsTuLPE_vVFmBEq8-sxxxEDxiWZUWdOU72Tp-NtGUcuR06-gChobZUpSE2Lr-pKBLoZVVZnYWyEeGcFlACcm8aj7-UidMumTHJHR9ftwZTk_t3jKjKJ2Uwxk25-ehXXVvVISS9bNFuSfoxhi91VCsshoXrhSDBDg9ubPHuqPkyL2OhEqITao-GNVpmMsy-brk1B1WoY3dQxPICJt16du5EoRwusmwh_thkoqw-MTIk2CwIImQCNCOi9MfkHqAfoBWrWgA3_357Z2WSpOefkgRS4SXhVGsuFyd-RlvPv9VKG1s1LOagiqKd2Ohggjw"
	differentPublicKey := mustCreatePublicKey(t, mustDecodeBase64(t, differentN2048Base64), 0x11223344, params)

	token := insecuresecretdataaccess.Token{}
	for _, tc := range []struct {
		name             string
		publicKey        *rsassapkcs1.PublicKey
		privateKeyValues rsassapkcs1.PrivateKeyValues
	}{
		{
			name:             "empty public key",
			publicKey:        &rsassapkcs1.PublicKey{},
			privateKeyValues: privateKeyValues,
		},
		{
			name:             "empty private key values",
			publicKey:        publicKey,
			privateKeyValues: rsassapkcs1.PrivateKeyValues{},
		},
		{
			name:      "invalid P",
			publicKey: publicKey,
			privateKeyValues: rsassapkcs1.PrivateKeyValues{
				P: secretdata.NewBytesFromData(invalidP, token),
				Q: secretdata.NewBytesFromData(q, token),
				D: secretdata.NewBytesFromData(d, token),
			},
		},
		{
			name:      "invalid Q",
			publicKey: publicKey,
			privateKeyValues: rsassapkcs1.PrivateKeyValues{
				P: secretdata.NewBytesFromData(p, token),
				Q: secretdata.NewBytesFromData(invalidQ, token),
				D: secretdata.NewBytesFromData(d, token),
			},
		},
		{
			name:      "invalid D",
			publicKey: publicKey,
			privateKeyValues: rsassapkcs1.PrivateKeyValues{
				P: secretdata.NewBytesFromData(p, token),
				Q: secretdata.NewBytesFromData(q, token),
				D: secretdata.NewBytesFromData(invalidD, token),
			},
		},
		{
			name:      "incompatible public key",
			publicKey: differentPublicKey,
			privateKeyValues: rsassapkcs1.PrivateKeyValues{
				P: secretdata.NewBytesFromData(p, token),
				Q: secretdata.NewBytesFromData(q, token),
				D: secretdata.NewBytesFromData(d, token),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rsassapkcs1.NewPrivateKey(tc.publicKey, tc.privateKeyValues); err == nil {
				t.Errorf("rsassapkcs1.NewPrivateKey(tc.publicKey, %v) = nil, want error", tc.privateKeyValues)
			}
		})
	}
}

type privateKeyTestCase struct {
	name             string
	publicKey        *rsassapkcs1.PublicKey
	privateKeyValues rsassapkcs1.PrivateKeyValues
	dp               secretdata.Bytes
	dq               secretdata.Bytes
	qInv             secretdata.Bytes
}

func setStringToBigInt(t *testing.T, s string, base int) *big.Int {
	t.Helper()
	i, ok := new(big.Int).SetString(s, base)
	if !ok {
		t.Fatalf("failed to parse %v as a base %v big number", s, base)
	}
	return i
}

func privateKeyTestCases(t *testing.T) []privateKeyTestCase {
	var testCases []privateKeyTestCase

	for _, hashType := range []rsassapkcs1.HashType{rsassapkcs1.SHA256, rsassapkcs1.SHA384, rsassapkcs1.SHA512} {
		for _, variant := range []rsassapkcs1.Variant{rsassapkcs1.VariantTink, rsassapkcs1.VariantCrunchy, rsassapkcs1.VariantLegacy, rsassapkcs1.VariantNoPrefix} {
			idRequirement := uint32(123)
			if variant == rsassapkcs1.VariantNoPrefix {
				idRequirement = 0
			}

			// 2048 bits
			token := insecuresecretdataaccess.Token{}
			testCases = append(testCases, privateKeyTestCase{
				name:      fmt.Sprintf("%v-%v-%v", 2048, hashType, variant),
				publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n2048Base64), idRequirement, mustCreateParameters(t, 2048, hashType, f4, variant)),
				privateKeyValues: rsassapkcs1.PrivateKeyValues{
					P: secretdata.NewBytesFromData(mustDecodeBase64(t, p2048Base64), token),
					Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q2048Base64), token),
					D: secretdata.NewBytesFromData(mustDecodeBase64(t, d2048Base64), token),
				},
				dp:   secretdata.NewBytesFromData(mustDecodeBase64(t, dp2048Base64), token),
				dq:   secretdata.NewBytesFromData(mustDecodeBase64(t, dq2048Base64), token),
				qInv: secretdata.NewBytesFromData(mustDecodeBase64(t, qInv2048Base64), token),
			})

			testCases = append(testCases, privateKeyTestCase{
				name:      fmt.Sprintf("%v-%v-%v-android", 2048, hashType, variant),
				publicKey: mustCreatePublicKey(t, setStringToBigInt(t, n2048BigInt16, 16).Bytes(), idRequirement, mustCreateParameters(t, 2048, hashType, f4, variant)),
				privateKeyValues: rsassapkcs1.PrivateKeyValues{
					P: secretdata.NewBytesFromData(setStringToBigInt(t, p2048BigInt10, 10).Bytes(), token),
					Q: secretdata.NewBytesFromData(setStringToBigInt(t, q2048BigInt10, 10).Bytes(), token),
					D: secretdata.NewBytesFromData(setStringToBigInt(t, d2048BigInt10, 10).Bytes(), token),
				},
				dp:   secretdata.NewBytesFromData(setStringToBigInt(t, dp2048BigInt10, 10).Bytes(), token),
				dq:   secretdata.NewBytesFromData(setStringToBigInt(t, dq2048BigInt10, 10).Bytes(), token),
				qInv: secretdata.NewBytesFromData(setStringToBigInt(t, qInv2048BigInt10, 10).Bytes(), token),
			})

			// 3072 bits
			params3072, err := rsassapkcs1.NewParameters(3072, hashType, f4, variant)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", 3072, hashType, f4, variant, err)
			}
			publicKey3072, err := rsassapkcs1.NewPublicKey(mustDecodeBase64(t, n3072Base64), idRequirement, params3072)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewPublicKey(n, %v, %v) = %v, want nil", idRequirement, params3072, err)
			}
			testCases = append(testCases, privateKeyTestCase{
				name:      fmt.Sprintf("%v-%v-%v", 3072, hashType, variant),
				publicKey: publicKey3072,
				privateKeyValues: rsassapkcs1.PrivateKeyValues{
					P: secretdata.NewBytesFromData(mustDecodeBase64(t, p3072Base64), token),
					Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q3072Base64), token),
					D: secretdata.NewBytesFromData(mustDecodeBase64(t, d3072Base64), token),
				},
				dp:   secretdata.NewBytesFromData(mustDecodeBase64(t, dp3072Base64), token),
				dq:   secretdata.NewBytesFromData(mustDecodeBase64(t, dq3072Base64), token),
				qInv: secretdata.NewBytesFromData(mustDecodeBase64(t, qInv3072Base64), token),
			})

			// 4096 bits
			params4096, err := rsassapkcs1.NewParameters(4096, hashType, f4, variant)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", 4096, hashType, f4, variant, err)
			}
			publicKey4096, err := rsassapkcs1.NewPublicKey(mustDecodeBase64(t, n4096Base64), idRequirement, params4096)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewPublicKey(n, %v, %v) = %v, want nil", idRequirement, params4096, err)
			}
			testCases = append(testCases, privateKeyTestCase{
				name:      fmt.Sprintf("%v-%v-%v", 4096, hashType, variant),
				publicKey: publicKey4096,
				privateKeyValues: rsassapkcs1.PrivateKeyValues{
					P: secretdata.NewBytesFromData(mustDecodeBase64(t, p4096Base64), token),
					Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q4096Base64), token),
					D: secretdata.NewBytesFromData(mustDecodeBase64(t, d4096Base64), token),
				},
				dp:   secretdata.NewBytesFromData(mustDecodeBase64(t, dp4096Base64), token),
				dq:   secretdata.NewBytesFromData(mustDecodeBase64(t, dq4096Base64), token),
				qInv: secretdata.NewBytesFromData(mustDecodeBase64(t, qInv4096Base64), token),
			})
		}
	}
	return testCases
}

func TestNewPrivateKey(t *testing.T) {
	for _, tc := range privateKeyTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, err := rsassapkcs1.NewPrivateKey(tc.publicKey, tc.privateKeyValues)
			if err != nil {
				t.Errorf("rsassapkcs1.NewPrivateKey(tc.publicKey, %v) err = %v, want nil", tc.privateKeyValues, err)
			}
			if !privateKey.D().Equal(tc.privateKeyValues.D) {
				t.Errorf("privateKey.D() = %v, want %v", privateKey.D(), tc.privateKeyValues.D)
			}
			if !privateKey.P().Equal(tc.privateKeyValues.P) {
				t.Errorf("privateKey.P() = %v, want %v", privateKey.P(), tc.privateKeyValues.P)
			}
			if !privateKey.Q().Equal(tc.privateKeyValues.Q) {
				t.Errorf("privateKey.Q() = %v, want %v", privateKey.Q(), tc.privateKeyValues.Q)
			}
			if !privateKey.DP().Equal(tc.dp) {
				t.Errorf("privateKey.DP() = %v, want %v", privateKey.DP(), tc.dp)
			}
			if !privateKey.DQ().Equal(tc.dq) {
				t.Errorf("privateKey.DQ() = %v, want %v", privateKey.DQ(), tc.dq)
			}
			if !privateKey.QInv().Equal(tc.qInv) {
				t.Errorf("privateKey.QInv() = %v, want %v", privateKey.QInv(), tc.qInv)
			}
			gotIDRequirement, gotRequired := privateKey.IDRequirement()
			wantIDRequirement, wantRequired := tc.publicKey.IDRequirement()
			if gotIDRequirement != wantIDRequirement || gotRequired != wantRequired {
				t.Errorf("invalid ID requirement: got (%v, %v), want (%v, %v)", gotIDRequirement, gotRequired, wantIDRequirement, wantRequired)
			}
			if got, want := privateKey.OutputPrefix(), tc.publicKey.OutputPrefix(); !bytes.Equal(got, want) {
				t.Errorf("privateKey.OutputPrefix() = %v, want %v", got, want)
			}
			if got, want := privateKey.Parameters(), tc.publicKey.Parameters(); !got.Equal(want) {
				t.Errorf("privateKey.Parameters() = %v, want %v", got, want)
			}
			want, err := privateKey.PublicKey()
			if err != nil {
				t.Fatalf("privateKey.PublicKey() err = %v, want nil", err)
			}
			if got := tc.publicKey; !got.Equal(want) {
				t.Errorf("privateKey.PublicKey() = %v, want %v", got, want)
			}
			otherPrivateKey, err := rsassapkcs1.NewPrivateKey(tc.publicKey, tc.privateKeyValues)
			if err != nil {
				t.Errorf("rsassapkcs1.NewPrivateKey(tc.publicKey, %v) err = %v, want nil", tc.privateKeyValues, err)
			}
			if !privateKey.Equal(otherPrivateKey) {
				t.Errorf("privateKey.Equal(otherPrivateKey) = false, want true")
			}
		})
	}
}

func TestNewPrivateKeyEqualFailsIfKeysAreDifferent(t *testing.T) {
	// From:
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_2048_test.json#L353
	differentN2048Base64 := "3ZBFkDl4CMQxQyliPZATRThDJRsTuLPE_vVFmBEq8-sxxxEDxiWZUWdOU72Tp-NtGUcuR06-gChobZUpSE2Lr-pKBLoZVVZnYWyEeGcFlACcm8aj7-UidMumTHJHR9ftwZTk_t3jKjKJ2Uwxk25-ehXXVvVISS9bNFuSfoxhi91VCsshoXrhSDBDg9ubPHuqPkyL2OhEqITao-GNVpmMsy-brk1B1WoY3dQxPICJt16du5EoRwusmwh_thkoqw-MTIk2CwIImQCNCOi9MfkHqAfoBWrWgA3_357Z2WSpOefkgRS4SXhVGsuFyd-RlvPv9VKG1s1LOagiqKd2Ohggjw"
	differentD2048Base64 := "K9aK3QFx7ZIcCSTcCkBCf9Sk_GeCHG59UNDoxzDGZeKoQ7HrJD52OnQNPGZrG7HU-UZrMrKy4JqeJuh3dZXaSKE7qfnEX20sIUueXlBL-z-vvOatsx6MFb3hloiZ7-4aXc3_DSqL8uJzAeqgeIJJRhCiPdNkTQ6wpghkUOOnvUtcRGwBgUvhbCCGGfilt0Y_ylg9k2hkv3TZZ4iq6OW648BSorQJ35oI65vnaz26uiiGPVxW7kLuzbhQdeBN6Qtt072UCNf6VpRpfBhRYjKaubV_IahMqwB8HBDZdfVJGXf-z2yUnzpWbYS-R33aqwLAdi0bIy-KYZEHFaD_pDikYQ"
	differentP2048Base64 := "_aykrdsX5T7qB7lJITtX2lDWWQc4ZP08IeVw60UPkBT6Q85TtM5MVayhic6TqMHWao60reJ62vdkrXV3wRvwuvFmpU8IDF8HZaSz_TlObWYKswJUy4mZ8P1wOHfHHkzvA4rK-B8IkefdBtf9WywBTmc0dm0YrbI8q655mY_z47E"
	differentQ2048Base64 := "35hEOarCZ7siiOU6ukmOSCWwAYJr-fgM8cChRQfziLNjRrfdWOo3FOnA5cr36lbHOsdBWysPB-sBp0oIU3RSvi7JGN6k2jMCVTQeDm_zS7JMok2V42mlulXpvRp9C6av8dpxjOsQbuHEY6f8MMEde4hcdrZfKLDzJD5ZHL6CmD8"
	token := insecuresecretdataaccess.Token{}
	for _, tc := range []struct {
		name string
		this *rsassapkcs1.PrivateKey
		that *rsassapkcs1.PrivateKey
	}{
		{
			name: "different RSA keys",
			this: func() *rsassapkcs1.PrivateKey {
				publicKey := mustCreatePublicKey(t, mustDecodeBase64(t, n2048Base64), 123, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink))
				privateKeyValue := rsassapkcs1.PrivateKeyValues{
					P: secretdata.NewBytesFromData(mustDecodeBase64(t, p2048Base64), token),
					Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q2048Base64), token),
					D: secretdata.NewBytesFromData(mustDecodeBase64(t, d2048Base64), token),
				}
				privateKey, err := rsassapkcs1.NewPrivateKey(publicKey, privateKeyValue)
				if err != nil {
					t.Fatalf("rsassapkcs1.NewPrivateKey(%v, %v) = %v, want nil", publicKey, privateKeyValue, err)
				}
				return privateKey
			}(),
			that: func() *rsassapkcs1.PrivateKey {
				publicKey := mustCreatePublicKey(t, mustDecodeBase64(t, differentN2048Base64), 123, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink))
				privateKeyValue := rsassapkcs1.PrivateKeyValues{
					P: secretdata.NewBytesFromData(mustDecodeBase64(t, differentP2048Base64), token),
					Q: secretdata.NewBytesFromData(mustDecodeBase64(t, differentQ2048Base64), token),
					D: secretdata.NewBytesFromData(mustDecodeBase64(t, differentD2048Base64), token),
				}
				privateKey, err := rsassapkcs1.NewPrivateKey(publicKey, privateKeyValue)
				if err != nil {
					t.Fatalf("rsassapkcs1.NewPrivateKey(%v, %v) = %v, want nil", publicKey, privateKeyValue, err)
				}
				return privateKey
			}(),
		},
		{
			name: "different parameters - ID requirement",
			this: func() *rsassapkcs1.PrivateKey {
				publicKey := mustCreatePublicKey(t, mustDecodeBase64(t, n2048Base64), 123, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink))
				privateKeyValue := rsassapkcs1.PrivateKeyValues{
					P: secretdata.NewBytesFromData(mustDecodeBase64(t, p2048Base64), token),
					Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q2048Base64), token),
					D: secretdata.NewBytesFromData(mustDecodeBase64(t, d2048Base64), token),
				}
				privateKey, err := rsassapkcs1.NewPrivateKey(publicKey, privateKeyValue)
				if err != nil {
					t.Fatalf("rsassapkcs1.NewPrivateKey(%v, %v) = %v, want nil", publicKey, privateKeyValue, err)
				}
				return privateKey
			}(),
			that: func() *rsassapkcs1.PrivateKey {
				publicKey := mustCreatePublicKey(t, mustDecodeBase64(t, n2048Base64), 456, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink))
				privateKeyValue := rsassapkcs1.PrivateKeyValues{
					P: secretdata.NewBytesFromData(mustDecodeBase64(t, p2048Base64), token),
					Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q2048Base64), token),
					D: secretdata.NewBytesFromData(mustDecodeBase64(t, d2048Base64), token),
				}
				privateKey, err := rsassapkcs1.NewPrivateKey(publicKey, privateKeyValue)
				if err != nil {
					t.Fatalf("rsassapkcs1.NewPrivateKey(%v, %v) = %v, want nil", publicKey, privateKeyValue, err)
				}
				return privateKey
			}(),
		},
		{
			name: "different parameters - variant",
			this: func() *rsassapkcs1.PrivateKey {
				publicKey := mustCreatePublicKey(t, mustDecodeBase64(t, n2048Base64), 123, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink))
				privateKeyValue := rsassapkcs1.PrivateKeyValues{
					P: secretdata.NewBytesFromData(mustDecodeBase64(t, p2048Base64), token),
					Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q2048Base64), token),
					D: secretdata.NewBytesFromData(mustDecodeBase64(t, d2048Base64), token),
				}
				privateKey, err := rsassapkcs1.NewPrivateKey(publicKey, privateKeyValue)
				if err != nil {
					t.Fatalf("rsassapkcs1.NewPrivateKey(%v, %v) = %v, want nil", publicKey, privateKeyValue, err)
				}
				return privateKey
			}(),
			that: func() *rsassapkcs1.PrivateKey {
				publicKey := mustCreatePublicKey(t, mustDecodeBase64(t, n2048Base64), 123, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantCrunchy))
				privateKeyValue := rsassapkcs1.PrivateKeyValues{
					P: secretdata.NewBytesFromData(mustDecodeBase64(t, p2048Base64), token),
					Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q2048Base64), token),
					D: secretdata.NewBytesFromData(mustDecodeBase64(t, d2048Base64), token),
				}
				privateKey, err := rsassapkcs1.NewPrivateKey(publicKey, privateKeyValue)
				if err != nil {
					t.Fatalf("rsassapkcs1.NewPrivateKey(%v, %v) = %v, want nil", publicKey, privateKeyValue, err)
				}
				return privateKey
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.this.Equal(tc.that) {
				t.Errorf("tc.this.Equal(tc.that) = true, want false")
			}
			if tc.that.Equal(tc.this) {
				t.Errorf("tc.that.Equal(tc.this) = true, want false")
			}
		})
	}
}

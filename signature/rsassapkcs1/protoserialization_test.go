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

package rsassapkcs1

import (
	"encoding/base64"
	"math/big"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	rsassapkcs1pb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

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

func mustCreateKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

func TestParsePublicKeyFails(t *testing.T) {
	publicKey := rsassapkcs1pb.RsaSsaPkcs1PublicKey{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: commonpb.HashType_SHA256,
		},
		N:       mustDecodeBase64(t, n2048Base64),
		E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
		Version: publicKeyProtoVersion,
	}
	serializedPublicKey := mustMarshalProto(t, &publicKey)
	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name:             "key data is nil",
			keySerialization: mustCreateKeySerialization(t, nil, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "wrong type URL",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "invalid_type_url",
				Value:           serializedPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "wrong key material type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "wrong key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: mustMarshalProto(t, &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
					Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
						HashType: commonpb.HashType_SHA256,
					},
					N:       mustDecodeBase64(t, n2048Base64),
					E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
					Version: publicKeyProtoVersion + 1,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "invalid modulus",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: mustMarshalProto(t, &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
					Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
						HashType: commonpb.HashType_SHA256,
					},
					N:       mustDecodeBase64(t, n2048Base64[:255]),
					E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
					Version: publicKeyProtoVersion + 1,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
		{
			name: "invalid exponent",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: verifierTypeURL,
				Value: mustMarshalProto(t, &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
					Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
						HashType: commonpb.HashType_SHA256,
					},
					N:       mustDecodeBase64(t, n2048Base64),
					E:       new(big.Int).Sub(new(big.Int).SetUint64(uint64(f4)), big.NewInt(1)).Bytes(),
					Version: publicKeyProtoVersion + 1,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &publicKeyParser{}
			if _, err := p.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want non-nil", tc.keySerialization)
			}
		})
	}
}

func mustCreateParameters(t *testing.T, modulusSizeBits int, hashType HashType, publicExponent int, variant Variant) *Parameters {
	t.Helper()
	params, err := NewParameters(modulusSizeBits, hashType, publicExponent, variant)
	if err != nil {
		t.Fatalf("NewParameters(%v, %v, %v, %v) = %v, want nil", modulusSizeBits, hashType, publicExponent, variant, err)
	}
	return params
}

func mustCreatePublicKey(t *testing.T, modulus []byte, idRequirement uint32, parameters *Parameters) *PublicKey {
	t.Helper()
	key, err := NewPublicKey(modulus, idRequirement, parameters)
	if err != nil {
		t.Fatalf("NewPublicKey(%v, %d, %v) = %v, want nil", modulus, idRequirement, parameters, err)
	}
	return key
}

func TestParsePublicKeyWithZeroPaddingModulus(t *testing.T) {
	n := mustDecodeBase64(t, n2048Base64)
	publicKey := &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: commonpb.HashType_SHA256,
		},
		N:       slices.Concat([]byte{0, 0, 0, 0}, n),
		E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
		Version: publicKeyProtoVersion,
	}
	serializedPublicKey := mustMarshalProto(t, publicKey)

	keySerialization := mustCreateKeySerialization(t, &tinkpb.KeyData{
		TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey",
		Value:           serializedPublicKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, tinkpb.OutputPrefixType_TINK, 123)

	wantPublicKey :=
		mustCreatePublicKey(t, n, 123, mustCreateParameters(t, 2048, SHA256, f4, VariantTink))

	parser := &publicKeyParser{}
	parsedPublicKey, err := parser.ParseKey(keySerialization)
	if err != nil {
		t.Fatalf("parser.ParseKey(%v) err = %v, want non-nil", keySerialization, err)
	}
	if got, want := parsedPublicKey, wantPublicKey; !got.Equal(want) {
		t.Errorf("got.Equal(want) = false, want true")
	}
}

func TestParseAndSerializePublicKey(t *testing.T) {
	publicKey2048 := rsassapkcs1pb.RsaSsaPkcs1PublicKey{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: commonpb.HashType_SHA256,
		},
		N:       mustDecodeBase64(t, n2048Base64),
		E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
		Version: publicKeyProtoVersion,
	}
	serialized2048ProtoPublicKey := mustMarshalProto(t, &publicKey2048)
	proto3072SHA384PublicKey := rsassapkcs1pb.RsaSsaPkcs1PublicKey{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: commonpb.HashType_SHA384,
		},
		N:       mustDecodeBase64(t, n3072Base64),
		E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
		Version: publicKeyProtoVersion,
	}
	serialized3072SHA384ProtoPublicKey := mustMarshalProto(t, &proto3072SHA384PublicKey)
	proto3072SHA512PublicKey := rsassapkcs1pb.RsaSsaPkcs1PublicKey{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: commonpb.HashType_SHA512,
		},
		N:       mustDecodeBase64(t, n3072Base64),
		E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
		Version: publicKeyProtoVersion,
	}
	serialized3072SHA512ProtoPublicKey := mustMarshalProto(t, &proto3072SHA512PublicKey)
	proto4096PublicKey := rsassapkcs1pb.RsaSsaPkcs1PublicKey{
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: commonpb.HashType_SHA512,
		},
		N:       mustDecodeBase64(t, n4096Base64),
		E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
		Version: publicKeyProtoVersion,
	}
	serialized4096ProtoPublicKey := mustMarshalProto(t, &proto4096PublicKey)

	for _, tc := range []struct {
		name                   string
		publicKeySerialization *protoserialization.KeySerialization
		publicKey              *PublicKey
	}{
		{
			name: "2048-SHA256-TINK",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized2048ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n2048Base64), 123, mustCreateParameters(t, 2048, SHA256, f4, VariantTink)),
		},
		{
			name: "2048-SHA256-LEGACY",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized2048ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_LEGACY, 123),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n2048Base64), 123, mustCreateParameters(t, 2048, SHA256, f4, VariantLegacy)),
		},
		{
			name: "2048-SHA256-CRUNCHY",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized2048ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 123),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n2048Base64), 123, mustCreateParameters(t, 2048, SHA256, f4, VariantCrunchy)),
		},
		{
			name: "2048-SHA256-RAW",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized2048ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n2048Base64), 0, mustCreateParameters(t, 2048, SHA256, f4, VariantNoPrefix)),
		},
		{
			name: "3072-SHA384-TINK",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA384ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n3072Base64), 123, mustCreateParameters(t, 3072, SHA384, f4, VariantTink)),
		},
		{
			name: "3072-SHA384-LEGACY",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA384ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_LEGACY, 123),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n3072Base64), 123, mustCreateParameters(t, 3072, SHA384, f4, VariantLegacy)),
		},
		{
			name: "3072-SHA384-CRUNCHY",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA384ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 123),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n3072Base64), 123, mustCreateParameters(t, 3072, SHA384, f4, VariantCrunchy)),
		},
		{
			name: "3072-SHA384-RAW",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA384ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n3072Base64), 0, mustCreateParameters(t, 3072, SHA384, f4, VariantNoPrefix)),
		},
		{
			name: "3072-SHA512-TINK",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA512ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n3072Base64), 123, mustCreateParameters(t, 3072, SHA512, f4, VariantTink)),
		},
		{
			name: "3072-SHA512-LEGACY",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA512ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_LEGACY, 123),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n3072Base64), 123, mustCreateParameters(t, 3072, SHA512, f4, VariantLegacy)),
		},
		{
			name: "3072-SHA512-CRUNCHY",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA512ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 123),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n3072Base64), 123, mustCreateParameters(t, 3072, SHA512, f4, VariantCrunchy)),
		},
		{
			name: "3072-SHA512-RAW",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized3072SHA512ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n3072Base64), 0, mustCreateParameters(t, 3072, SHA512, f4, VariantNoPrefix)),
		},
		{
			name: "4096-SHA512-TINK",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized4096ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 123),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n4096Base64), 123, mustCreateParameters(t, 4096, SHA512, f4, VariantTink)),
		},
		{
			name: "4096-SHA512-LEGACY",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized4096ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_LEGACY, 123),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n4096Base64), 123, mustCreateParameters(t, 4096, SHA512, f4, VariantLegacy)),
		},
		{
			name: "4096-SHA512-CRUNCHY",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized4096ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 123),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n4096Base64), 123, mustCreateParameters(t, 4096, SHA512, f4, VariantCrunchy)),
		},
		{
			name: "4096-SHA512-RAW",
			publicKeySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serialized4096ProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, n4096Base64), 0, mustCreateParameters(t, 4096, SHA512, f4, VariantNoPrefix)),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &publicKeyParser{}
			gotKey, err := p.ParseKey(tc.publicKeySerialization)
			if err != nil {
				t.Fatalf("p.ParseKey(%v) err = %v, want non-nil", tc.publicKeySerialization, err)
			}
			if !gotKey.Equal(tc.publicKey) {
				t.Errorf("%v.Equal(%v) = false, want true", gotKey, tc.publicKey)
			}

			// Make sure we can serialize back the key serialization.
			s := &publicKeySerializer{}
			gotSerialization, err := s.SerializeKey(gotKey)
			if err != nil {
				t.Errorf("s.SerializeKey(%v) err = %v, want nil", tc.publicKeySerialization, err)
			}
			if !gotSerialization.Equal(tc.publicKeySerialization) {
				t.Errorf("gotSerialization.Equal(tc.publicKeySerialization) = false, want true")
			}
		})
	}
}

type testParams struct{}

func (p *testParams) HasIDRequirement() bool { return true }

func (p *testParams) Equal(params key.Parameters) bool { return true }

type testKey struct{}

func (k *testKey) Parameters() key.Parameters { return &testParams{} }

func (k *testKey) Equal(other key.Key) bool { return true }

func (k *testKey) IDRequirement() (uint32, bool) { return 123, true }

func TestSerializePublicKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name      string
		publicKey key.Key
	}{
		{
			name:      "nil public key",
			publicKey: nil,
		},
		{
			name:      "invalid public key",
			publicKey: &PublicKey{},
		},
		{
			name:      "incorrect key type",
			publicKey: &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &publicKeySerializer{}
			if _, err := s.SerializeKey(tc.publicKey); err == nil {
				t.Errorf("s.SerializeKey(%v) err = nil, want non-nil", tc.publicKey)
			}
		})
	}
}

func mustMarshalProto(t *testing.T, message proto.Message) []byte {
	t.Helper()
	serializedPrivateKey, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", message, err)
	}
	return serializedPrivateKey
}

func TestParsePrivateKeyFails(t *testing.T) {
	privateKey := &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
		D:   mustDecodeBase64(t, d2048Base64),
		P:   mustDecodeBase64(t, p2048Base64),
		Q:   mustDecodeBase64(t, q2048Base64),
		Dp:  mustDecodeBase64(t, dp2048Base64),
		Dq:  mustDecodeBase64(t, dq2048Base64),
		Crt: mustDecodeBase64(t, qInv2048Base64),
		PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
			Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
				HashType: commonpb.HashType_SHA256,
			},
			N:       mustDecodeBase64(t, n2048Base64),
			E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
			Version: publicKeyProtoVersion,
		},
		Version: privateKeyProtoVersion,
	}
	serializedPrivateKey := mustMarshalProto(t, privateKey)

	publicKeyWithWrongPrivateKeyVersion := proto.Clone(privateKey).(*rsassapkcs1pb.RsaSsaPkcs1PrivateKey)
	publicKeyWithWrongPrivateKeyVersion.Version = privateKeyProtoVersion + 1
	serializedPrivateKeyWithWrongPrivateKeyVersion := mustMarshalProto(t, publicKeyWithWrongPrivateKeyVersion)

	privateKeyWithWrongPublicKeyVersion := proto.Clone(privateKey).(*rsassapkcs1pb.RsaSsaPkcs1PrivateKey)
	privateKeyWithWrongPublicKeyVersion.PublicKey.Version = publicKeyProtoVersion + 1
	serializedPrivateKeyWithWrongPublicKeyVersion := mustMarshalProto(t, privateKeyWithWrongPublicKeyVersion)

	privateKeyWithWrongPublicKey := &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
		D:   mustDecodeBase64(t, d2048Base64),
		P:   mustDecodeBase64(t, p2048Base64),
		Q:   mustDecodeBase64(t, q2048Base64),
		Dp:  mustDecodeBase64(t, dp2048Base64),
		Dq:  mustDecodeBase64(t, dq2048Base64),
		Crt: mustDecodeBase64(t, qInv2048Base64),
		PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
			Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
				HashType: commonpb.HashType_SHA256,
			},
			N:       make([]byte, 256), // All bytes are 0.
			E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
			Version: publicKeyProtoVersion,
		},
		Version: privateKeyProtoVersion,
	}
	serializedPrivateKeyWithWrongPublicKeyBytes := mustMarshalProto(t, privateKeyWithWrongPublicKey)

	// From https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_2048_test.json#L348.
	invalidDp := "PGEOZW9DtcYO0D3S4T0NwSICkvg7_RWlbW_-O5GZjbLgiqkelWeRFcdcP7_St5VDouNKsCS7F0lRRlQyZ91tpCF3TBuOj9tCmHfme3xbZYCnRUplwniDErBQOLCRzW2EanRrsTk5wfjNTCa24C-ONAoum42GFTnaZQbHXLy90VE"
	invalidDq := "qy_pDD2wmbqstiLK09V9Gb_BAWbZRIilYHIbBr8PtZmiaIJc9bZcdaaCCW1cYg4OevITF7nfyDAlE--acEqfDvzC-kd775MeNh2w5VzQ6SOZiKneGD7Ko98jFaUyF7mG-6RDS6Cs9DfmJGZ4rtsrt2ivYjQ-pujTPux9TYSOeAE"
	invalidQInv := "U4LZcUWgEjw4Pt5rXe0hfOUKN1HQkmFIqniV9QFWPRMavML_IiFQs-NeNT_bAGIy8fUh4pQe7FGBCl2yLBr0E78ySRjN-eAMkW7Hkctqw_vLBPomOW8FQEcKvZKZgxcvSEsQLiH0TIqwhn7JCnfX9Gpv_hBGuNTn4mF8A1v-FIo"

	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name:             "key data is nil",
			keySerialization: mustCreateKeySerialization(t, nil, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong type URL",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "invalid_type_url",
				Value:           serializedPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_UNKNOWN_PREFIX, 12345),
		},
		{
			name: "wrong private key material type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong private key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKeyWithWrongPrivateKeyVersion,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong public key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKeyWithWrongPublicKeyVersion,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong public key bytes",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKeyWithWrongPublicKeyBytes,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid Dp",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value: mustMarshalProto(t, &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
					D:   mustDecodeBase64(t, d2048Base64),
					P:   mustDecodeBase64(t, p2048Base64),
					Q:   mustDecodeBase64(t, q2048Base64),
					Dp:  mustDecodeBase64(t, invalidDp),
					Dq:  mustDecodeBase64(t, dq2048Base64),
					Crt: mustDecodeBase64(t, qInv2048Base64),
					PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
						Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
							HashType: commonpb.HashType_SHA256,
						},
						N:       mustDecodeBase64(t, n2048Base64),
						E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
						Version: publicKeyProtoVersion,
					},
					Version: privateKeyProtoVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid Dq",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value: mustMarshalProto(t, &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
					D:   mustDecodeBase64(t, d2048Base64),
					P:   mustDecodeBase64(t, p2048Base64),
					Q:   mustDecodeBase64(t, q2048Base64),
					Dp:  mustDecodeBase64(t, dp2048Base64),
					Dq:  mustDecodeBase64(t, invalidDq),
					Crt: mustDecodeBase64(t, qInv2048Base64),
					PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
						Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
							HashType: commonpb.HashType_SHA256,
						},
						N:       mustDecodeBase64(t, n2048Base64),
						E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
						Version: publicKeyProtoVersion,
					},
					Version: privateKeyProtoVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "invalid QInv",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl: "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value: mustMarshalProto(t, &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
					D:   mustDecodeBase64(t, d2048Base64),
					P:   mustDecodeBase64(t, p2048Base64),
					Q:   mustDecodeBase64(t, q2048Base64),
					Dp:  mustDecodeBase64(t, dp2048Base64),
					Dq:  mustDecodeBase64(t, dq2048Base64),
					Crt: mustDecodeBase64(t, invalidQInv),
					PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
						Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
							HashType: commonpb.HashType_SHA256,
						},
						N:       mustDecodeBase64(t, n2048Base64),
						E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
						Version: publicKeyProtoVersion,
					},
					Version: privateKeyProtoVersion,
				}),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &privateKeyParser{}
			if _, err := p.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want non-nil", tc.keySerialization)
			}
		})
	}
}

func mustCreatePrivateKey(t *testing.T, publicKey *PublicKey, privateKeyValues PrivateKeyValues) *PrivateKey {
	t.Helper()
	privateKey, err := NewPrivateKey(publicKey, privateKeyValues)
	if err != nil {
		t.Fatalf("NewPrivateKey(%v, %v) err = %v, want nil", publicKey, privateKeyValues, err)
	}
	return privateKey
}

func TestParsePrivateKeyWithZeroPaddingValues(t *testing.T) {
	n := mustDecodeBase64(t, n2048Base64)
	p := mustDecodeBase64(t, p2048Base64)
	q := mustDecodeBase64(t, q2048Base64)
	d := mustDecodeBase64(t, d2048Base64)
	privateKey := &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
		D:   slices.Concat([]byte{0, 0, 0, 0}, d),
		P:   slices.Concat([]byte{0, 0, 0, 0}, p),
		Q:   slices.Concat([]byte{0, 0, 0, 0}, q),
		Dp:  slices.Concat([]byte{0, 0, 0, 0}, mustDecodeBase64(t, dp2048Base64)),
		Dq:  slices.Concat([]byte{0, 0, 0, 0}, mustDecodeBase64(t, dq2048Base64)),
		Crt: slices.Concat([]byte{0, 0, 0, 0}, mustDecodeBase64(t, qInv2048Base64)),
		PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
			Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
				HashType: commonpb.HashType_SHA256,
			},
			// Pad with zeros.
			N:       slices.Concat([]byte{0, 0, 0, 0}, mustDecodeBase64(t, n2048Base64)),
			E:       slices.Concat([]byte{0, 0, 0, 0}, new(big.Int).SetUint64(uint64(f4)).Bytes()),
			Version: publicKeyProtoVersion,
		},
		Version: privateKeyProtoVersion,
	}
	serializedPrivateKey := mustMarshalProto(t, privateKey)
	token := insecuresecretdataaccess.Token{}
	keySerialization := mustCreateKeySerialization(t, &tinkpb.KeyData{
		TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
		Value:           serializedPrivateKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, tinkpb.OutputPrefixType_TINK, 12345)
	wantPrivateKey := mustCreatePrivateKey(t, mustCreatePublicKey(t, n, 12345, mustCreateParameters(t, 2048, SHA256, f4, VariantTink)), PrivateKeyValues{
		P: secretdata.NewBytesFromData(p, token),
		Q: secretdata.NewBytesFromData(q, token),
		D: secretdata.NewBytesFromData(d, token),
	})
	parser := &privateKeyParser{}
	parsedPrivateKey, err := parser.ParseKey(keySerialization)
	if err != nil {
		t.Fatalf("parser.ParseKey(%v) err = %v, want non-nil", keySerialization, err)
	}
	if got, want := parsedPrivateKey, wantPrivateKey; !got.Equal(want) {
		t.Errorf("got.Equal(want) = false, want true")
	}
}

func TestParseAndSerializePrivateKey(t *testing.T) {
	privateKey2048 := &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
		D:   mustDecodeBase64(t, d2048Base64),
		P:   mustDecodeBase64(t, p2048Base64),
		Q:   mustDecodeBase64(t, q2048Base64),
		Dp:  mustDecodeBase64(t, dp2048Base64),
		Dq:  mustDecodeBase64(t, dq2048Base64),
		Crt: mustDecodeBase64(t, qInv2048Base64),
		PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
			Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
				HashType: commonpb.HashType_SHA256,
			},
			N:       mustDecodeBase64(t, n2048Base64),
			E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
			Version: publicKeyProtoVersion,
		},
		Version: privateKeyProtoVersion,
	}
	serializedPrivateKey2048 := mustMarshalProto(t, privateKey2048)

	privateKey3072 := &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
		D:   mustDecodeBase64(t, d3072Base64),
		P:   mustDecodeBase64(t, p3072Base64),
		Q:   mustDecodeBase64(t, q3072Base64),
		Dp:  mustDecodeBase64(t, dp3072Base64),
		Dq:  mustDecodeBase64(t, dq3072Base64),
		Crt: mustDecodeBase64(t, qInv3072Base64),
		PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
			Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
				HashType: commonpb.HashType_SHA256,
			},
			N:       mustDecodeBase64(t, n3072Base64),
			E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
			Version: publicKeyProtoVersion,
		},
		Version: privateKeyProtoVersion,
	}
	serializedPrivateKey3072 := mustMarshalProto(t, privateKey3072)

	privateKey4096 := &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
		D:   mustDecodeBase64(t, d4096Base64),
		P:   mustDecodeBase64(t, p4096Base64),
		Q:   mustDecodeBase64(t, q4096Base64),
		Dp:  mustDecodeBase64(t, dp4096Base64),
		Dq:  mustDecodeBase64(t, dq4096Base64),
		Crt: mustDecodeBase64(t, qInv4096Base64),
		PublicKey: &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
			Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
				HashType: commonpb.HashType_SHA256,
			},
			N:       mustDecodeBase64(t, n4096Base64),
			E:       new(big.Int).SetUint64(uint64(f4)).Bytes(),
			Version: publicKeyProtoVersion,
		},
		Version: privateKeyProtoVersion,
	}
	serializedPrivateKey4096 := mustMarshalProto(t, privateKey4096)

	token := insecuresecretdataaccess.Token{}
	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
		privateKey       *PrivateKey
	}{
		{
			name: "2048-SHA256-TINK",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKey2048,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
			privateKey: mustCreatePrivateKey(t, mustCreatePublicKey(t, mustDecodeBase64(t, n2048Base64), 12345, mustCreateParameters(t, 2048, SHA256, f4, VariantTink)), PrivateKeyValues{
				P: secretdata.NewBytesFromData(mustDecodeBase64(t, p2048Base64), token),
				Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q2048Base64), token),
				D: secretdata.NewBytesFromData(mustDecodeBase64(t, d2048Base64), token),
			}),
		},
		{
			name: "2048-SHA256-LEGACY",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKey2048,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_LEGACY, 12345),
			privateKey: mustCreatePrivateKey(t, mustCreatePublicKey(t, mustDecodeBase64(t, n2048Base64), 12345, mustCreateParameters(t, 2048, SHA256, f4, VariantLegacy)), PrivateKeyValues{
				P: secretdata.NewBytesFromData(mustDecodeBase64(t, p2048Base64), token),
				Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q2048Base64), token),
				D: secretdata.NewBytesFromData(mustDecodeBase64(t, d2048Base64), token),
			}),
		},
		{
			name: "2048-SHA256-CRUNCHY",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKey2048,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_CRUNCHY, 12345),
			privateKey: mustCreatePrivateKey(t, mustCreatePublicKey(t, mustDecodeBase64(t, n2048Base64), 12345, mustCreateParameters(t, 2048, SHA256, f4, VariantCrunchy)), PrivateKeyValues{
				P: secretdata.NewBytesFromData(mustDecodeBase64(t, p2048Base64), token),
				Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q2048Base64), token),
				D: secretdata.NewBytesFromData(mustDecodeBase64(t, d2048Base64), token),
			}),
		},
		{
			name: "2048-SHA256-RAW",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKey2048,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_RAW, 0),
			privateKey: mustCreatePrivateKey(t, mustCreatePublicKey(t, mustDecodeBase64(t, n2048Base64), 0, mustCreateParameters(t, 2048, SHA256, f4, VariantNoPrefix)), PrivateKeyValues{
				P: secretdata.NewBytesFromData(mustDecodeBase64(t, p2048Base64), token),
				Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q2048Base64), token),
				D: secretdata.NewBytesFromData(mustDecodeBase64(t, d2048Base64), token),
			}),
		},
		{
			name: "3072-SHA256-TINK",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKey3072,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
			privateKey: mustCreatePrivateKey(t, mustCreatePublicKey(t, mustDecodeBase64(t, n3072Base64), 12345, mustCreateParameters(t, 3072, SHA256, f4, VariantTink)), PrivateKeyValues{
				P: secretdata.NewBytesFromData(mustDecodeBase64(t, p3072Base64), token),
				Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q3072Base64), token),
				D: secretdata.NewBytesFromData(mustDecodeBase64(t, d3072Base64), token),
			}),
		},
		{
			name: "3072-SHA256-LEGACY",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKey3072,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_LEGACY, 12345),
			privateKey: mustCreatePrivateKey(t, mustCreatePublicKey(t, mustDecodeBase64(t, n3072Base64), 12345, mustCreateParameters(t, 3072, SHA256, f4, VariantLegacy)), PrivateKeyValues{
				P: secretdata.NewBytesFromData(mustDecodeBase64(t, p3072Base64), token),
				Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q3072Base64), token),
				D: secretdata.NewBytesFromData(mustDecodeBase64(t, d3072Base64), token),
			}),
		},
		{
			name: "3072-SHA256-CRUNCHY",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKey3072,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_CRUNCHY, 12345),
			privateKey: mustCreatePrivateKey(t, mustCreatePublicKey(t, mustDecodeBase64(t, n3072Base64), 12345, mustCreateParameters(t, 3072, SHA256, f4, VariantCrunchy)), PrivateKeyValues{
				P: secretdata.NewBytesFromData(mustDecodeBase64(t, p3072Base64), token),
				Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q3072Base64), token),
				D: secretdata.NewBytesFromData(mustDecodeBase64(t, d3072Base64), token),
			}),
		},
		{
			name: "3072-SHA256-RAW",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKey3072,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_RAW, 0),
			privateKey: mustCreatePrivateKey(t, mustCreatePublicKey(t, mustDecodeBase64(t, n3072Base64), 0, mustCreateParameters(t, 3072, SHA256, f4, VariantNoPrefix)), PrivateKeyValues{
				P: secretdata.NewBytesFromData(mustDecodeBase64(t, p3072Base64), token),
				Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q3072Base64), token),
				D: secretdata.NewBytesFromData(mustDecodeBase64(t, d3072Base64), token),
			}),
		},
		{
			name: "4096-SHA256-TINK",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKey4096,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
			privateKey: mustCreatePrivateKey(t, mustCreatePublicKey(t, mustDecodeBase64(t, n4096Base64), 12345, mustCreateParameters(t, 4096, SHA256, f4, VariantTink)), PrivateKeyValues{
				P: secretdata.NewBytesFromData(mustDecodeBase64(t, p4096Base64), token),
				Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q4096Base64), token),
				D: secretdata.NewBytesFromData(mustDecodeBase64(t, d4096Base64), token),
			}),
		},
		{
			name: "4096-SHA256-LEGACY",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKey4096,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_LEGACY, 12345),
			privateKey: mustCreatePrivateKey(t, mustCreatePublicKey(t, mustDecodeBase64(t, n4096Base64), 12345, mustCreateParameters(t, 4096, SHA256, f4, VariantLegacy)), PrivateKeyValues{
				P: secretdata.NewBytesFromData(mustDecodeBase64(t, p4096Base64), token),
				Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q4096Base64), token),
				D: secretdata.NewBytesFromData(mustDecodeBase64(t, d4096Base64), token),
			}),
		},
		{
			name: "4096-SHA256-CRUNCHY",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKey4096,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_CRUNCHY, 12345),
			privateKey: mustCreatePrivateKey(t, mustCreatePublicKey(t, mustDecodeBase64(t, n4096Base64), 12345, mustCreateParameters(t, 4096, SHA256, f4, VariantCrunchy)), PrivateKeyValues{
				P: secretdata.NewBytesFromData(mustDecodeBase64(t, p4096Base64), token),
				Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q4096Base64), token),
				D: secretdata.NewBytesFromData(mustDecodeBase64(t, d4096Base64), token),
			}),
		},
		{
			name: "4096-SHA256-RAW",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				Value:           serializedPrivateKey4096,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_RAW, 0),
			privateKey: mustCreatePrivateKey(t, mustCreatePublicKey(t, mustDecodeBase64(t, n4096Base64), 0, mustCreateParameters(t, 4096, SHA256, f4, VariantNoPrefix)), PrivateKeyValues{
				P: secretdata.NewBytesFromData(mustDecodeBase64(t, p4096Base64), token),
				Q: secretdata.NewBytesFromData(mustDecodeBase64(t, q4096Base64), token),
				D: secretdata.NewBytesFromData(mustDecodeBase64(t, d4096Base64), token),
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &privateKeyParser{}
			gotKey, err := p.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("p.ParseKey(%v) err = %v, want non-nil", tc.keySerialization, err)
			}
			if !gotKey.Equal(tc.privateKey) {
				t.Errorf("%v.Equal(%v) = false, want true", gotKey, tc.privateKey)
			}

			s := &privateKeySerializer{}
			gotKeySerialization, err := s.SerializeKey(gotKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(%v) err = %v, want nil", gotKey, err)
			}
			if !gotKeySerialization.Equal(tc.keySerialization) {
				t.Errorf("gotKeySerialization.Equal(tc.keySerialization) = false, want true")
			}
		})
	}
}

func TestSerializePrivateKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name       string
		privateKey key.Key
	}{
		{
			name:       "nil private key",
			privateKey: nil,
		},
		{
			name:       "invlid private key",
			privateKey: &PrivateKey{},
		},
		{
			name:       "incorrect key type",
			privateKey: &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &privateKeySerializer{}
			if _, err := s.SerializeKey(tc.privateKey); err == nil {
				t.Errorf("s.SerializeKey(%v) err = nil, want non-nil", tc.privateKey)
			}
		})
	}
}

func TestSerializeParametersFailsWithWrongParameters(t *testing.T) {
	for _, tc := range []struct {
		name       string
		parameters key.Parameters
	}{
		{
			name:       "struct literal",
			parameters: &Parameters{},
		},
		{
			name:       "nil",
			parameters: nil,
		},
		{
			name:       "wrong type",
			parameters: &testParams{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializer := &parametersSerializer{}
			if _, err := serializer.Serialize(tc.parameters); err == nil {
				t.Errorf("serializer.Serialize(%v) err = nil, want error", tc.parameters)
			}
		})
	}
}

func mustCreateKeyTemplate(t *testing.T, outputPrefixType tinkpb.OutputPrefixType, format *rsassapkcs1pb.RsaSsaPkcs1KeyFormat) *tinkpb.KeyTemplate {
	t.Helper()
	serializedFormat := mustMarshalProto(t, format)
	return &tinkpb.KeyTemplate{
		TypeUrl:          "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
		OutputPrefixType: outputPrefixType,
		Value:            serializedFormat,
	}
}

type parametersParserTest struct {
	name        string
	parameters  key.Parameters
	keyTemplate *tinkpb.KeyTemplate
}

func mustCreateParametersParserTests(t *testing.T) []parametersParserTest {
	t.Helper()
	return []parametersParserTest{
		{
			name: "2048-SHA256-VariantTink",
			parameters: &Parameters{
				hashType:        SHA256,
				variant:         VariantTink,
				modulusSizeBits: 2048,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA256,
				},
				ModulusSizeInBits: 2048,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "2048-SHA256-VariantCrunchy",
			parameters: &Parameters{
				hashType:        SHA256,
				variant:         VariantCrunchy,
				modulusSizeBits: 2048,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA256,
				},
				ModulusSizeInBits: 2048,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "2048-SHA256-VariantLegacy",
			parameters: &Parameters{
				hashType:        SHA256,
				variant:         VariantLegacy,
				modulusSizeBits: 2048,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA256,
				},
				ModulusSizeInBits: 2048,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "2048-SHA256-VariantNoPrefix",
			parameters: &Parameters{
				hashType:        SHA256,
				variant:         VariantNoPrefix,
				modulusSizeBits: 2048,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA256,
				},
				ModulusSizeInBits: 2048,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "2048-SHA384-VariantTink",
			parameters: &Parameters{
				hashType:        SHA384,
				variant:         VariantTink,
				modulusSizeBits: 2048,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA384,
				},
				ModulusSizeInBits: 2048,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "2048-SHA384-VariantCrunchy",
			parameters: &Parameters{
				hashType:        SHA384,
				variant:         VariantCrunchy,
				modulusSizeBits: 2048,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA384,
				},
				ModulusSizeInBits: 2048,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "2048-SHA384-VariantLegacy",
			parameters: &Parameters{
				hashType:        SHA384,
				variant:         VariantLegacy,
				modulusSizeBits: 2048,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA384,
				},
				ModulusSizeInBits: 2048,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "2048-SHA384-VariantNoPrefix",
			parameters: &Parameters{
				hashType:        SHA384,
				variant:         VariantNoPrefix,
				modulusSizeBits: 2048,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA384,
				},
				ModulusSizeInBits: 2048,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "2048-SHA512-VariantTink",
			parameters: &Parameters{
				hashType:        SHA512,
				variant:         VariantTink,
				modulusSizeBits: 2048,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA512,
				},
				ModulusSizeInBits: 2048,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "2048-SHA512-VariantCrunchy",
			parameters: &Parameters{
				hashType:        SHA512,
				variant:         VariantCrunchy,
				modulusSizeBits: 2048,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA512,
				},
				ModulusSizeInBits: 2048,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "2048-SHA512-VariantLegacy",
			parameters: &Parameters{
				hashType:        SHA512,
				variant:         VariantLegacy,
				modulusSizeBits: 2048,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA512,
				},
				ModulusSizeInBits: 2048,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "2048-SHA512-VariantNoPrefix",
			parameters: &Parameters{
				hashType:        SHA512,
				variant:         VariantNoPrefix,
				modulusSizeBits: 2048,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA512,
				},
				ModulusSizeInBits: 2048,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "3072-SHA256-VariantTink",
			parameters: &Parameters{
				hashType:        SHA256,
				variant:         VariantTink,
				modulusSizeBits: 3072,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA256,
				},
				ModulusSizeInBits: 3072,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "3072-SHA256-VariantCrunchy",
			parameters: &Parameters{
				hashType:        SHA256,
				variant:         VariantCrunchy,
				modulusSizeBits: 3072,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA256,
				},
				ModulusSizeInBits: 3072,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "3072-SHA256-VariantLegacy",
			parameters: &Parameters{
				hashType:        SHA256,
				variant:         VariantLegacy,
				modulusSizeBits: 3072,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA256,
				},
				ModulusSizeInBits: 3072,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "3072-SHA256-VariantNoPrefix",
			parameters: &Parameters{
				hashType:        SHA256,
				variant:         VariantNoPrefix,
				modulusSizeBits: 3072,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA256,
				},
				ModulusSizeInBits: 3072,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "3072-SHA384-VariantTink",
			parameters: &Parameters{
				hashType:        SHA384,
				variant:         VariantTink,
				modulusSizeBits: 3072,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA384,
				},
				ModulusSizeInBits: 3072,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "3072-SHA384-VariantCrunchy",
			parameters: &Parameters{
				hashType:        SHA384,
				variant:         VariantCrunchy,
				modulusSizeBits: 3072,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA384,
				},
				ModulusSizeInBits: 3072,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "3072-SHA384-VariantLegacy",
			parameters: &Parameters{
				hashType:        SHA384,
				variant:         VariantLegacy,
				modulusSizeBits: 3072,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA384,
				},
				ModulusSizeInBits: 3072,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "3072-SHA384-VariantNoPrefix",
			parameters: &Parameters{
				hashType:        SHA384,
				variant:         VariantNoPrefix,
				modulusSizeBits: 3072,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA384,
				},
				ModulusSizeInBits: 3072,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "3072-SHA512-VariantTink",
			parameters: &Parameters{
				hashType:        SHA512,
				variant:         VariantTink,
				modulusSizeBits: 3072,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA512,
				},
				ModulusSizeInBits: 3072,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "3072-SHA512-VariantCrunchy",
			parameters: &Parameters{
				hashType:        SHA512,
				variant:         VariantCrunchy,
				modulusSizeBits: 3072,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA512,
				},
				ModulusSizeInBits: 3072,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "3072-SHA512-VariantLegacy",
			parameters: &Parameters{
				hashType:        SHA512,
				variant:         VariantLegacy,
				modulusSizeBits: 3072,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA512,
				},
				ModulusSizeInBits: 3072,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "3072-SHA512-VariantNoPrefix",
			parameters: &Parameters{
				hashType:        SHA512,
				variant:         VariantNoPrefix,
				modulusSizeBits: 3072,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA512,
				},
				ModulusSizeInBits: 3072,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "4096-SHA256-VariantTink",
			parameters: &Parameters{
				hashType:        SHA256,
				variant:         VariantTink,
				modulusSizeBits: 4096,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA256,
				},
				ModulusSizeInBits: 4096,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "4096-SHA256-VariantCrunchy",
			parameters: &Parameters{
				hashType:        SHA256,
				variant:         VariantCrunchy,
				modulusSizeBits: 4096,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA256,
				},
				ModulusSizeInBits: 4096,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "4096-SHA256-VariantLegacy",
			parameters: &Parameters{
				hashType:        SHA256,
				variant:         VariantLegacy,
				modulusSizeBits: 4096,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA256,
				},
				ModulusSizeInBits: 4096,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "4096-SHA256-VariantNoPrefix",
			parameters: &Parameters{
				hashType:        SHA256,
				variant:         VariantNoPrefix,
				modulusSizeBits: 4096,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA256,
				},
				ModulusSizeInBits: 4096,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "4096-SHA384-VariantTink",
			parameters: &Parameters{
				hashType:        SHA384,
				variant:         VariantTink,
				modulusSizeBits: 4096,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA384,
				},
				ModulusSizeInBits: 4096,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "4096-SHA384-VariantCrunchy",
			parameters: &Parameters{
				hashType:        SHA384,
				variant:         VariantCrunchy,
				modulusSizeBits: 4096,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA384,
				},
				ModulusSizeInBits: 4096,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "4096-SHA384-VariantLegacy",
			parameters: &Parameters{
				hashType:        SHA384,
				variant:         VariantLegacy,
				modulusSizeBits: 4096,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA384,
				},
				ModulusSizeInBits: 4096,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "4096-SHA384-VariantNoPrefix",
			parameters: &Parameters{
				hashType:        SHA384,
				variant:         VariantNoPrefix,
				modulusSizeBits: 4096,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA384,
				},
				ModulusSizeInBits: 4096,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "4096-SHA512-VariantTink",
			parameters: &Parameters{
				hashType:        SHA512,
				variant:         VariantTink,
				modulusSizeBits: 4096,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_TINK, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA512,
				},
				ModulusSizeInBits: 4096,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "4096-SHA512-VariantCrunchy",
			parameters: &Parameters{
				hashType:        SHA512,
				variant:         VariantCrunchy,
				modulusSizeBits: 4096,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_CRUNCHY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA512,
				},
				ModulusSizeInBits: 4096,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "4096-SHA512-VariantLegacy",
			parameters: &Parameters{
				hashType:        SHA512,
				variant:         VariantLegacy,
				modulusSizeBits: 4096,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_LEGACY, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA512,
				},
				ModulusSizeInBits: 4096,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
		{
			name: "4096-SHA512-VariantNoPrefix",
			parameters: &Parameters{
				hashType:        SHA512,
				variant:         VariantNoPrefix,
				modulusSizeBits: 4096,
				publicExponent:  f4,
			},
			keyTemplate: mustCreateKeyTemplate(t, tinkpb.OutputPrefixType_RAW, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
				Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
					HashType: commonpb.HashType_SHA512,
				},
				ModulusSizeInBits: 4096,
				PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
			}),
		},
	}
}

func TestSerializeParameters(t *testing.T) {
	for _, tc := range mustCreateParametersParserTests(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeParameters(tc.parameters)
			if err != nil {
				t.Fatalf("protoserialization.SerializeParameters(%v) err = %v, want nil", tc.parameters, err)
			}
			if diff := cmp.Diff(tc.keyTemplate, got, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeParameters(%v) returned unexpected diff (-want +got):\n%s", tc.parameters, diff)
			}
		})
	}
}

func TestParseParameters(t *testing.T) {
	for _, tc := range mustCreateParametersParserTests(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseParameters(tc.keyTemplate)
			if err != nil {
				t.Fatalf("protoserialization.ParseParameters(%v) err = %v, want nil", tc.keyTemplate, err)
			}
			if diff := cmp.Diff(tc.parameters, got); diff != "" {
				t.Errorf("protoserialization.ParseParameters(%v) returned unexpected diff (-want +got):\n%s", tc.keyTemplate, diff)
			}
		})
	}
}

func TestParseParametersFails(t *testing.T) {
	for _, tc := range []struct {
		name        string
		keyTemplate *tinkpb.KeyTemplate
	}{
		{
			name: "invalid output prefix type",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
				Value: mustMarshalProto(t, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
					Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
						HashType: commonpb.HashType_SHA256,
					},
					ModulusSizeInBits: 2048,
					PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
				}),
			},
		},
		{
			name: "invalid hash type",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshalProto(t, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
					Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
						HashType: commonpb.HashType_UNKNOWN_HASH,
					},
					ModulusSizeInBits: 2048,
					PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
				}),
			},
		},
		{
			name: "invalid modulus size",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshalProto(t, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
					Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
						HashType: commonpb.HashType_SHA256,
					},
					ModulusSizeInBits: 1024,
					PublicExponent:    new(big.Int).SetUint64(uint64(f4)).Bytes(),
				}),
			},
		},
		{
			name: "invalid public exponent",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshalProto(t, &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{
					Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
						HashType: commonpb.HashType_SHA256,
					},
					ModulusSizeInBits: 2048,
					PublicExponent:    new(big.Int).SetUint64(uint64(f4) - 1).Bytes(),
				}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseParameters(tc.keyTemplate); err == nil {
				t.Errorf("protoserialization.ParseParameters(%v) err = nil, want error", tc.keyTemplate)
			}
		})
	}
}

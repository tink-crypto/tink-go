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

package jwtrsassapkcs1_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/secretdata"
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

func mustBase64Decode(t *testing.T, in string) []byte {
	t.Helper()
	d, err := base64.RawURLEncoding.DecodeString(in)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString(%q) failed: %v", in, err)
	}
	return d
}

func mustCreateParametersFromOpts(t *testing.T, opts jwtrsassapkcs1.ParametersOpts) *jwtrsassapkcs1.Parameters {
	p, err := jwtrsassapkcs1.NewParameters(opts)
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewParameters(%v) failed: %v", opts, err)
	}
	return p
}

func mustStringToBigInt(t *testing.T, s string, base int) *big.Int {
	t.Helper()
	i, ok := new(big.Int).SetString(s, base)
	if !ok {
		t.Fatalf("failed to parse %v as a base %v big number", s, base)
	}
	return i
}

type publicKeyTestCase struct {
	name       string
	opts       jwtrsassapkcs1.PublicKeyOpts
	wantKID    string
	wantHasKID bool
}

func publicKeyTestCases(t *testing.T) []publicKeyTestCase {
	var tcs []publicKeyTestCase

	for _, algorithm := range []jwtrsassapkcs1.Algorithm{jwtrsassapkcs1.RS256, jwtrsassapkcs1.RS384, jwtrsassapkcs1.RS512} {
		for _, modulusAndSize := range []struct {
			modulus []byte
			size    int
		}{
			{mustBase64Decode(t, n2048Base64), 2048},
			{mustStringToBigInt(t, n2048BigInt16, 16).Bytes(), 2048},
			{mustBase64Decode(t, n3072Base64), 3072},
			{mustBase64Decode(t, n4096Base64), 4096},
		} {
			for _, exponent := range []int{f4} {
				for _, kidStrategyAndValues := range []struct {
					strategy      jwtrsassapkcs1.KIDStrategy
					idRequirement uint32
					customKID     string
					hasCustomKID  bool
					wantKID       string
					wantHasKID    bool
				}{
					{
						strategy:      jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
						idRequirement: 0x01020304,
						customKID:     "",
						hasCustomKID:  false,
						wantKID:       "AQIDBA",
						wantHasKID:    true,
					},
				} {
					tcs = append(tcs, publicKeyTestCase{
						name: fmt.Sprintf("%s_%d_%d_%s", algorithm, modulusAndSize.size, exponent, kidStrategyAndValues.strategy),
						opts: jwtrsassapkcs1.PublicKeyOpts{
							Modulus:       modulusAndSize.modulus,
							IDRequirement: kidStrategyAndValues.idRequirement,
							CustomKID:     kidStrategyAndValues.customKID,
							HasCustomKID:  kidStrategyAndValues.hasCustomKID,
							Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
								ModulusSizeInBits: modulusAndSize.size,
								PublicExponent:    exponent,
								Algorithm:         algorithm,
								KidStrategy:       kidStrategyAndValues.strategy,
							}),
						},
						wantKID:    kidStrategyAndValues.wantKID,
						wantHasKID: kidStrategyAndValues.wantHasKID,
					})
				}
			}
		}
	}

	return tcs
}

func TestPublicKey(t *testing.T) {
	for _, tc := range publicKeyTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			pk, err := jwtrsassapkcs1.NewPublicKey(tc.opts)
			if err != nil {
				t.Fatalf("NewPublicKey(%v) failed: %v", tc.opts, err)
			}
			kid, hasKID := pk.KID()
			if kid != tc.wantKID || hasKID != tc.wantHasKID {
				t.Errorf("pk.KID() = %q, %v, want %q, %v", kid, hasKID, tc.wantKID, tc.wantHasKID)
			}
			if !bytes.Equal(pk.Modulus(), tc.opts.Modulus) {
				t.Errorf("pk.Modulus() = %v, want %v", pk.Modulus(), tc.opts.Modulus)
			}

			params := pk.Parameters()
			if !params.Equal(tc.opts.Parameters) {
				t.Errorf("pk.Parameters() = %v, want %v", params, tc.opts.Parameters)
			}

			idRequirement, hasIDRequirement := pk.IDRequirement()
			if idRequirement != tc.opts.IDRequirement || hasIDRequirement != tc.opts.Parameters.HasIDRequirement() {
				t.Errorf("pk.IDRequirement() = %v, %v, want %v, %v", idRequirement, hasIDRequirement, tc.opts.IDRequirement, tc.opts.Parameters.HasIDRequirement())
			}

			pk2, err := jwtrsassapkcs1.NewPublicKey(tc.opts)
			if err != nil {
				t.Fatalf("NewPublicKey(%v) failed: %v", tc.opts, err)
			}
			if diff := cmp.Diff(pk, pk2); diff != "" {
				t.Errorf("NewPublicKey(%v) returned unexpected diff (-want +got):\n%s", tc.opts, diff)
			}
		})
	}
}

func TestPublicKeyEqual_Different(t *testing.T) {
	for _, tc := range []struct {
		name         string
		opts1, opts2 jwtrsassapkcs1.PublicKeyOpts
	}{
		{
			name: "DifferentModulus",
			opts1: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustBase64Decode(t, n2048Base64),
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 2048,
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS256,
					KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
				}),
				IDRequirement: 0x01020304,
			},
			opts2: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustBase64Decode(t, n3072Base64), // Different modulus
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 3072, // Different size
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS256,
					KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
				}),
				IDRequirement: 0x01020304,
			},
		},
		{
			name: "SameModulusSize_DifferentModulus",
			opts1: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustBase64Decode(t, n2048Base64),
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 2048,
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS256,
					KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
				}),
				IDRequirement: 0x01020304,
			},
			opts2: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustStringToBigInt(t, n2048BigInt16, 16).Bytes(), // Different modulus, same size
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 2048,
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS256,
					KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
				}),
				IDRequirement: 0x01020304,
			},
		},
		{
			name: "DifferentKIDStrategy",
			opts1: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustBase64Decode(t, n2048Base64),
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 2048,
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS256,
					KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
				}),
				IDRequirement: 0x01020304,
			},
			opts2: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustBase64Decode(t, n2048Base64),
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 2048,
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS256,
					KidStrategy:       jwtrsassapkcs1.CustomKID, // Different KID strategy
				}),
				CustomKID:    "some_kid",
				HasCustomKID: true,
			},
		},
		{
			name: "DifferentIDRequirement",
			opts1: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustBase64Decode(t, n2048Base64),
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 2048,
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS256,
					KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
				}),
				IDRequirement: 0x01020304,
			},
			opts2: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustBase64Decode(t, n2048Base64),
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 2048,
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS256,
					KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
				}),
				IDRequirement: 0x05060708, // Different ID requirement
			},
		},
		{
			name: "DifferentAlgorithm",
			opts1: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustBase64Decode(t, n2048Base64),
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 2048,
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS256,
					KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
				}),
				IDRequirement: 0x01020304,
			},
			opts2: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustBase64Decode(t, n2048Base64),
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 2048,
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS384, // Different algorithm
					KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
				}),
				IDRequirement: 0x01020304,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pk1, err := jwtrsassapkcs1.NewPublicKey(tc.opts1)
			if err != nil {
				t.Fatalf("NewPublicKey(%v) failed: %v", tc.opts1, err)
			}
			pk2, err := jwtrsassapkcs1.NewPublicKey(tc.opts2)
			if err != nil {
				t.Fatalf("NewPublicKey(%v) failed: %v", tc.opts2, err)
			}

			if cmp.Equal(pk1, pk2) {
				t.Errorf("cmp.Equal(%v, %v) = true, want false", pk1, pk2)
			}
		})
	}
}

func TestNewPublicKey_Errors(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts jwtrsassapkcs1.PublicKeyOpts
	}{
		{
			name: "NilParameters",
			opts: jwtrsassapkcs1.PublicKeyOpts{
				Modulus:       mustBase64Decode(t, n2048Base64),
				IDRequirement: 0x01020304,
				Parameters:    nil,
			},
		},
		{
			name: "IDRequirementNotRequiredButSet",
			opts: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustBase64Decode(t, n2048Base64),
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 2048,
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS256,
					KidStrategy:       jwtrsassapkcs1.CustomKID,
				}),
				IDRequirement: 0x01020304,
				CustomKID:     "some_kid",
				HasCustomKID:  true,
			},
		},
		{
			name: "InvalidModulusBitLength",
			opts: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustBase64Decode(t, n3072Base64),
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 2048,
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS256,
					KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
				}),
				IDRequirement: 0x01020304,
			},
		},
		{
			name: "Base64EncodedKeyIDAsKID_CustomKIDSet",
			opts: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustBase64Decode(t, n2048Base64),
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 2048,
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS256,
					KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
				}),
				IDRequirement: 0x01020304,
				CustomKID:     "some_kid",
				HasCustomKID:  true,
			},
		},
		{
			name: "IgnoredKID_CustomKIDSet",
			opts: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustBase64Decode(t, n2048Base64),
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 2048,
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS256,
					KidStrategy:       jwtrsassapkcs1.IgnoredKID,
				}),
				CustomKID:    "some_kid",
				HasCustomKID: true,
			},
		},
		{
			name: "CustomKID_CustomKIDNotSet",
			opts: jwtrsassapkcs1.PublicKeyOpts{
				Modulus: mustBase64Decode(t, n2048Base64),
				Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
					ModulusSizeInBits: 2048,
					PublicExponent:    f4,
					Algorithm:         jwtrsassapkcs1.RS256,
					KidStrategy:       jwtrsassapkcs1.CustomKID,
				}),
				HasCustomKID: false,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := jwtrsassapkcs1.NewPublicKey(tc.opts); err == nil {
				t.Errorf("NewPublicKey(%v) err = nil, want error", tc.opts)
			} else {
				t.Logf("NewPublicKey(%v) err = %v", tc.opts, err)
			}
		})
	}
}

type privateKeyTestCase struct {
	name string
	opts jwtrsassapkcs1.PrivateKeyOpts
	// Derived values.
	wantDP   secretdata.Bytes
	wantDQ   secretdata.Bytes
	wantQInv secretdata.Bytes
}

func privateKeyTestCases(t *testing.T) []privateKeyTestCase {
	var tcs []privateKeyTestCase

	type keyMaterial struct {
		n, d, p, q, dp, dq, qInv string
		size                     int
	}
	keyMaterials := []keyMaterial{
		{n2048Base64, d2048Base64, p2048Base64, q2048Base64, dp2048Base64, dq2048Base64, qInv2048Base64, 2048},
		{n3072Base64, d3072Base64, p3072Base64, q3072Base64, dp3072Base64, dq3072Base64, qInv3072Base64, 3072},
		{n4096Base64, d4096Base64, p4096Base64, q4096Base64, dp4096Base64, dq4096Base64, qInv4096Base64, 4096},
	}

	for _, algorithm := range []jwtrsassapkcs1.Algorithm{jwtrsassapkcs1.RS256, jwtrsassapkcs1.RS384, jwtrsassapkcs1.RS512} {
		for _, km := range keyMaterials {
			decodedD := mustBase64Decode(t, km.d)
			decodedP := mustBase64Decode(t, km.p)
			decodedQ := mustBase64Decode(t, km.q)
			decodedDP := mustBase64Decode(t, km.dp)
			decodedDQ := mustBase64Decode(t, km.dq)
			decodedQInv := mustBase64Decode(t, km.qInv)

			for _, kidStrategyAndValues := range []struct {
				strategy      jwtrsassapkcs1.KIDStrategy
				idRequirement uint32
				customKID     string
				hasCustomKID  bool
			}{
				{jwtrsassapkcs1.Base64EncodedKeyIDAsKID, 0x01020304, "", false},
				{jwtrsassapkcs1.IgnoredKID, 0, "", false},
				{jwtrsassapkcs1.CustomKID, 0, "test-kid", true},
			} {
				pkOpts := jwtrsassapkcs1.PublicKeyOpts{
					Modulus:       mustBase64Decode(t, km.n),
					IDRequirement: kidStrategyAndValues.idRequirement,
					CustomKID:     kidStrategyAndValues.customKID,
					HasCustomKID:  kidStrategyAndValues.hasCustomKID,
					Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: km.size,
						PublicExponent:    f4,
						Algorithm:         algorithm,
						KidStrategy:       kidStrategyAndValues.strategy,
					}),
				}
				pk := mustCreatePublicKey(t, pkOpts)

				tcs = append(tcs, privateKeyTestCase{
					name: fmt.Sprintf("%s_%d_%s", algorithm, km.size, kidStrategyAndValues.strategy),
					opts: jwtrsassapkcs1.PrivateKeyOpts{
						PublicKey: pk,
						D:         secretdata.NewBytesFromData(decodedD, insecuresecretdataaccess.Token{}),
						P:         secretdata.NewBytesFromData(decodedP, insecuresecretdataaccess.Token{}),
						Q:         secretdata.NewBytesFromData(decodedQ, insecuresecretdataaccess.Token{}),
					},
					wantDP:   secretdata.NewBytesFromData(decodedDP, insecuresecretdataaccess.Token{}),
					wantDQ:   secretdata.NewBytesFromData(decodedDQ, insecuresecretdataaccess.Token{}),
					wantQInv: secretdata.NewBytesFromData(decodedQInv, insecuresecretdataaccess.Token{}),
				})
			}
		}
	}
	return tcs
}

func TestPrivateKey(t *testing.T) {
	for _, tc := range privateKeyTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			privKey, err := jwtrsassapkcs1.NewPrivateKey(tc.opts)
			if err != nil {
				t.Fatalf("NewPrivateKey(%v) failed: %v", tc.opts, err)
			}

			// Test getters
			if !privKey.Parameters().Equal(tc.opts.PublicKey.Parameters()) {
				t.Errorf("privKey.Parameters() = %v, want %v", privKey.Parameters(), tc.opts.PublicKey.Parameters())
			}
			pubKey, err := privKey.PublicKey()
			if err != nil {
				t.Fatalf("privKey.PublicKey() failed: %v", err)
			}
			if !pubKey.Equal(tc.opts.PublicKey) {
				t.Errorf("privKey.PublicKey() = %v, want %v", pubKey, tc.opts.PublicKey)
			}
			idReq, hasIDReq := privKey.IDRequirement()
			wantIDReq, wantHasIDReq := tc.opts.PublicKey.IDRequirement()
			if idReq != wantIDReq || hasIDReq != wantHasIDReq {
				t.Errorf("privKey.IDRequirement() = %v, %v, want %v, %v", idReq, hasIDReq, wantIDReq, wantHasIDReq)
			}

			if diff := cmp.Diff(tc.opts.D, privKey.D()); diff != "" {
				t.Errorf("privKey.D() mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.opts.P, privKey.P()); diff != "" {
				t.Errorf("privKey.P() mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.opts.Q, privKey.Q()); diff != "" {
				t.Errorf("privKey.Q() mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantDP, privKey.DP()); diff != "" {
				t.Errorf("privKey.DP() mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantDQ, privKey.DQ()); diff != "" {
				t.Errorf("privKey.DQ() mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantQInv, privKey.QInv()); diff != "" {
				t.Errorf("privKey.QInv() mismatch (-want +got):\n%s", diff)
			}

			// Test equality with a newly created key from the same options
			privKey2, err := jwtrsassapkcs1.NewPrivateKey(tc.opts)
			if err != nil {
				t.Fatalf("NewPrivateKey(%v) failed: %v", tc.opts, err)
			}
			if !privKey.Equal(privKey2) {
				t.Errorf("privKey.Equal(privKey2) = false, want true")
			}
			if !privKey2.Equal(privKey) {
				t.Errorf("privKey2.Equal(privKey) = false, want true")
			}
		})
	}
}

func TestPrivateKeyEqual_Different(t *testing.T) {
	for _, tc := range []struct {
		name string
		pk1  *jwtrsassapkcs1.PrivateKey
		pk2  *jwtrsassapkcs1.PrivateKey
	}{
		{
			name: "DifferentKey",
			pk1: mustCreatePrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus: mustBase64Decode(t, n2048Base64),
					Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    f4,
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
					}),
					IDRequirement: 0x01020304,
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			}),
			pk2: mustCreatePrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus: mustStringToBigInt(t, n2048BigInt16, 16).Bytes(),
					Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    f4,
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
					}),
					IDRequirement: 0x01020304,
				}),
				D: secretdata.NewBytesFromData(mustStringToBigInt(t, d2048BigInt10, 10).Bytes(), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustStringToBigInt(t, p2048BigInt10, 10).Bytes(), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustStringToBigInt(t, q2048BigInt10, 10).Bytes(), insecuresecretdataaccess.Token{}),
			}),
		},
		{
			name: "DifferentIDRequirement",
			pk1: mustCreatePrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus: mustBase64Decode(t, n2048Base64),
					Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    f4,
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
					}),
					IDRequirement: 0x01020304,
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			}),
			pk2: mustCreatePrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus: mustBase64Decode(t, n2048Base64),
					Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    f4,
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
					}),
					IDRequirement: 0x020304005,
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			}),
		},
		{
			name: "DifferentKIDStrategy",
			pk1: mustCreatePrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus: mustBase64Decode(t, n2048Base64),
					Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    f4,
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.CustomKID,
					}),
					HasCustomKID:  true,
					IDRequirement: 0,
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			}),
			pk2: mustCreatePrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus: mustBase64Decode(t, n2048Base64),
					Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    f4,
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
					IDRequirement: 0,
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.pk1.Equal(tc.pk2) {
				t.Errorf("tc.pk1.Equal(tc.pk2) = true, want false")
			}
			if tc.pk2.Equal(tc.pk1) {
				t.Errorf("tc.pk2.Equal(tc.pk1) = true, want false")
			}
		})
	}
}

func mustCreatePrivateKey(t *testing.T, opts jwtrsassapkcs1.PrivateKeyOpts) *jwtrsassapkcs1.PrivateKey {
	t.Helper()
	pk, err := jwtrsassapkcs1.NewPrivateKey(opts)
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewPrivateKey(%v) failed: %v", opts, err)
	}
	return pk
}

func TestNewPrivateKey_Errors(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts jwtrsassapkcs1.PrivateKeyOpts
	}{
		{
			name: "NilPublicKey",
			opts: jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: nil,
				D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			},
		},
		{
			name: "InvalidPrivateKey_WrongSizeD",
			opts: jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus: mustBase64Decode(t, n2048Base64),
					Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    f4,
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d3072Base64), insecuresecretdataaccess.Token{}), // Wrong size D
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			},
		},
		{
			name: "InvalidPrivateKey_MismatchedD",
			opts: jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus: mustBase64Decode(t, n2048Base64),
					Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    f4,
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
				}),
				D: secretdata.NewBytesFromData(mustStringToBigInt(t, d2048BigInt10, 10).Bytes(), insecuresecretdataaccess.Token{}), // Mismatched D
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			},
		},
		{
			name: "InvalidPrivateKey_WrongSizeP",
			opts: jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus: mustBase64Decode(t, n2048Base64),
					Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    f4,
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p3072Base64), insecuresecretdataaccess.Token{}), // Wrong size P
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			},
		},
		{
			name: "InvalidPrivateKey_MismatchedP",
			opts: jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus: mustBase64Decode(t, n2048Base64),
					Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    f4,
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustStringToBigInt(t, p2048BigInt10, 10).Bytes(), insecuresecretdataaccess.Token{}), // Mismatched P
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			},
		},
		{
			name: "InvalidPrivateKey_WrongSizeQ",
			opts: jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus: mustBase64Decode(t, n2048Base64),
					Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    f4,
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q3072Base64), insecuresecretdataaccess.Token{}), // Wrong size Q
			},
		},
		{
			name: "InvalidPrivateKey_MismatchedQ",
			opts: jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus: mustBase64Decode(t, n2048Base64),
					Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    f4,
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustStringToBigInt(t, q2048BigInt10, 10).Bytes(), insecuresecretdataaccess.Token{}), // Mismatched Q
			},
		},
		{
			name: "IncompatiblePublicKey",
			opts: jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreatePublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Modulus: mustStringToBigInt(t, n2048BigInt16, 16).Bytes(),
					Parameters: mustCreateParametersFromOpts(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    f4,
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := jwtrsassapkcs1.NewPrivateKey(tc.opts); err == nil {
				t.Errorf("NewPrivateKey(%v) err = nil, want error", tc.opts)
			} else {
				t.Logf("NewPrivateKey(%v) err = %v", tc.opts, err)
			}
		})
	}
}

func TestPrivateKeyCreator(t *testing.T) {
	for _, tc := range []struct {
		kidStrategy   jwtrsassapkcs1.KIDStrategy
		algorithm     jwtrsassapkcs1.Algorithm
		idRequirement uint32
	}{
		{jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS256, 0x01020304},
		{jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS384, 0x01020304},
		{jwtrsassapkcs1.Base64EncodedKeyIDAsKID, jwtrsassapkcs1.RS512, 0x01020304},
		{jwtrsassapkcs1.IgnoredKID, jwtrsassapkcs1.RS256, 0},
		{jwtrsassapkcs1.IgnoredKID, jwtrsassapkcs1.RS384, 0},
		{jwtrsassapkcs1.IgnoredKID, jwtrsassapkcs1.RS512, 0},
	} {
		for _, modulusSizeInBits := range []int{2048, 3072, 4096} {
			t.Run(fmt.Sprintf("%v_%v", tc.kidStrategy, tc.algorithm), func(t *testing.T) {
				params := mustCreateParameters(t, tc.kidStrategy, tc.algorithm, modulusSizeInBits)
				key, err := keygenregistry.CreateKey(params, tc.idRequirement)
				if err != nil {
					t.Fatalf("keygenregistry.CreateKey() err = %v, want nil", err)
				}
				jwtrsassapkcs1PrivateKey, ok := key.(*jwtrsassapkcs1.PrivateKey)
				if !ok {
					t.Fatalf("keygenregistry.CreateKey() returned key of type %T, want %T", key, (*jwtrsassapkcs1.PrivateKey)(nil))
				}

				idRequirement, hasIDRequirement := jwtrsassapkcs1PrivateKey.IDRequirement()
				if tc.kidStrategy == jwtrsassapkcs1.Base64EncodedKeyIDAsKID {
					if !hasIDRequirement || idRequirement != tc.idRequirement {
						t.Errorf("jwtrsassapkcs1PrivateKey.IDRequirement() (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 0x01020304, true)
					}
				} else {
					if hasIDRequirement {
						t.Errorf("jwtrsassapkcs1PrivateKey.IDRequirement() (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 0, false)
					}
				}
				if diff := cmp.Diff(jwtrsassapkcs1PrivateKey.Parameters(), params); diff != "" {
					t.Errorf("jwtrsassapkcs1PrivateKey.Parameters() diff (-want +got): \n%s", diff)
				}
			})
		}
	}
}

// Key creation fails only for CustomKID.
func TestPrivateKeyCreator_Errors(t *testing.T) {
	for _, tc := range []struct {
		kidStrategy jwtrsassapkcs1.KIDStrategy
		algorithm   jwtrsassapkcs1.Algorithm
	}{
		{jwtrsassapkcs1.CustomKID, jwtrsassapkcs1.RS256},
		{jwtrsassapkcs1.CustomKID, jwtrsassapkcs1.RS384},
		{jwtrsassapkcs1.CustomKID, jwtrsassapkcs1.RS512},
	} {
		t.Run(fmt.Sprintf("%v_%v", tc.kidStrategy, tc.algorithm), func(t *testing.T) {
			params := mustCreateParameters(t, tc.kidStrategy, tc.algorithm, 2048)
			if _, err := keygenregistry.CreateKey(params, 0); err == nil {
				t.Errorf("keygenregistry.CreateKey() err = nil, want error")
			} else {
				t.Logf("keygenregistry.CreateKey() err = %v", err)
			}
		})
	}
}

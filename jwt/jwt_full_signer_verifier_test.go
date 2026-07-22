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

package jwt

import (
	"encoding/base64"
	"encoding/hex"
	"slices"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtecdsa"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtmldsa"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapss"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

const (
	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.5
	p256PrivateKeyHex      = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
	p256PublicKeyPointXHex = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
	p256PublicKeyPointYHex = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
	p256PublicKeyPointHex  = "04" + p256PublicKeyPointXHex + p256PublicKeyPointYHex

	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.6
	p384PrivateKeyHex      = "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5"
	p384PublicKeyPointXHex = "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13"
	p384PublicKeyPointYHex = "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720"
	p384PublicKeyPointHex  = "04" + p384PublicKeyPointXHex + p384PublicKeyPointYHex

	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.7
	p521PrivateKeyHex      = "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"
	p521PublicKeyPointXHex = "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4"
	p521PublicKeyPointYHex = "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5"
	p521PublicKeyPointHex  = "04" + p521PublicKeyPointXHex + p521PublicKeyPointYHex

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

	// Seed and public key generated using ML-DSA-44.
	mldsa44SeedHex      = "dddaccfaa05b0332b3fd7269c7d42de6cbe370735431f735346ccb6be7ad3174"
	mldsa44PublicKeyHex = "6e17b61b6c7881ab6d39ee703ab4ab4888d2134e54bb0195bfd0573c03d60bb8445f3a2045029da4fef83f7c55869c46d73dd641bc81baf1e713cdeec5116f24338a565c4a54d9d7acf4413ea505e00f294e48b1c7f9a391d2f070a6a741f12c0ed605a3e9ac6bcb5b5819703b17dcd331f08d987d50e2aa0df091c1a182ddd5ffd19a2b9ef27a5355d962229aa9451397569917e3325b44a7f040f6fbea8e69dbcf42d2d0b7af204368ebed1ba6be5ecb503a8d8bd3325dcc8dbf07b64ea9884b114f394cc17dcf4f80c58c1dced81a3f8ef8f201605e5f3306d436e9697a68a2b62a3fc5478e7113a070f5aa69385a8076d522652d6926b114838cb2e5578edba7488c1cfeabe41fdcf477aecf74755d1a67384c896e22a22f1106e0a1684838642afb76c3ebee45f48139fcef99afc885b2a51b519a3d59804b6a1a6a7077edd82705d1551bf12a215ef7053b57d2789f532ef1d5736ab088629cc09f536030cdb4b89b2bdf547b874913cc5d62fcf98f1e537e4252315a3768710972a14066f12cc01548bd9de6a59425b161d1441d3f6c2abafef11e8f35756d27a7754004e449a95eb698dc66463bfe3b3f8ca47e7340e10b69b42b105b39d9dced186d09595e9d65ce6227c039c8c6c6f9e45d17d5a2834b073e4b7cf0f1ce12a9453da2ba3ebb5bc0ffac14243af76517ad7d6fbd319c54391334e97d899b04bc91a31adad7cc7a056b5987fbc818075966814776aefca64381b1d3c5d01e933dc354f63bb79d9aafec70927972cbf9252b96e2b02770b6c4956021a6e1552ac0258d4245e1f9de76e523377d87d57ba7d8f442ab52b86f180040d47b8620feeaed7d543b0f38af35127013e5e8a32813f3eb7182ab3b154734b48ffd31fda285873312b59713b59d1bdce3147237b9ccbdd0a9e1394f02c3636b4739d00f2251572d455d8ffb45d43270e42c132f96e99cfac1186e4bb27cd0510536d742f7394259207f332a2df9a7740bebf66c03bbe5380c0c2daa1c736c4b0c938ed12884464d6f069d9cff3e3e8cc93fea8f5e2c707e53d24f2d2a69623a23a456447aad4bbeab468949c8006facd119c0c3ce6f4166495b5d10395d6c55adf87a08c379110e0811899eb97fb6168633a487db9ffa3a3dcf6bad9870493731acc4d4ba3280c197d7ce2f550294349ff8d5ba196ac50f45f9c6a62fcaede31f9068a90830e89f50cd5b11adc90cefc3a33a96e03400346e595866fad098b5e001a3cf7579b45da72aae543c7cfb4a78aded527aa266b98f4ce11038bb50698d02407c4a698bf502d4222c912d90462a4cea4abf2b4434fa0f72687dcad38e43292b843da6273cdf2da4f430253b99bdd39b2913416ff13c366387db72738061d3269c4c3bb5518ea53da32112d0681f750772cc517b48263e44348a2575c745eb1fa43c44a3c19ae2e2b373c6d048849df1b9f09ea59167b07d8611e96d7d297a55ae13ec4f82c825d661607b39b5f820b9be55e5f0b28e28b064f8faf5117eb462588e91003c0fed30d313fc4ef996f7598946714e2849580510c1496c91821bf16c7329c6cba46a013e40e2a5c0f9e8cd3e6830641ce8013212aa7bea6e9073c138bec6b7814458cc16b78b8a84fcee22c18b73976b11b22749bab5852411de427b0abbce118a0f204289ad0983bce87f99dea31e7172774ad3827c85165bf68aee7a983558aaa2792ddbc95bc748d4af646991ceda2b095c0f35bcc0e45e8608f71cfc69fc01170b6f9c7c83adda58d3efcc340a67d54ca9f0099f999cce42947499253bf798b5207c03f3c44c41da57f06ba761e029e1c768f2d77034552e2ae2a67fc956"

	// Seed and public key generated using ML-DSA-65.
	mldsa65SeedHex      = "dddaccfaa05b0332b3fd7269c7d42de6cbe370735431f735346ccb6be7ad3174"
	mldsa65PublicKeyHex = "ff693f4fa4305b7f0df64de0dc9aebf13843197c2072f6719d46c66cc57d3d2002a852dbcc8b09937ec9cb6a00b5c07abf368714ad2443df69853a4e1ee6ee6278ebbec5d0c7e85ee129d0cb93b40294d4812eb9df1cf45a00b5ccdf0529d1d3cdf300336e765536567117c23450dbf6ae0f1e291ec455eb3890fa51dfc833a5c792ebf841085a05ed2c5c13b1aebd30348b1381e0fd0c7d54c1f38f813644ac589eb3eb965a05c3bce53c846163c6335244322ccf604342d3f76d2fe29fd1a3df061265c4db2b4710cc30572fcdc5102237f50b7177f96c91a266baae7e51ed0637be3d5fe960a8eae90f589d1b52d7b1882d9841ce3ff4d70ab92f84c2d0e37c3fcc6daf7e863956e26c0e8de8305f467f3b417b7b03a9a6b8946e5bfc74156a0265483984df48462b3b335ce3a1a5aa9211cd5fbf19e796e179b798db4de8f0ae4c8104e1074b4a8b88ca40f3469c635dc37fdfb44db39947454fd3725b8c7127d1183c60d8a6373229e60609f3090f9f2a23122ee28d6b9a77eccd5b7b094c3413c8f35257030cf07394e86fa40870b41a4c7d03ebf2cdffd8b8ae9da1fab1f8a4b6ebac52270a88046bcca4a5fbca1069cb6d701ff33a3dd4012b581b8cb1254a71f6a703cfc908f28df90b19c8354f686ff1bf2198d1c6ce4460a881b17630d8e2b0063a243e212905b9f5b4b24f16f08d467e88a953696cabe58a7f230c9bcaf3af8cb18f4e023a586917e1acac1e39510942609049759d0bdd9a5b51d98b6bba885f1ebcb05f55c2f665ad7f021a0dca04ef36ff13ca626c7357725439dde2dce1a41c46399215272ba09092c930a8a9d53f40c4741a37aa540fa9a1010cf9742b3f3019b09bea2c6a24b21ea47e221a52eee264b7a6ab00c0b5423a5359cae62330670f831baf1f76761b7ce41bdad3e6776c4a7ac5bf4bc86a92a38b2b36cdf62d64f0de23b9dfe407c5069aa4f9c3573295203f7e0c10eda6513403b860b3d788a81920a878b31833f58754c1642ed5227fff8cea4095a98eddd54fff5bf21ccf4b16e12ba16d219b79a8fe02c9c3b30eec4e3815b9cac0a7bc0e10b125d8e8dceb250ad93a5204fb8e74487b873f4f35691b5442ad0f936430451cc86b31ebb7ff1b9b1d4ad875614cd65cb35c402b07f66bf1b7587ca8c7c322444e949cb76b215ff36e7fc076e9e0eee54cf0fa1f567d4ac2ab81b33fe29029cc079cfcdabb17ceee18b44c874a5cbccf86098d9a4e8bdb9d2722504bd2cca3ae18c8835bc6419c47d6091aa03a714e827c4b055f9cea4e2048714bc65050df6470923e3deeceb8a830bd8c546e554279e07be18b3479c7a5f6108e8cc483c1bfa24c9e30889b92cee2b79b9e769f38fe38630ba763e84835fb0755bf4ea0d0d63a556354fc8a7fe12a044c53023755b40a48c5068e414a7467d422bb85ad3f38559c4e17de597f533897f44ae9f6214377457187dbaecd9ca847e56498f7bbf437a4c4d3da9d5158758260637f155a3bd159ddf80b577370064a6666ca4a3caa5dba728d6b3ad25e4a1773b5c27d6ae011c144a61cf372a9405d6aa5a0f764bec102389ae2769eb1a2927f8f42f29d0fef78bec0aafedd368c00a9fdc726761c78a35e2a69a7fb0c1f4f37b76d17f446dade851dc63de76c8448cdee87563903df300d6c6730a7f848e0d71baaeef23354656c13fb4b6e1ab3d7678460445909e9404c9ae95728c01f13dcfc6d038bd94365a819453478ca208a0aeb6aa9435472a7a49d4f1794c402f78af2bd3205c834f926122f319bf8e2e7e85474728ceff9fd2add289f8010c3b60976ce848405aad7a65d1087d6dbbebd16dec130aba6279904d590534447862d2d9505fb75de383ee5a408cc20b61020cd5506e5c9fc89d695e1f8259c71556e13e40fb32f041b9fca61d129f744858e6af13168c21639d342ab879f3718175d695efa9c4fd1dfc0c0e28ceaab0a95f3bab371e96e2c3406015e81fd84ff93ff9b4f182c1cbcc6f50b46e2fbd4f607d2cffa10feca7e74d04b465479d30e5e0407af02871d719880c0627a225c715511b6d621cf56b53a2b8cb1413b37160f891e1bffce358376254f524139432eec72531835ae4ee82e127b2a1b3b8c68b7571f6ef103e39b42c1f32f08400580dafcf758dcc3bf65416917ce08ee6a496694b0027352a780a2d395d2e37bffa3e93b9b3f82e46f682bae508f684894a6705ef28263f2b1ed183998ef49fbc0fdc46c5bff5902acaa56fd95b26a3fc16ef6636a9d0c64597bab651c26b8ee1c966436fb1a4521c4a08a36f8db1340a1cdbfa6358bf8aa23edf09c1c487d318ac6b240a28c60edd7e624dac95f1ff36e95899f1f6ba0dbadcfdeca17a20c4ef343a9ab76f1209c759cbe4f5f73a1a4dcd0d18202e1ef472d023138889fc1445afcb2e1dbe6d4a6878ffd42f1cea8e96569a92c82d6807406580ba6f985e905a73dfafee5f1858db99a5555093d5cce8ac15cc6001352366e09d47c2afb342c80f8ef928cdf80aa9d8d39495282e628a1a8e3284ac68a5aa700b9c690bf6fd81856ad289d0f2998dc657e5cb9c021ea532732a4e0c7dae19f406b6df4b67a71f1dbc17260c210ecb99072d947b193ff50b62f7f2270d69fd27a411dca5e3f48c6560a8134822e8120fb226d5636183cc6f2ac83c9f5955aafdd08ae60c51a885edefc4ade6da2524164688eabbb70996f1d24a8045e9c6a10c8e2af690d4d7bb15352dcb134bf50c9"

	// Seed and public key generated using ML-DSA-87.
	mldsa87SeedHex      = "dddaccfaa05b0332b3fd7269c7d42de6cbe370735431f735346ccb6be7ad3174"
	mldsa87PublicKeyHex = "62329b19bb6bbfb56215d5311a4dfff20d2a9349b8827002f09c5661b5839d85f9e57fa0df1f7d8154a4ede81b90f09b627c5d4db2207280b845c58cd4874484f1949ba6e7ec95b631839a420b49239d65a09b21494a62e60bc085974e6041b88acabde3ae343dd74662679667d0b4072d0bb72bce73b0dec1d742fe9289b6d2458dc4061f6cd44eb25e3eb6bcfd5c55e623735dd9db8edf413ee5a0648a07b30e0a5f5c3317a8bf5fe0df658de35a6258f7b5500e9575d2fc6c73bb5086665ee649083118647f2fd93e5ea839bd76dade96269ac4fc87fcdbaa302cf3df5e42015e59ef37391e4d7b80f36b0d5fbda13f2a10d282961d4b357a82f4537c439a683ff9b3856e67f090ff4693405f7e00c86c2fc27ba32605320cf683d152ac443743ec09bda8b5d4a2eb43337d8502af40d08c99465ae027e4cb04075406f034fa9b954fc4fef910bff010bbfcb6884e0cf588a5b6fc0383d29b7653b36c8ee57262fc90bd59fbd5e41e89bee870ebaa777616ca24e2ffa3dc309109b3a450610fa4cb923ea49a3ff0c06cf821460ca215d1560592897896223c2251729eb343c5497d2b6a40989073d63c2c0497ff8322c67b2f1b27b54c0502fac792c4eaeb136858ddbdce4c1c50d7a6f81d514417568ba6732a4e38b8e91d6b779d7cefd63b4b1559b48092903b11145e2ebbd3232edb4b62d0a14ceb9b44e1b01b9738e8039f991156ccfa6e416cf5fd9cecf76825cbf27fec624beb38a1a92b9a0b2dc486c1b24aa6d71cc1dee35055c03803b60ac7661b2dab93b16eb0d4996394146d2b407d2df1a4753eba99f3fcba822a9a3f36d1b495141e4fdf5efd9e1af4d643f6a320f1c001a1e290de63ecffe2e55aaa1ca0bb7de7c6d0d968611b285dfc0b1b6b99f60e7e9b91c3650857dbe5665c90430543ece8df44cb60164d45578997c0448be088236dece92ff74a8376ebf066219f0645ba3b612ce22d846d310f18fce9f564f7bc54026ce94e61241511d701f5bdd28bd7aa037f57881e0bf45cc82fee03d650bfdb2d6efd734d6adfa9b5dc64c29bb04cd1a57d7bfeed888fe3dc1969eb4e0815be1b5d94c10e45ecf900bf5dada9e4bdd5318e80a2b7c2121f91f9e1b06174f8216aee611e7047cc4f08afd2fade17f20f3025a025a8ea95bba391bdc12d9ee5a6a9f1b90e3b0f4e2782448ad36810789660c16f1622c7bc805a36e5c4a231ef998469c7a961d5c869d823a63fb8e2fa2bd1ebd6a9b17e5fc76bf9809e3d98b65287935dd799bf2fe743a90ed21f8b567b6acf7f7cb60105d92eaf305c2e38be5a525247bee01a2e03279983b4e2b0d4452117a07e8c527e82d67cb5e5367a3470194132b8dafcab70c6480e83ef7a2c8485a7bc3a57c4e264c8296b6cd4f1d913da0b491742e668d33772da156cd2a0130295edc9b817eb0fc86301fcbad07d955a66bb83defec7b47ec6c9b07f9dbcd95d26c63991dada2314e2327d658d3cf4863759c2a0a0e447904cb5c4951f9b0e9ae52e47e2831f84c01672ff7ab56d0e41e1794e12aa29f2e4c030bdb9d6285b6814a1d2744049aaf4930089ce34c2dc7a40d4c0319029a5b7d58b47cfc9f8754494b3932dadfe3a28d4d5965a5957b13ef684c8a1f11b1544402005bd067c43323ab2fdf57882ab80a6002a8f4e3e1606718fd5894e53f1ce46149e03f15dedde35e4a152c455938de31257cfd00d4808cb7ecbd284f6e60ad1c576c6e0eb73fda6886f06d00396f6ba58e8bd6ebd72c8dd685c52419491716750e2c3a19a62d747359ab49c9c6f95b8fb8fd5e6c34007903c8cb6f28db7104a1d4e8edfc0ecbbe3286bd2feed57a7d57ae13257479119d32d59389cd0a589898a5c65da85dfc1ce2be69eaad5f54c9715e0c92ed1033c5a4ba4ccd44c9621825155285e93a31d95c22c2faa79b39353654da179835253c49c8bd3199139b1f3f236c2deb7ac68999f38a884ca28178673d05739a39a3fecdc2603977dfdaeb3d15f8f11b853784cd022b7a3715a50f6756b23a7a3f525772cccf0922676590bfe04d6bb93727020a9025f2f98aebf704db71996c23026091169fefe6db28e233f5868f7a15efa7e94040dbb0447e4a6059e38237823c80c8401c13a40f93c2abad63f32a394c0b724f78d166fa1da3565393c5e630b1a1517fc68a0dc396f9802923ecb24e6ba1fc16b89a509139c2cce2d68b01fc4790e48749219e9b45f9bee57b04f40f0a83b066efa2ad961e82688550d6c816c5395a6d5b2d1e5b013fe72acaaff8bcddb96bc58f7c3841bb20eb48e938cc3f0c70f508b7995c479acce108063afc85c3f5c270d5665f1cc2c8ae708d432f3b0b984f5b9f989f3537d4e0f0798a899965dd9484fe558bb6d799146c1e1b327a5274a4daa15b360e758c6507365a179e39074027396dc6b8d4e9f79b34c5d6bf3fdf3a655bede7ad62662956b7a5e9f97499e5f81443b098ed40ed8d540377bd81f7a048586ecceecbd9af7d16e0754ce6397d618e5754c63d53ae272a6f2aebd8318298cbac6c30203be28dd89914bc30889469f2939da74919a5ef3b2cfefa19e083521cc4da10688386591e44c17e14ebb344c32bb4fe1a545cc0946b389dfe0076d3a20fd2cecf025cc202b412fa08cdb7a183db30c3b4fa87737776cb0fa3a6ebc739362d636a4b71f83de1725c891d8f8678245beca907a07b560907edaaf4913b25501392439d11ea4c749d5cf387260f8fb7dcd400dd4442e6a41c0e1b5f60326ce4b8100e1a948fcb5a4664e1bfffcf5c8a2a21cdd9cf857375b13479dd3e90554e3d6ac66ee1f12612b9a999197a70e4864a09b9c65b25f58b4fd9c4a45eb2632be2ab213aedf1b9ec8b78f465da4ebc52812f5fd30fe7eb6623aad0a4cf39739ea935cf34c70335950cac41cd8f12ee76edfa5982d6d7072465a6f86c90edfe08feda802389ace7fb973d05f9ccc39bfcee1aea7f4e3f702d7a60db00d6f44c0e7f3cdb532e1999acb7cce0cfb45025efde99b237e4bdf0632cc8a08c249314b1c7b6bdb23fa10cb4cc5e7033590eca6cf7b5f63191a6af112edbbfdbee45bb966b00a0f3b50ed08ad71cfb5e9a1c19b393eaaa1344f62d9121d98499608ecbe1e12abfc434932ae350ebef637723fb1805405c670d4232e610cfb4fc0034478676f078a75e53509942eb48e8f3af5402be5b6f299d6b38a41f90b9026bba1cf104a2cfaebf904fc543c019d40155ce45a48a2f087690c4682f9de276ebfd8f3a540f609c1e928d5d033d62636d1c45cb1867b222e4649584157b2c3179ff008602ac43da0c115447ea2953270fc863f97b02a2cf77840375f774e51491d92cbdc141afaa1566522d2dd2afb7d9b8d340def896debbf5ab93df4c7adce9b74ba30f10db8a510058cfa8ca642a660526dd2c139fce94c18bfb2ec5510303ebc6786fb8bd3a758d274c29794fd7b461acc16eb1e866b0c35b358240f02b516677198d89dbff6fa0485606eb45912d977c36f095240f98809f40efa20f1d28e1f4aada094a401d5986d4eef552fa6d11de472cebf9f25bcefd71b0d88c48bea9e8acf4da8b47a0fb6aaa5a27f6ee64c4811a7fbd8f326153a238d37be6c42bb9de338ace2946f1a6987b5e8ef8c6923890a2f0addb5"
)

func mustCreateJWTECDSAParameters(t *testing.T, kidStrategy jwtecdsa.KIDStrategy, alg jwtecdsa.Algorithm) *jwtecdsa.Parameters {
	t.Helper()
	params, err := jwtecdsa.NewParameters(kidStrategy, alg)
	if err != nil {
		t.Fatalf("jwtecdsa.NewParameters() err = %v, want nil", err)
	}
	return params
}

func mustCreateJWTECDSAPublicKey(t *testing.T, opts jwtecdsa.PublicKeyOpts) *jwtecdsa.PublicKey {
	t.Helper()
	key, err := jwtecdsa.NewPublicKey(opts)
	if err != nil {
		t.Fatalf("jwtecdsa.NewPublicKey() err = %v, want nil", err)
	}
	return key
}

func mustCreateJWTECDSAPrivateKey(t *testing.T, keyBytes []byte, pub *jwtecdsa.PublicKey) *jwtecdsa.PrivateKey {
	t.Helper()
	secretDataKeyValue := secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{})
	key, err := jwtecdsa.NewPrivateKeyFromPublicKey(secretDataKeyValue, pub)
	if err != nil {
		t.Fatalf("jwtecdsa.NewPrivateKeyFromPublicKey() err = %v, want nil", err)
	}
	return key
}

func mustCreateJWTRSASSAPKCS1Parameters(t *testing.T, opts jwtrsassapkcs1.ParametersOpts) *jwtrsassapkcs1.Parameters {
	t.Helper()
	params, err := jwtrsassapkcs1.NewParameters(opts)
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewParameters() err = %v, want nil", err)
	}
	return params
}

func mustCreateJWTRSASSAPKCS1PublicKey(t *testing.T, opts jwtrsassapkcs1.PublicKeyOpts) *jwtrsassapkcs1.PublicKey {
	t.Helper()
	key, err := jwtrsassapkcs1.NewPublicKey(opts)
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewPublicKey() err = %v, want nil", err)
	}
	return key
}

func mustCreateJWTRSASSAPKCS1PrivateKey(t *testing.T, opts jwtrsassapkcs1.PrivateKeyOpts) *jwtrsassapkcs1.PrivateKey {
	t.Helper()
	key, err := jwtrsassapkcs1.NewPrivateKey(opts)
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewPrivateKey() err = %v, want nil", err)
	}
	return key
}

func mustCreateJWTRSASSAPSSParameters(t *testing.T, opts jwtrsassapss.ParametersOpts) *jwtrsassapss.Parameters {
	t.Helper()
	params, err := jwtrsassapss.NewParameters(opts)
	if err != nil {
		t.Fatalf("jwtrsassapss.NewParameters() err = %v, want nil", err)
	}
	return params
}

func mustCreateJWTRSASSAPSSPublicKey(t *testing.T, opts jwtrsassapss.PublicKeyOpts) *jwtrsassapss.PublicKey {
	t.Helper()
	key, err := jwtrsassapss.NewPublicKey(opts)
	if err != nil {
		t.Fatalf("jwtrsassapss.NewPublicKey() err = %v, want nil", err)
	}
	return key
}

func mustCreateJWTRSASSAPSSPrivateKey(t *testing.T, opts jwtrsassapss.PrivateKeyOpts) *jwtrsassapss.PrivateKey {
	t.Helper()
	key, err := jwtrsassapss.NewPrivateKey(opts)
	if err != nil {
		t.Fatalf("jwtrsassapss.NewPrivateKey() err = %v, want nil", err)
	}
	return key
}

func mustCreateJWTMLDSAParameters(t *testing.T, kidStrategy jwtmldsa.KIDStrategy, alg jwtmldsa.Algorithm) *jwtmldsa.Parameters {
	t.Helper()
	params, err := jwtmldsa.NewParameters(kidStrategy, alg)
	if err != nil {
		t.Fatalf("jwtmldsa.NewParameters(%v, %v) err = %v, want nil", kidStrategy, alg, err)
	}
	return params
}

func mustCreateJWTMLDSAPublicKey(t *testing.T, opts jwtmldsa.PublicKeyOpts) *jwtmldsa.PublicKey {
	t.Helper()
	key, err := jwtmldsa.NewPublicKey(opts)
	if err != nil {
		t.Fatalf("jwtmldsa.NewPublicKey(%v) err = %v, want nil", opts, err)
	}
	return key
}

func mustCreateJWTMLDSAPrivateKey(t *testing.T, seedBytes []byte, pub *jwtmldsa.PublicKey) *jwtmldsa.PrivateKey {
	t.Helper()
	key, err := jwtmldsa.NewPrivateKeyFromPublicKey(secretdata.NewBytesFromData(seedBytes, insecuresecretdataaccess.Token{}), pub)
	if err != nil {
		t.Fatalf("jwtmldsa.NewPrivateKeyFromPublicKey() err = %v, want nil", err)
	}
	return key
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

type privateKey interface {
	PublicKey() (key.Key, error)
}

type jwtSignatureTestVector struct {
	name       string
	privateKey key.Key
	publicKey  key.Key
	signedJwt  string
	validator  *Validator
}

// ES256, https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
const (
	es256X = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	es256Y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
	es256S = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
)

func jwtSignatureTestVectors(t *testing.T) []jwtSignatureTestVector {
	var testVectors []jwtSignatureTestVector

	// ES256
	{ // Ignored KID
		params := mustCreateJWTECDSAParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES256)
		publicKey := mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
			Parameters:    params,
			PublicPoint:   slices.Concat([]byte{4}, mustBase64Decode(t, es256X), mustBase64Decode(t, es256Y)),
			IDRequirement: 0,
		})
		privateKey := mustCreateJWTECDSAPrivateKey(t, mustBase64Decode(t, es256S), publicKey)

		iss := "joe"
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedIssuer: &iss,
			FixedNow:       time.Unix(1300819380, 0).Add(-1 * time.Hour),
		})
		if err != nil {
			t.Fatalf("NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtSignatureTestVector{
			name:       "ES256_IgnoredKID",
			privateKey: privateKey,
			publicKey:  publicKey,
			validator:  validator,
			signedJwt:
			// {"alg":"ES256"}
			"eyJhbGciOiJFUzI1NiJ9" +
				"." +
				// {"iss":"joe",
				//  "exp":1300819380,
				//  "http://example.com/is_root":true}
				"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
				"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
				"." +
				"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
				"pmWQxfKTUJqPP3-Kg6NU1Q",
		})
	}
	{ // Base64EncodedKeyIDAsKID
		params := mustCreateJWTECDSAParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256)
		publicKey := mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
			Parameters:    params,
			PublicPoint:   slices.Concat([]byte{4}, mustBase64Decode(t, es256X), mustBase64Decode(t, es256Y)),
			IDRequirement: 0x01020304,
		})
		privateKey := mustCreateJWTECDSAPrivateKey(t, mustBase64Decode(t, es256S), publicKey)

		iss := "issuer"
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedIssuer:         &iss,
			AllowMissingExpiration: true,
		})
		if err != nil {
			t.Fatalf("NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtSignatureTestVector{
			name:       "ES256_Base64EncodedKeyIDAsKID",
			privateKey: privateKey,
			publicKey:  publicKey,
			validator:  validator,
			signedJwt:
			// {"kid":"AQIDBA","alg":"ES256"}
			"eyJraWQiOiJBUUlEQkEiLCJhbGciOiJFUzI1NiJ9" +
				"." +
				// {"iss":"issuer"}
				"eyJpc3MiOiJpc3N1ZXIifQ" +
				"." +
				"Mgzp130-bvzWJAQlkrQRt45EeKQ6ymZX1ABQoautz1fMW2sVLONkoPl_g6UYxecYz-" +
				"2ApvT292dR_3jHd0S3QA",
		})
	}
	{ // CustomKID
		params := mustCreateJWTECDSAParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES256)
		publicKey := mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
			Parameters:   params,
			PublicPoint:  slices.Concat([]byte{4}, mustBase64Decode(t, es256X), mustBase64Decode(t, es256Y)),
			CustomKID:    "custom-kid",
			HasCustomKID: true,
		})
		privateKey := mustCreateJWTECDSAPrivateKey(t, mustBase64Decode(t, es256S), publicKey)

		iss := "issuer"
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedIssuer:         &iss,
			AllowMissingExpiration: true,
		})
		if err != nil {
			t.Fatalf("NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtSignatureTestVector{
			name:       "ES256_CustomKID",
			privateKey: privateKey,
			publicKey:  publicKey,
			validator:  validator,
			signedJwt:
			// {"kid":"custom-kid","alg":"ES256"}
			"eyJraWQiOiJjdXN0b20ta2lkIiwiYWxnIjoiRVMyNTYifQ" +
				"." +
				// {"iss":"issuer"}
				"eyJpc3MiOiJpc3N1ZXIifQ" +
				"." +
				"A51jqxnj-pddSJUm7dxe4bcmac3xOVg85xhIQ8Fsohv4_" +
				"LNMJnmx6Pw9xXGeUHDtW4Y59CxATAmXDqnqvB-kiA",
		})
	}
	// RS256
	{ // Ignored KID
		params := mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    0x10001,
			Algorithm:         jwtrsassapkcs1.RS256,
			KidStrategy:       jwtrsassapkcs1.IgnoredKID,
		})
		publicKey := mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
			Parameters:    params,
			IDRequirement: 0,
			Modulus:       mustBase64Decode(t, n2048Base64),
		})
		privateKey := mustCreateJWTRSASSAPKCS1PrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
			PublicKey: publicKey,
			D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
			P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
			Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
		})

		iss := "joe"
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedIssuer: &iss,
			FixedNow:       time.Unix(1300819380, 0).Add(-1 * time.Hour),
		})
		if err != nil {
			t.Fatalf("NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtSignatureTestVector{
			name:       "RS256_IgnoredKID",
			privateKey: privateKey,
			publicKey:  publicKey,
			validator:  validator,
			signedJwt:
			// {"alg":"RS256"}
			"eyJhbGciOiJSUzI1NiJ9" +
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
				"xKJ5YwXVLukyGqvPLy8PNCkQlh32N5kjh9IGdg25OgR08ADQjRKinVjO_UxROv0bj4Q",
		})
	}
	{ // Base64EncodedKeyIDAsKID
		params := mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    0x10001,
			Algorithm:         jwtrsassapkcs1.RS256,
			KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
		})
		publicKey := mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
			Parameters:    params,
			IDRequirement: 0x01020304,
			Modulus:       mustBase64Decode(t, n2048Base64),
		})
		privateKey := mustCreateJWTRSASSAPKCS1PrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
			PublicKey: publicKey,
			D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
			P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
			Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
		})

		iss := "issuer"
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedIssuer:         &iss,
			AllowMissingExpiration: true,
		})
		if err != nil {
			t.Fatalf("NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtSignatureTestVector{
			name:       "RS256_Base64EncodedKeyIDAsKID",
			privateKey: privateKey,
			publicKey:  publicKey,
			validator:  validator,
			signedJwt:
			// {"kid":"AQIDBA","alg":"RS256"}
			"eyJraWQiOiJBUUlEQkEiLCJhbGciOiJSUzI1NiJ9" +
				"." +
				// {"iss":"issuer"}
				"eyJpc3MiOiJpc3N1ZXIifQ" +
				"." +
				"SPjCMSIBpUwJZXV-wxs_2IT6Vh6znxtAasbK9eONeljAqPcBDm3dpjC25rtoeWEN5fL1_" +
				"P4EG6C87jLQyFgaFt1ghvJIN3_mlcykVKKj1P_wrxIyjg7itRujKw_" +
				"GIYj6eT3CV0Ei6xx6UHTkyIGZwQnGO2I6Q9mFyS-1OGBUmK-4xXK_" +
				"CCk9Bop5gjNcPkbrnFql15-KygppSbYp8s4ob59K_g6G-b7JN32WAqjoRzaAOJ9GhItg_" +
				"2BTow4Z1-4w6wH94X1WRnZbjFXJ6JcBr0noNy1k1PnavsHiQTm_" +
				"FRqsR6JbqkVDGLueWHlCBuBFr2SKqvIYDY8DOCP3Qi3nGA",
		})
	}
	{ // CustomKID
		params := mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    0x10001,
			Algorithm:         jwtrsassapkcs1.RS256,
			KidStrategy:       jwtrsassapkcs1.CustomKID,
		})
		publicKey := mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
			Parameters:   params,
			CustomKID:    "custom-kid",
			HasCustomKID: true,
			Modulus:      mustBase64Decode(t, n2048Base64),
		})
		privateKey := mustCreateJWTRSASSAPKCS1PrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
			PublicKey: publicKey,
			D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
			P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
			Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
		})

		iss := "issuer"
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedIssuer:         &iss,
			AllowMissingExpiration: true,
		})
		if err != nil {
			t.Fatalf("NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtSignatureTestVector{
			name:       "RS256_CustomKID",
			privateKey: privateKey,
			publicKey:  publicKey,
			validator:  validator,
			signedJwt:
			// {"kid":"custom-kid","alg":"RS256"}
			"eyJraWQiOiJjdXN0b20ta2lkIiwiYWxnIjoiUlMyNTYifQ" +
				"." +
				// {"iss":"issuer"}
				"eyJpc3MiOiJpc3N1ZXIifQ" +
				"." +
				"jHc-0csHrSxYdJ6fhfiS88Evy4q1FZ3igL-" +
				"f8vP0RBdl5gYy1Lx8qJQJkybZ04BzwyockPz3rs5UGj7a0w5S0jVnPC9Ktg1O5V5vY28ua" +
				"EQHXrskuBRPiynNOS_" +
				"MCJtc1CJlmzVD99UHJGcKsTfzN30u6wZALnlLqrMEJ6ZluQ4T1UJUJjlFjlrf9qWeHhFu8" +
				"xEEovnbwlX54UgGuaYiuqlS1ZV8_c9kG9oXU-8IriuqUctss3VtN4_" +
				"1XgEvFreOypKnCn29TAIaB8Frhq5CBsF2O30cTFFa0WtZox2lZsFU9RobrIOELC-" +
				"9kpIkE6iS03H-G0fi228XNRNCB0XhzA",
		})
	}
	// PS256
	{ // Ignored KID
		params := mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    0x10001,
			Algorithm:         jwtrsassapss.PS256,
			KidStrategy:       jwtrsassapss.IgnoredKID,
		})
		publicKey := mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
			Parameters:    params,
			IDRequirement: 0,
			Modulus:       mustBase64Decode(t, n2048Base64),
		})
		privateKey := mustCreateJWTRSASSAPSSPrivateKey(t, jwtrsassapss.PrivateKeyOpts{
			PublicKey: publicKey,
			D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
			P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
			Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
		})

		iss := "joe"
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedIssuer: &iss,
			FixedNow:       time.Unix(1300819380, 0).Add(-1 * time.Hour),
		})
		if err != nil {
			t.Fatalf("NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtSignatureTestVector{
			name:       "PS256_IgnoredKID",
			privateKey: privateKey,
			publicKey:  publicKey,
			validator:  validator,
			signedJwt:
			// {"alg":"PS256"}
			"eyJhbGciOiJQUzI1NiJ9" +
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
				"5TK1TQhykfbIuXYAClbt1tM74ee27sb2uuQ",
		})
	}
	{ // Base64EncodedKeyIDAsKID
		params := mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    0x10001,
			Algorithm:         jwtrsassapss.PS256,
			KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
		})
		publicKey := mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
			Parameters:    params,
			IDRequirement: 0x01020304,
			Modulus:       mustBase64Decode(t, n2048Base64),
		})
		privateKey := mustCreateJWTRSASSAPSSPrivateKey(t, jwtrsassapss.PrivateKeyOpts{
			PublicKey: publicKey,
			D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
			P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
			Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
		})

		iss := "issuer"
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedIssuer:         &iss,
			AllowMissingExpiration: true,
		})
		if err != nil {
			t.Fatalf("NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtSignatureTestVector{
			name:       "PS256_Base64EncodedKeyIDAsKID",
			privateKey: privateKey,
			publicKey:  publicKey,
			validator:  validator,
			signedJwt:
			// {"kid":"AQIDBA","alg":"PS256"}
			"eyJraWQiOiJBUUlEQkEiLCJhbGciOiJQUzI1NiJ9" +
				"." +
				// {"iss":"issuer"}
				"eyJpc3MiOiJpc3N1ZXIifQ" +
				"." +
				"g3PZHFG5ZTEhq_" +
				"73HvCOy5DMsEIYOvuhDVzx839d8KhepjQ50QukGG5xIndgNkwJ6lHNGoDxXuAWu8ckSkt7" +
				"y4RVYc9Qef7cViiHFlJSSFhGocZZuoNFa4uVyQFRe84Zn70kTt2CZ22bhFAJ9rGdTF-" +
				"Vw5BgiHquHiivFzHyo6Q4hOL901Sm1hIW3wHJ6wneW_at6iVLv80l3jRxh19y7JfQJ-" +
				"hCE3yv5UKDYJMlNwwY1jzVD1GdFwpNnjTtgtSH9rFMY8t7D9iXfQjo4iNpZFxeho2igyuV" +
				"dUj8BhfzFO6aSk6NxWdY--ALTJ06YfqMhqNzt_cDrtMksR8vJMcjEQ",
		})
	}
	{ // CustomKID
		params := mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
			ModulusSizeInBits: 2048,
			PublicExponent:    0x10001,
			Algorithm:         jwtrsassapss.PS256,
			KidStrategy:       jwtrsassapss.CustomKID,
		})
		publicKey := mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
			Parameters:   params,
			CustomKID:    "custom-kid",
			HasCustomKID: true,
			Modulus:      mustBase64Decode(t, n2048Base64),
		})
		privateKey := mustCreateJWTRSASSAPSSPrivateKey(t, jwtrsassapss.PrivateKeyOpts{
			PublicKey: publicKey,
			D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
			P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
			Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
		})

		iss := "issuer"
		validator, err := NewValidator(&ValidatorOpts{
			ExpectedIssuer:         &iss,
			AllowMissingExpiration: true,
		})
		if err != nil {
			t.Fatalf("NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtSignatureTestVector{
			name:       "PS256_CustomKID",
			privateKey: privateKey,
			publicKey:  publicKey,
			validator:  validator,
			signedJwt:
			// {"kid":"custom-kid","alg":"PS256"}
			"eyJraWQiOiJjdXN0b20ta2lkIiwiYWxnIjoiUFMyNTYifQ" +
				"." +
				// {"iss":"issuer"}
				"eyJpc3MiOiJpc3N1ZXIifQ" +
				"." +
				"jrJpl_N-" +
				"uwEDnFrUoqjvJb0Hc9RCyXl9C8heT9Z7ITKOHn4B8laq3Otz20TLeJ9eHNESHZh7mq5R1o" +
				"1vgdkGmxvtmQ8OXC9sr1paFFWREH7FD9ofHSpru7WqkDLH4K9iiQnr6s_" +
				"Idy56f9xbELgBkwipSQVeEiLbWXvMasU2YyyOMfEFF40Y-" +
				"dzxFVHPUWKV7GdrrT7TdiA9Z9pSl4JNQau3_" +
				"sEXOnBZQ3GxJ63vsDQgAzTuz6Ggr8DuuiLHkOZyqAF6qckQ7IzGEYw7jDbHEBR3VbUU8xZ" +
				"e-X1uZS-ZbijC452qDAT8qCp0z9zKT-zOOa1W0hdxDOnG2pPWqNzy7g",
		})
	}

	// ML-DSA Test Vectors (MLDSA44, MLDSA65, MLDSA87 x IgnoredKID, Base64EncodedKeyIDAsKID, CustomKID)
	mldsaNow := time.Unix(1300819380, 0).Add(-1 * time.Hour)
	mldsaTestCases := []struct {
		name          string
		alg           jwtmldsa.Algorithm
		strategy      jwtmldsa.KIDStrategy
		seedHex       string
		pubHex        string
		idRequirement uint32
		customKID     string
		hasCustomKID  bool
		iss           string
		fixedNow      *time.Time
		signedJwt     string
	}{
		{
			name:      "MLDSA44_IgnoredKID",
			alg:       jwtmldsa.MLDSA44,
			strategy:  jwtmldsa.IgnoredKID,
			seedHex:   mldsa44SeedHex,
			pubHex:    mldsa44PublicKeyHex,
			iss:       "joe",
			fixedNow:  &mldsaNow,
			signedJwt: "eyJhbGciOiJNTC1EU0EtNDQifQ.eyJpc3MiOiJqb2UifQ.Dy2FaisH0ANuGoqz_q99pBDLrxXRO_-3i3uGiaKveG4W1u0uzD680jsH63QmeiC8Q33PfW65t-k9nyRTnhNG1QHaC5PkgCcPQv-w5YAX-jBPb5HfoKQLi_8m28wT1jdNWqz03S7x2zge0xcox_kNmW7_sLuSOkZ0I_NVc1Yvr-dHU3xxzgUW59i_N-3CWIvJcB0L-0HAWj_3mfCQq2Q_KVwe1Z_--8QnuO_oTXD0Tf948SM0_vpIB0QdoiXokRknC3XhYVixsmWQ5hMH32TMhVjOi8KZoL7W-FzyM4DJhPHAJjGj1Xlhfyufvx_intjphGjQZsoReaO0HjtP7zHm5_jsP7gaD1XPOqMOUS2bYz1UP1XgPoztU6JBSWiqG3g7FrzJDUXPr8kI42n2dKzCWV9unVjIIYZP3BN1To2BiL63eKhAztlhyvTuOV6DktT1ae9GlNxnX9Id445aCUGAQIcajnaJNyuyUl7iMl89ear83PHF2vx3IEUqXoI4A5MZ166vKvAYMI28c5gvW6bSNf44UeXKjk52Hc10chvQUoJKrwouYAPPupL-mAnvBZSwM3eloFddWPSF-lQxdDZjYjvFFlWiPMPoN98pPjIKQSmysjEdxgqTmaPDnBN2LL_aqhGj03BPJweBwA7xg3neU0IiZ0DLjTmyjdAPirSsGzF95NBKrt2PaQHXQiviTYepo_k393NO6unDNwATJcJRQCTsyJQoI-93jlpVvPjU5ziTIoaZ99lUORNd-QCIa7c3kW5UahL_rDZM3ey-MC3FI88lb0x1wJ9ALYLkB-F-mm9qBoHch9xJkgP_6B-c59dkXXto4s2PFpwrfs05mSWap60-203Tf4RAhJD6wLtyeJd4JIqOxaIGLc-LrO5bE26dVkW2NAAL57muReY9MHetXFGdkmv4sw9locaw5UxFVZb1rZwv2zLQNvvzCynE6uJ7wq5p2lVyrd5On7cQ3qbbh5uaIpJpH3SEVp1RHnM7CBaShwsOSv5a2UoM1munX2CSerVE0jxZdrjrSe5WvU_lI_B_S_RREe8n72e2cf8vw9R1xGNnQ35tjwU4yhqVc5BapPHuUMaZIzy_6zAEpho7QDeLsc1hGxQl6loqvStSOlJ84b1y65Oqf9cg01fuJMGTUJrgjirFx6OHzq7svymSx8nzo2470FiUHrJ-j3pHpozFbaaThTnz4Nz798ZBWLZRrxXTZLWljKv-qabWVCI94rBbHUixW-Rv3uWdR1f0Tccq3A5hlFTsetG_udU66MsXCmIIEkfC2TDUJZqLGF93ylpT6GTWtzCCmBifm5xnH8WptfHzuD_9omHua5KNDj1kckF9cXGCvjegn6RohgssFzmfnaHv67ygWBkSyZvcwN52SXO6YDAvinzeKuDNHkMdrcIBn9tVN1g1b83YvXB2-pLImFytrw8tsC0Ev_ntSs78X6dkMVxkTpByrm41sYEvlkjfu8P-47hr4d7gVozmjKMxdokSf0hnloLHTMf13l6gvrMvufa2KX5HHFqHDRcCuOOtwORsETn7j-bdrDyqgMnxrzgkfJvIy_3tkeMbd-l3zgTL6jz3-oDIHuXvudnMDIRPeFVcMf6XwovjfR77FRw1USdR-yuWqDJH3k3P2uU25zbS8tOU3xTiIPdL0CkruvYRSlv14CvYK5D9bJ-BtPoIdhR2k6W7d1bV_sK4F_4GWUy2BBmXpGYVtYBCeXkEzzOOwfuG_r-JpRlkNSVhCIK8tE6J7E2KCVh8br0WnVv-Obx7o1_4Yh92U2YEMuVREUx8u-25EriCTW8N2xTW0sHTxSezv3FFbOSr5wp7cd18w3vfvl9h2kQnLMnnjtLoCp1laMDMz6MphCLaF2PBD8ifm5p2bs7YzTLGCLauKlXLHFSIIRetxaSVps5rmvVpDgSJfcgSxhGo3lrqLgPacMAwXJCZ3TxBM7LXyOdlTMI7CUORvs1aIAkw1pEx3LQJxzTsw9Z7NISgz5oCaTTpQjGJ4C4r9wSDhDxuJnKaZkKQAcEZwXbnCQZjzHfiWrlmTEDChAFZ5iBAEWXMoSkgkD_5tXq1cjW-pputmDGOnov84MWVq8v1F-8AIhT7nXg6jTpfL_xoFMKgNvPJ9QU9jSVQmpxiomBK_QgPx-AV3PImoXaGN9I27LwFBs-VfYeNHV6312NhmBkFYXE1sy9peVkoXGwi0VLUq1F2aqYks22-6lcpO2mIORVeD-KTIRCfFJ0-_jtO9LaGvDH8QDS-r7DZBw9VpJmntrxvDRbj00q_9TfhLQIHWe7YK-UiYLCkLssr8AQ74kKZqT1osrN68WhD33qzI4ajq3U7H6R4ngThjCyNX6A9XBwY127XYT_N0We_UCi7wLxa8JD01rfXFhphfrmbtUoAoifZdY2dqBSIlodmDEJ1Pi670QeMYMJaidiGjXrv78JxcbRf0xxk-l7nmJrbDnIEM8jaaSlsSm4DezM_mZsAq6IXa0AXVKzrY2KlnxpfLYQ-EVyYsVm8W0VXSI14aGVwmNdZM3DlSFwllMiBalFIDmKluWZOfYS9AaLqEpAF0w0iOmYIkxBKDz1f5XRaP49FzWiCbAFmgFsDriQ0ZlJOKVKzQ80miavJYuPJw9TRzhoLobn0UFcPBRgAuEl1XcAwo0mY50JvHa9-vML6Jt4EVkKJm8UFPZSmjmgWhJOs_0-ycIsXWatYh39j4reUqZ-88fUV-B5KeQixYM5IB0t998Sj0Be9ERynVV5XXpzEr0oq7APanAqE8pHYbWmwd4Gv11K5Ld3D5JIY5-dlsaskRGd1UFUSWSVCZ98wQtv7sx4LN_bJOr6lau-xKwEe-AXLKZ3XUFbeyk7fmd4gCUOTX6PJiFBfGNj1a23r_fe-xKuSGknqWVRRXPXXpvG7y5XA16va-MSwUa8E7uAmYrUx1qwi6C3DZ3h_D1ogsaG5wxgM50ndr12GwHAvO15-DqD7y2U-hLl044Jqs4VxzglxUFrN7pX1xyx1MiJuaQQ6IkynRkK7uTMAm_WP6hWZOZ1H4NyC9KgVbEKVB0GFkV4uZexbpFH4qRrjWriQ3y14MCNksPDAe9iayPdkUAyhwmNkiggrWb7fq58CBw0ZGyYrLUtNVGSMj6LDzs_5CXV4fH-hrK7U1ujwFCQqWH2YoaKrv8zU8PENGTA8VltyipaqsLzBzc_R2evv-QAAAAAAAAAAAAAAAAAAABMfLUE",
		},
		{
			name:          "MLDSA44_Base64EncodedKeyIDAsKID",
			alg:           jwtmldsa.MLDSA44,
			strategy:      jwtmldsa.Base64EncodedKeyIDAsKID,
			seedHex:       mldsa44SeedHex,
			pubHex:        mldsa44PublicKeyHex,
			idRequirement: 0x01020304,
			iss:           "issuer",
			signedJwt:     "eyJhbGciOiJNTC1EU0EtNDQiLCJraWQiOiJBUUlEQkEifQ.eyJpc3MiOiJpc3N1ZXIifQ.jdKrqRn8SWNRz8iGXe2q5hE-zMh_9_I-DUaRCpVXMyNKpJVYBRDd3Vhks-VcZaM58z6aDLPc3zwweJR4CI5yC_V73AQtT_hLQDvp5y9PHkvnuRdo_l8ZqtPgDKAR5S_oP_trWk16pYuBMMujhtNJLtvj5Jl5xs1oLbaPi9MEK_YX1POzetxTmZlzK0V_g0QVZNSOKXm9NMYeRRpryypjetxjaVXgp3NCZ31CSFq3mmlAT9wl3zg5LhZ9Cj-Fa9IxncTA-gCF7BVaO9TcRT57AwCEQ0Vfu7Yx71dX6bN8P_a16m2ultozKK-BFm3h_3EI4WJ9rKR0oyWmwcAKPoPcaAXFY8fWTUaBeK7v5lhoUpZU-okX0cGX9hnhb47PUL7QaKC4lhQF3JplL8D7MlHah1I_06WBp_VfxWUuXYakzVs27zJr9Hz99wHCQEVUjiAmGEdvfNCRf-7ZfxwYQeNg27kN5gg7C07lIR_OkhPUEjWQyaf_2TfiDTZiv4SEGYq-CvpF02rOr7rBAJ-ExJ9Qavi94MhqBiaSC9rYwVrJSExbTiEfUTI2SsF5NLVObQyXGBgyN3LUqnnFR_jw-ESLTbD5Fd5-UDMorBKmkWX87MbE8oE1-6-72-2qILBFugtNmXkN18CCkrmDy608FX1slwD335c22AraCSwrIJMExoaD9Kv0DcZDyxKR1jgG4-bHDor3WYwTJP4PfTsaJf8tN1Q8W5FsMuUmf34DBKYC9vrI2RATxGaRCNAYvikvZ1P7Yuf46zmSpmjPdfAnjeqkPyP8uTZMPPvLoQGQfG610Bv77CHfvQlsAmfkv1FALxJ8JMAlb-fzKKQB-hFbZDMK8PZDlAZabdNtHmm9XQdi9Jsa_Ovsu85a_hsMgs-q0vFIsVFNW0112E0kOsDTttbRh0qjEoTXYuR95bv7DgkAp892SeBcVvyQcFNDh1rgTruJ_yGhBNnBVrBcwTsvRMJ1HKyDHIuyj5iCrExo9L38wCYP7LY25HGZBjxmabnubD51e0bgc7eeDcacjbtTD0OJjHv9AYwpBv2b3u6s-gb-nz8QQSzrXuPBahYbPoVqXfsNME4Ys_agoi0eZA49CfSI589ntyZ_sWxfcZuGIzkKvkbjrT3stGu2bZ8pTwdEVWA719XV5ZjSULJhJlkgyWHH_FSsV02-fJXoeOYHYIWbeGFUaiz7O2T1spS_o3qBwN525NuYgG14l8BpBJ86-nY7gk4HaWYCNHwUMsqYgPIsw0uHqHlBif3KOdb4i1NJz4fKnYwl1WN2Cjc9wKVU15esq-62qdHOpgkApiMpJU2zhWV9JYFOpYdEmg9-YLmRJkh_g-t3Cz5_AUgXoLULiewmd4AWK_yPJLOMaQnyBWFIlOU4XiOi1sIe9jEEJKPFw5rqurTgxp8wtyv8zbfz-ndLsWL8TcSTnXNgSaesNh76O5OFgjO2peovNq5Mvttg6JKY7qa8JnTeHBwl9deBKi3mO-pWM5Sim6N3JwGesOkrB28kVdOxOxkPeKsXwVC2d9dSN6BOYfCEOujmA1tikNdVLhkUr3dF7sf48OhXfS5sI6GNvil98XUdsROUSAAVY4PrWPFkUnSUbq4zzxYvPfKqm4_8QalikfCd4z0x84QqTY115aO6Gh6eQjspelHkqfqZGU8QIUCluvILM5g5SypYVcQx2nW_KrfLpjm6VFtmlPSV9imNOROW2--eH6g_KmSpFRLFSEULKE9kmHH8brZUt9Oiz5j2TbHQecd2VX6j_iNIIP9igGRCwIIKoe-iLrusny6e8WJSee3aNcm0PlheNnBQ5KI8q2a3UddqQ3C-DLLOgOwl8wPAecvHMMIAjFKrmRViBd7XggGZ4Sdb_nv_dodLBvYEmabPaNBHO0zRvIHthMSIhda9tUK9x7UfNNRuJNtKTLjYyITv59GO8bEKgH0J8ZIKzzRYgwpvJ_BPz_82fRpjHU3wIEwoSQuK6DGl_YdTrSleK_RrXJV9zof-5ETXnp4b3dt1l-oEEYUHWVFgJwkGfZmlgMmPs9s2dX7omvRR-m8q8-Q6hJfWX9egpKyxhB-nXrr7A8mLWlfCd3VBny4eizE3rpNwly6kfBsZGWFR68zHJrJb-CqoTWfNKad1njbMO4tNSkryDElm_qVT3lHuXz6qQnYegZRBzVuVEd2PeJmQigB-97Y21lkxgLLjkOjswBMfRN0y3sqK5bLLoxrfeEw-e5UWbvuo4p2BtdE4FIIvYKgimtwrHDM2IRPx2-iF7t-5tOMqBhtLHwqj6Fv44KmwsjLrMq8XknNXgN8rBcp4lUT3k-Fz3rBEb7pC4ZJnC9WrIShX3z05hf-htvM6ujESIcxAtk2L6MJqpPv21-Bd_oaOE6wPG65sX3247POFaCxSj2svZYepw8Ntr8GbIc3ruSPS3Gtr9yl1_XC7RpzjuBuyj7Pprm1Fzf8Tjhuj7l1a_X4_78LywWvKbfwGCOUkgWEz-CA166GylffTq_HxIaM0zOiTMkDhDwGuiODZyPJZ_IKudgE6RLUfAG7ZsqRD3jK1nAI8aUTH9kB9QOpGG-vipFH2MXUEa9sMvDRWCmzwaWBx-wti6YVqeXEt8zxaQGTrM2Rr4prDVnTCouQn3n9mstjgjbFvtggt7cw_BXMOsN244T95tQ9sDGgOV2tWkPf-RpxcY4pxm3-4dS-aoonp1izKmfzsqG2LlIAYZbYoXRTezdrSMzo2rCge-VWegfrIvMG3VgmNJ9YSM3-fMuJPJtWqvXlciZ8McjdfHKZ37zPiCnfn5wc1Sjtu4JKEb9L9z7AIv0c7aZkm4mQn9iJY6sr84fCHYpVgHtGVsWX2Ub-fgkteppV1uT8MHn2_rSF0O8Yel8AfOW34Pm4rt9eDw_yQzT4z6b2LcxCcYjtzrm_NfSR2fB71pda5nwQ1OjjEiZzbTu5rSxPvtYIGeG9QMFUSYMm8_K6c635Wc7UqcDQc9oKx0eFmv136qZp_ADjtHPTain6SmQi-r-VP2pR2k6F_yIfglbWeXgQ9AI3MS2qGST7Ab7MZNRL7j_RTJCkpMtk2JqNb5VDZZkyxemuOiPiGNwCk-WLTjcvzaWmoc99IN7jGB0oGQUVmbHCZuMPK4PcBFhkdRlhaZ35_o8jX6fb5ICEkLERHwQIEEBY3QUZQXGBjbbjGycvV5-sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcIzY",
		},
		{
			name:         "MLDSA44_CustomKID",
			alg:          jwtmldsa.MLDSA44,
			strategy:     jwtmldsa.CustomKID,
			seedHex:      mldsa44SeedHex,
			pubHex:       mldsa44PublicKeyHex,
			customKID:    "custom-kid",
			hasCustomKID: true,
			iss:          "issuer",
			signedJwt:    "eyJhbGciOiJNTC1EU0EtNDQiLCJraWQiOiJjdXN0b20ta2lkIn0.eyJpc3MiOiJpc3N1ZXIifQ.2C1gQTWE-nilND_3rEPFrIy9WN8hb5i2JY2FmKIVrRAARyIkuj-DPkWZFH9Mi3mbyIzsriff4nPOl3a0pdms7WI9OTWSEtnwwpmrH8rqG-p4q2VztvSOLcKl9mYOxK2Ces0X9Sq1NWqEibPyZVGxSuFwDteJxOYkD12K1P7pe2bccZyr1_hqEXnv4Ac0FcWuvYezg37tVnrXzf2ATuArJCRzHERd3I05X1_0zj5yy0lNQc1bsVejtmELqyz1czOFnWpWgwJk1Pk8ZpxXsbESSrtvxLHopYXo4Mgq6DsHriakSCk2H9jCmfuWkMa-Gd69-paRGosUkYjlUAFUw_Snl69ihNHyZNG5s2UdkRuolqaHcC5l5YVLMRMb-zp43Xlo2RGPS3NuxZ5AvZU3-CMKzVfjHpV3049r-LXZyvel6eywRbtoswu5QR6DKoGhvvdw5BMNcKpgaJYf9zxPb5fAcbRXlG4r3UvL2j4xEvcXbU6RJyae0mjI1B8ZNnorl8QCQeX564c3uAkEKx3cIGqu3QK8FdyDnsKWCfAVuSYwca-W2jP_4nCHPmWiPrRuukCLzCVuXEQutrz1jxQVVD0x2kKAcDWAhVZw7pYn0wFla6Vb8fAri3Bz3BaW5jM6tQaoMZ-CFSv-SMPFA5c3zMPTqNiBsWog02BMGkDsGcRv1hAToeSvZVkvm6d-riDbr95PbvN5_QvyDlLWUsRwirMhdAy2pKFsp9uH_9USKk65jC3sNRG1ffLvp-bkspkeNl1Y966SZHpxrn4uKqTQEMPQdIwfi19xIaq-dad_kJZHMfwbeZWj4ouWSVOsLmeILBQvoz0LaXyrPQELuFzr7BCPmgGURSZB-lpPTMFJzcb9NFYQDG_w473oa19jobp578muHzeNgjHr9WSqllTvcUmP9Z2KuJca1VL_JovkSyXAUuBOFz0LHM-gK_eUS1Q6zAIwYok3qUsyTEFGJC0U3CsQki3g_enJa-aimzL_x1C7O-fZlSrmcu4xYTATXloCQoRMlZuXZVYGixbazkQKZYBqORSQ8RWGf02mwZbu3qdrXkz8_nBeWTJPE6FIxSbq8lWqVnk5aMwXyIpPR8Gu9PiSlTgcHg2SSbpbpZlSZtAp5_Hpgb7bArcZZ3cqNcA9wgQo_vKYtmayDPSLazldCHLe6pxGrXeTuJUwfqWnRQ8ddZ9f2D9OZnoBZnTXtX23xH11e0jdhJbnAdb3o3utT-bu_yVsAuzpSlZo4GCuwmatKXQyahMoIwLkCV4YEweFYPsOS6MIG30f5eehez-1T3wvnUt6DF_5j4nUn9BlNgKWTq4rv7Dj4YsXpX195_lc-Jf2Ok-MyaWjXxMG3SoiqSdP5a566sPr7Eq5NEZPGt-m3cnHK3AQ0hcJHhwBwpig358lm8Pfpx19o7dzJGBFmNY_w9OMVdG-JuGWfDEE09qYGga7Qbo25MEjH96NgDoS2Znt2zYQXML9pS4LifFGX_WqE7H2V58ysr3Ag86eqASyFUEJB_e5IyTdVuh__foMAJ37Zi592YUsGwvy4nrZEVbx7iQT0gOOEU53WVWE_aKz9t56DqXm2z8JEJo1ZYtA1HVFYbgAywRfOxvGqPl_tV6eRm516lf6RqkVg9RZ8F-PdSDJpYn4Qa6RtdR7mB_neTqFitYVNEaLBR5VuC2e_vYZgi5BeFnz0SF_7dHavT4NsjlSNcpVsRFOHU-A7bkxCLas1g3obH-ZAxZMRKiRyOcyZKrcuXrpC6aet0FKxmA5lenOIuTELjYZYcLtJW09TD6J4dCT0209snVjnaFZkQLxruINOTwQB-Msez8LxwZbN79s2Y0Y1Q6mejbdYSeIrcuqFG41tZ89m-gzP0KL3CkaZv9n6KSjy7kRuZrTuH8eYQrx2Pcq-PoNhOUfEL4MDE6YywcQoRKO_UFHxVHUVlTq7SYQVSXXlLJ1VCh8_0ndK3GgZkAk5PTfBqT8bJ55XIYKYBNtnnytTfmSlveonrZMxnjCQ8HpopOZQI6octKhPrzYZGZkDmVw4TU_-7tR5e0Eqp-kU4Czz1n1BYmFn0MZFKlR0o4HcWG9JSvVF6z87F2OTXfhOdSC33r7KIEP2uPU3Yr3pB6jQcMqpz9KNEOvWuqtuYE4nAfcqA9asKXbbMU6-D1_w3zsg5AxqSSyMjCSJLpVOK8HEiOB3ZFvZvy_SUV1oIWfKvhr6dfCfQzWA_XJ0jWhGlk5uc9YadU4t_Z9xsGYjav5rd9M8Se21VPt0x8tqUnDqGc6qlYbuEB_uPBDD9Oqtx5rMWEFa5hYhlImvziPvPqfM_5LS84rBglKzOwv6WTtCFec0RIl-rs1HhcD3Y7XjeYrdHpw6DuEgz8F70oFsywcBwTZRKfXMFnfm2E3HZ5cS49CTkgPnO4Ijok_2r8HUdoME5Fb6uucvXZoMbHqABmgvwTSjEK9te1XED6MVyWGO6OS2B5o_8Txc4xaEVSZdUMLFk8Qam27VTLIundYDaak1NxnBTgLWwKNHVg9-WbrXBamUuyQ2nr--wTqx4b2xqXVlRCA6HN7XqeUbXUqYxn3ZCvQn3x2HLtDCguCzGvz6dtwtcbRWaMlvAlrErzZxg6bQZ2rGzQI-VCC3I3Uo-KClMxc0DbfQvm3Ir-TD1l9raOoioDT4URI0II19zu9CdjBzNLqWX3E262E5SHYabwX6giAPsKREllNMjqX0iJOsTcRGUni7NQoxM2JOOzAyXKfPGm7rIh9nXhl6ZSt-6ahN06BgMmnoYgnwuYNuYKKny4sxlAp1v-zQ0UcU16XjSvxXYJ74SaUM5OvwcDm-W9xxYBf-sytIcVXaAlG-rQqHsS0xKv2OhaJVjGJPkFRJ_f1cR6N_SKY4kuTRMwjFW4kcwowPEf8CuPR8-oy5TCDO8Q2ZVlsYWaaP2hxB7p_BIhNdUgjf1tTRaQp5h0ZAfR5oNojlawtfpkvu8N2gj1BSh7zPIgLkBfBmGgTNiUJW2ijac8XOSRCDFqk1n_zCPb5cHVipxNry0f_V1YFvCIZBu3GSFg9QmD4rc-kHMB96LoADzomvVoCpJ0vd1MW-Y1xBHSbclLSBphvJDy-TtYZ1WglcqaJJcSHSOkBDxMhJyswTlldZYqls7fD3OT0-wgmWmqCi5SYmanGAAgOEB4jLDk_Qk5pcYChqrHE19_n7PH5DjtSU1p4gJSg4fH6AAAAAAAAAAAAAAAAABQfN0M",
		},
		{
			name:      "MLDSA65_IgnoredKID",
			alg:       jwtmldsa.MLDSA65,
			strategy:  jwtmldsa.IgnoredKID,
			seedHex:   mldsa65SeedHex,
			pubHex:    mldsa65PublicKeyHex,
			iss:       "joe",
			fixedNow:  &mldsaNow,
			signedJwt: "eyJhbGciOiJNTC1EU0EtNjUifQ.eyJpc3MiOiJqb2UifQ.YDxAiNP6mfhwW_pH8IllG75CaCzIk1mxCbdOKd4BwftJ9kyc3Yk0XPkcH1JkagmV0NkQ_iNAG53sbL5vut0VH5X5hhNZ2rk-F2fjzVIS4JRxpCRg1A7o7kulsfRjJ_ONXKpf17CXb87R1X6ZZ0aTYzFSzgjVhltxssMccRUA5kT6vE7BDcRZyo0DHD-BDSKV0sqG2D_BdvdTBSw3GghwPwAOXXr30hO2fe9VR9C6W20Y9Fo4NiM4UUyEfv7bGDBQ7jV8LOThb6xUi9yNC1P4jLdnYwptdNVrFEw9VN1Hv6S8ec_WnnB8pvvFrecGNKMI0apzhhQg92MeGY57111WLTkQhs8o-zdyWCma5-5FiGw_NjwNJm6mbh6WjmLmFA6pJVzrGcjfvIDl_Z9qMy6OEK8IWOwZgTtNsIQprfahfv3kfwqkPcng_VwpMt27Ac1p46C-VfqfuUN7wMUvU9AKeKzQKhRqT8XG-GJIPy9RE_iDmF0OogyD17GSWU17AYCToFWiaAUs8-X9JIkeU8W6UTKrRXttWIRu1mUm9f2pR6DfiO4DdJ__w7kyaI_mrrHtA44_nJs_odpOcpoVzoweuWNFEiNmKh5lKr4perTBFSeILYA_HG-MpR5TVib90N7tKLbsOctYjbfJ8MqBsOJfw8FxSxJkbG1PvKtGZRmUGnlRhJKfcYk-3Y3FdRsBCprobLJKzzZpXPsZfRpfTwBCzR7zjPUNSxPavXu-27iKiHRmB4J_U5X6LgZhC_1bnCdMdC-BxxGd3mm5rMZ6WFTQpEzj3WJdXvIeMTfLarBxrHnBH6aXvOg4HJeop_lbFLiBKYZlNa-7C3JPEYg7juHCWp0B-GEUr4mBOD-AX1jWxgPUWGHexSE95E9yS8BoBhZkOT6bDFYCyja109xSDOuMsi_aBleS7soyWVCn3UHakl7tQsOHYrioXvHz4bpsYfLfe6US8XifQ7BE5h4_ESvvzw4tNjOOUJCjEq8qr_6wFsUhiG0lk3VEbuQBiAsPFBPbXB5yMyU2aRcQYsFPLKjAhdbWohnJVxkZoLrUfH1ZoRbAQKmkJHBj5Sw0Eqre4zD60b379ObTqFzKfBRaEfu7KQxzE-CKR8K_XD3vLfXUUq_8i5wO5Jtw6fh-tVUPk-E8FVDCb3UVjNGWIGQ1rcNOEDtiD8uRgXQ76jpthx29TYw21V1ZfTwzf-OOk9CFRWnUnqD5uxEDut1vdP3MD65IItf5NbLelVKmYOWvn1VKMQB3tsmV2qLixwdPzAv3q_Yzl4uIpEZH0pdod_YUHxdTDAvd4llo99POg6yF_fihK6Ig-5Gthfi8eJT4_GMC3_z4e9Zmj6vPdKMV9gHfS1H4XD6cAwpAnFSEFKsETiVn4fjwo-ulxMVUhOyVrzp-SimZecvsD7rBiJYu0SoqOY-YwPTfqKiUM4_WfLdKH3t3ZvP5rrjTjaGqlgacLy8ieophaTNTVn2Z3dm-rqjNs1u5Ldh3raTxXizUd7c1uSIiMDDpERr49QsmW7_yVEf-p6QSHslbZEkYRm0DmaQB3vrXh3UdO24R7zuAwe-DfyCUU3i2Jn0bGH35lDNOQASUfBurQ5geQVv0w91Jjzs8lRCUPS-i8cVn11-2f_97kADLpmYQRq9k0fymO_Z4F0S8eM00_m38nK9JLnZkh1H9u8Kwzf8FgxHnrypM-kxK12-tUX2XUaipmwxhTY1uKuPdvQP_zoM6wLULhfoVXhyiZmloJ3lbb5FFpgus2YW-g5x4EGZ99dGcXGqilV7JJKLhfQp_jS5EjznnxeKgdoTloNNFTjuK3SdRMtRhsrBGGodZSqRUt9IaZNTL4dO1HarHcK8pc9-KPRXh_CB6robBj2MBpo8dv_0R9Xm8alXlAlzrgKZUsOvmYHCm5r2zIeL8jswNopn1j2GsNtDVbjVfVD_lwPG3g9j5hAWpepHEQ1gr9gt4aFPwTVNkSbx2bk54gQDfHtAWHtnZwecH8Ryg3BRUM3InzHRKralLPypIMjuBsNCNYU5xQIouQH71BZ_2onO85TPsA8XfmT9P6Eq-yPM4QZJEmi1FJE05BuldEXVC3N-HtIpCzw7peKuBTNYOk4CBHbuFc4fsUwLBp6gZCfj6Str8VaUkZ0qOMKnAvWcm5iyqXPXoMBm5Rn5ge0PQZKBON2tYVRsRl-wn0ahyXILg9RF0T2rfDwOdvoSqA2yOIYy_WcIpbvp7ZJFCrEckHq4DsjRI-GfHPoMG00zG9fIOFAtbCWxtrfDjq7oxQwAU1vQinA43v-a17blZyB_gnFr5u-yeNWp-VtuCEu8cGInE4-5wl7BOrreio7Kj07nVXiDPsh7-9_R5o-rXh9weyCQntLIIi_r5KqqdLzDRWu4xRH-OwQhYPmOdh1ne8m6JvMAHXkMNmxhx5SAXqHq_OUjP1O1H5ugeZHI9agmlusPrj9KTAcDSwFU56bZkGoTVUvUzWrvhr5rN1O1oXkPlUSzY-chmFGNig_kA9-ZHbWg8y9gEKVEVbxdtb8xl81nWp5iBbdbV3PceOYXOw4AoLf28vNdOhj-OGpwYIW3vb6Porfhl1syKv9X8FFhAyMBe2wLwRSw54XkMn0KbSPTdT9QHVlwtnVXoPlNx7ioVac7kVj1UJN8Vff9AB7ysU0UVXv39ZrYSoy5LwLoixJAx0jtVPR9_T2Xo65Wv2gbW3_hV7cuZ5_Cxr6R7dFh_IHzqPavQFTyiw545Zux7fQqkXEGMz8Og7pXetBYxLen006dkcHjrXLHIKt_dBqEbOhW1CfVvliKdTDH3QSCUQsMnPHamB01387Hw4OteTPKyG5fyhIii1tJ3TJ05ephHbRfWmqnOsoOE6alckLdBVoIzdXnQ39BKgdtkphTwAzDVVckXy-aI3N4sxzJXwDYyftQxjVtaMW51LZpAzDw-ma1VSJ-hDDRDzKJGapJAdtloedt9RmK7CY-zcdN_C8131cf1XmbTIcLOnlXxkDKnyJ2gc7290wyIDi2LODZwbRjPiCZ-gKlQEueo83rvrs7-cpdmrgcFbRnW7XXRPTL2OD1kiKMhZaE0NhCz9MVZs_OcmUUNcoMyZStOjYZm_pEjtZJg4KS6VQffeI-0Z64eBRm3nBWJugAH7CAfYqetxFRFwfJzISjTfoHYt32OP_KAVX3d6UY0epYu-o9dTIf5dotAv6adxHIt8P3_b5apccaCVqrAJBSmSRSkpkwU4otnx9lYKoONTgyJQIdtXjmcNT6uqH9FbVqzoTyVijmb_UVsMLyscPzQQOMeyLP0cewcwJsivbKirDneaqPfkBYA0_eJQnjMlCnSxdUX6Lvlv63mumELS7gR9kYPKw-bY3lTk8DLAqxmrh9PVg90mmyuMBn8p99Iu7zmDLSWZjsTf4iUGfkFqcMzvhHmVIDtr0Asdhc4QjiqRW0Mvy1juWA8MW87Yy_4p4zLdFle8MvCSgkszEqB-DXV0b6FhCsAAZtGoSE_tavpe81E9yJ1vDEbDt-0kgS8DrO13xRQ3ZkGprmlT9ooE0zNI7nVFiuxFG9Il_RbtCgnM7T47jkIvVds7KS-SD_gwOOmaOj8vYFUpGBxpj_0LcQyg8zhMYQUDJoOBLQAeMmmF-Fa-73ZLuwwYBYqhQsigJGoUIoIoDmtptIfKPoiFsQwfpEaSdTfsLe3B3XP1r9jqTnPvM1pqfi1dzAmNu23QOWacfXbkaGxuT1BMJKIk43PCZF837G05U-_EdsUSfRFwMqRPMTqUvInk-DEEKnruDp4rBPnvs5Qkyjrao75x5io1Udjy5Ex8O03_W5xXAgbrb3C3_fmTXKskkE7m-NTrEVom7Sn0qK_sd3t7lHGpJ4NJIS7NkmWyszR2IJID-bwsIFV4Cz9com_yJ3sw5MR5cWRnFO8mkoS7Ea_4g6YTb7l0ahBPw_okBHNbwc913JUx4x-mjfqr5n2BUStyM-ZuU1c_GG7rX2Uy5fGiO8YkUW2Mfj9eA4zQSR95TbxomCiy0fNeXNbgy8nV1Ezomzm2tkX98750xYWXj9punOvjWbn8oKSB-Z8tValhv0jVqM4rHFIV1bEGIT5oFyU-bb1TxbFM9gnA388DttdeRwnbJUdwhF_jB7LgwOmNUYNBtE6c14GcasKOqf791biTg9JYpPykmnO0sDzGDz7XwwV1dUptCWRlUNOPIbkLmOs7I33CUMAtdEhgNCa2wPX-zT-teOYr6XFumO1s9dNRN6OEaV_82ETUaYflSflrrMES9Rrw2Z7u81WUfAgpy_0bazDGqbXKcWzicyprU7wdK4Se2Lj4Zq-uQnI_w9GaJjVmFIbc4uwssHf42mkpqfN3fxGZoMSGs7zDC543iorZoKKpdb5AAAAAAAAAAAAAAAAAAAAAAAAAAAACA8SFhoi",
		},
		{
			name:          "MLDSA65_Base64EncodedKeyIDAsKID",
			alg:           jwtmldsa.MLDSA65,
			strategy:      jwtmldsa.Base64EncodedKeyIDAsKID,
			seedHex:       mldsa65SeedHex,
			pubHex:        mldsa65PublicKeyHex,
			idRequirement: 0x01020304,
			iss:           "issuer",
			signedJwt:     "eyJhbGciOiJNTC1EU0EtNjUiLCJraWQiOiJBUUlEQkEifQ.eyJpc3MiOiJpc3N1ZXIifQ.ygZ6a8F6djuzMQJPRt2l2se8ENuyYnn-t4akkZ259uRsyTNTrN8qIN_Q308L8Mpj5XDS-33G2NTEMk9PxZs2xshBUq3An_qc5MdswidqAc0qSi6GOF9EtEqJS5aUkynQQXm64xLwdwhcXtga5XyT0TmvwH2Ajv2WCKCI6eZMv1-WePbLa4T5obViEdZukYo7AbiB0jEe0UH98mguLWdZ92307KyMB6NxYWX9yzjePcBLyyqp1g_dkXfRy6qMkgQ5VD0l_RZQSX3hRs8sYZimQGCM3jDFUwVlzM4TzjugBZcYn6InQ1husVbPPU7nmMyM70Pu5F1L_tnBTrkjtoRMA0yQmWI5Mj2iyaE-br81b5rBNmNxCIuAerj82jbPJOAP1ei5_kO_ANlx7agjVZUGiW586K6bGhIthOASezDsBU5K6Y9_UyPP8QbYDLHJiNPgWX1cKFKHFbBva6bB6xAuhMRWszXb4M2rd3DLQw0TATBLHda4wIcHarw7ZAQUCWoQiJ4v8CBqZV9B9yeJkAA2giI-HvJ4_ayBa7OwMzgiH7DtEoZapniIgRT31RKBApel8Qp_jnR7t_ZWv59AelMhfxwvA6KjgLjRx3uXNhUZFpoAGYoUJTF-TONzhnEWrTnvOghdsbLji6mXoydE4vat2rNHxoQY3nuiQjRJHkocPVta9ge1J4FtbYgdLzjsf0bcm1sN4biHEvaDcHY-Y2iTEDUmwfB4hsA1oTHtCHjV99OOL3zuAfVRSzWZkblaL1o9umgxc2dCsZx3BFB0OYZQHkfzJUu6hiMCNzp2cIkilG5besseZgphj8oBe7jD_PgowQRpPxbRTtsrddrH3mem7Ok9oOg7O03Noj90Y2M_O9fCfqxAeiN0ZiVR1stwgE6vvbfuUcyQ4dhW1ZQJZ_6AKphchG7Xc7c5EY4W9sjkEDVjnpMT0gQ4RsU4B3VglmqwlMK3Seg_XX2Yq8i7HC523fpveLq4Z7qVrYkDTrnYBUOj1I5Q1o2eEeKIKG5Cw1extrKPpdERnNjiwpyNyNN0fKlKyG6ZewWpj7UUWmVid_tDa7guZ33wV_h2Qcz0bf6Gtf-teV-gEWsraxqx4x2Ts2VWOIdQucesnk1yzduqApJQkwaVa0tK2aea8PzEZY2gPqjSIsmtxlvMBsrwfGL4YuhETTi8nyYZWZJlt4MKuDsjr8MtK8Cl257RocojliWr4l5vbEPyfYpXvZK0UNkqArX4Xgdd4F291ouvnhqVnnuLWAMnXmFP-HE32QluawW2WNtvCHtjg57YqFHOcCIb9pzt73r-aphWS_JK75c1vcpQ1flwnhNQnV25WKA-FwAMg5m25VFKPBpham3DzdXQ4Z3VJxfiMptkCOE-QpWUl_4bMwmqtOhu5M6U4Fg9HjYoEGuW6TBiQ9jFDBAPQAwnqQO_tkZ-aNWtYcsCd2Es7Wu6LaglqBiX3owOBfsfLDPoY0TnzIWdq_zJNdMNFVLXS8hen4YTKME5cziHu20xSjx3u1t0_OuRGbkN6kwMFYt6Bk-GNKP9fNLFoFSdq08hzhTUKDNLTPa2CsA6GA8aNzOKI31bH6COxGcPCBIG58auEtLwd9SoHe_jtVc0z_aPB_13tnEhz11o9CQzDzl8MzeEm0pY88sKndV7BLLBpnOrxx8Z2g5KPqN4QNkN_DnrdpDgR6MlLm7TDCsXkxlqDA6hPHY4qYq-a4678Vtj1gNT_XWlCsZLiY0Dv-T4BH_4KkmDXAulogDlV4OGqwOY2ga7I_28ATrNLwHWrH9QL6hLRF9bEOVm6_XjMxBVthfz9n3PdJk43ve79XSxzSglYuqxr9saUGt8TNQ1Twr52FKOSF7tp6vcaUVxs89CH-hWQTfWhr82-6IL5WmHfC5XeTKOmEreZxy_a1Xrt3Mo2s4npb6pN5jEO1KG_bhvzoN0zBnyJTJPgjKZsl5scYP5dfT6Z1Xo_M6YEhd825FwKBL3bmeqe94MvYnoGpdYYtkYAR4ydajxILQMrfFWrBqIjqhrabT-TVkELxlK_Qf33fsmvGQBhJpyCbYfQ9fA2aqVUNz_lbvbBAmEZSVoqaDTLTL6CkAuPUqH4i52NLFDTVSUUiv6eYxib3tJPV3pplFl3QafUAS-c0DVjXqExKBjfncFME-eM9VfQORVkTPc8bRSAT8ZGZPrd4kyJY2QPY4HHyya99SUnmWv4JJuZfFRdkmoHwGrT_lqZgCfyEYAEGKhIoARVVMa4-GH_9mIUthK9KvZPg7eompar6PCVv8a-euMlnL2grS6DfANYnzeE7nz4yLWUIQ0V4QjPyQFLuDQA3jTeRFHetW82bozix85pQSFtzi7eT9r4x7kkgwBzZEwl_PVZydie3LF4IXpLct615395t5GXXhUi8H4Pwg6xrsNy6FRMKcuR7FdezBhYh6qZwMZe7mH2sa5VIWk2IcH4q44bqP_6LGNfZzBm8f8wOJtEfZCOxz80bt3mHwrOMTzrOkyIknjwNU9tdJvNzMj_nGVbzWBUZo7etJa0SE7408KekD25xHgiTB55T05wnZ5ou7vLz4mMYXaXvh27M-V0W2AWvRXBhIMdQYfSuyO28110aV-4SO_o0A0lBTbMjx0IBAHclW-obo4lnkA8neRahldO04DOIJiP2XIbNgj7thoM_jmHLfx35A2H8YojhqX6QimiFCtkViuvIMccWi_7eSU8yhet_DI2iABYkmbMAoBzsWo5Pg8jXPXISV4UmkWZZtBo6G7CUHMJtDMapLxki2-kgD71fQtks-wsZ8BGyrewZbfb8o6hWl4juJF_L9gqZ7biadK7MtiCHFIKCmQA5-V3iAiTO-XVdcPQKNP99fXu5lX2IDxL8qtFzMhzNb_poP4pjCz83u4o7UinJFeFdNj6mJEvTitN8BGyyg61ctvkozcpxjGJkDVTNe3zMLtlhUnV3DUYqmsUVV_wzoQGzZmrRntVtOYwa5SYlPA93OhEGze4zAFqTp2wAfgPxRvMR5IFpXGpg6xsIVXPr8a2pV37MbJwIDHwq8T0ulb9MpvY_H_C_ZzhVJx32y7LWAOlR4kfLcmxe_UE9C2ZDV0GJA3b37rgumMtIan-656NlOzyLkX1zEDINPysnwr8UF7fAWepCLp2FhpITUCXP8uSfql94FONhhitLOKy8E7vGY907T6pZC45HKSnI6UskuDZjxLpoaBfo7BPf0FIS4XXj2CNmFyd_66qcFObu0z30oNa9tENWe0Hm-sXGORm4LojdDJQ2pjSJ3wm4n6K8WahkDsaDsX02L-cYMJMqnN61ivCRL8rC9QC9PnuqRUECE5VgQsLyG2_KGrqegVre8itl0VjehmyHUbQR9kGKZ0UQ16AKJdrS-K9n2UvqPx2AOXANpY5-WAYg15Y-NPK_Ul5B--K1tMLbtndiSM5BiX2gRyH9-_vIcpWgmownb7JZQjIkdxAVUkjfsKoWJ9LvS_emG7x_eDyNiseqiZFk4DdjYpPjUCX1OU25nmOgNMtblS5B7T_WYAe9v1UO3mTdNkv0x4L8eZ62ukP-6eoYXGBOazPIfZuy3SdeQhZ-Dh12oirPT1GfgxpQUQYL1xxBSWs39kwS5F259Zw7nj_QwZm7WE_C8mNVAhIfebWHebYWlihhLmFhDrwCJD-0eL9gz8TIs8Ycv15MVzl4ye3_i1tCC0S7l4_nOA8j_RvbGsL3a9vnd9O8bQ57-WoNdv6NT6XHbpgv6YDK-FeRcn-KfV5C44gLPlMSfyHa2e0XkzZvrOr5vfdaDfcWyvgY9XS0TX6L_H0Uu5GtNz4jCqDKM7fhIxk5eblO5Gl-7M1hT2RjbS_CFdZ7pGjVMPCe1XdaaH4JUe3Aa5rjcWUvEjCVJTd6WMax9rF3CRHSThXCSmvXwIFcmXRHelIMrr8p7B1f8bYHEVfH6sPca9opZA2dE8YYMZ6t5Di_v4bnAJy9FWVq-NRdA3-JWuoCYJ8hUXf1A0qMcNF6IQRga7uYFLt4d_4KDyBiPuzko1GSK4CJsdprU9m_2hzBVym02BkKDUlLwImlGcamq_ImiqeV0i2tpHYYQ_yCXWdekb_IpW3G3lmAXOiFfHsXoHTARwGROAL3D6WlNY8obZkBbT1XMs6Mpj5--U_hZsH6hFBCuVK4OpfJVgrSKsNjAEfl6efbnPSpBL-hh_-_mJgnQ52E3ykktvVR9zzKZr_fFJKFa0F8l0sznjr2Ot6p6-iKhRWUAZw9JDHsi3_BTDFfUemJybrFHnrrA95_YgDx_FbrK5sOsIIsE2YQsZXsg1rSjT0RMl5x-DyiOT61xTfh39SukNp52TA9U0RXN2kuh_g5awxNzf8S42dtXWOImUs9zt_QECQlStxh4sVai65-oAAAAAAAAAAAAAAAAAAAAABg4TGiAn",
		},
		{
			name:         "MLDSA65_CustomKID",
			alg:          jwtmldsa.MLDSA65,
			strategy:     jwtmldsa.CustomKID,
			seedHex:      mldsa65SeedHex,
			pubHex:       mldsa65PublicKeyHex,
			customKID:    "custom-kid",
			hasCustomKID: true,
			iss:          "issuer",
			signedJwt:    "eyJhbGciOiJNTC1EU0EtNjUiLCJraWQiOiJjdXN0b20ta2lkIn0.eyJpc3MiOiJpc3N1ZXIifQ.i65HC7qxH69SB4jbuDovAGOFa-I1VU2pLfIlo32AJRAnU6vcCyD1RP9f_WTY8ui54djJrFbnW_y-hqsnDZtyEe9FcwKYvrnT9o7iNZTX927P54seC-oxed8UcVC6fOVkjc-_Lwv-tRds6atbtCRsGa3S1LzkyW60rdEaqDgYb_OvkNs_fdGIGq9vvm5F5YhfD6KGc7O3DXeGqvgBHIlzdIlPJfy_l0OiuUiuzvjk2-y_WeRP7guWzuvPUN7b8PZOYvM45GpmnImG98jddL7JcoKSpEZmBPyPyPyljWk6kWkWrKoVZL64BQ0cXizadR1HyU_NIywsgC2KH2bgr6dfYmyBSS-XQqqa_q2gtA6culq7z3kk6pdK0PhunMT6ksG7eSmck_cuUNyMnAb3tdPjQxL7VVDJ-pD44BqojRcEf1ASCmzhwQZhIEYtoiD6FJ8CPruUnbWh-Ic_XFro5EuETvl9EF1iHzqbykGhsqYUVQl4uECMgNuuk_pSsyfyJ5o8pmhRO6W4v-D1bSVEcTsjzqIqFYHC04ThGEPb0ZgvtG3TpwhHPmwtJ8kXEhmEBKmzdrOq3r1CS0jjvS0V_5EB2GUvfnv-aqNdTKxyzBBMmtNHpYl97UJXgx6a3YgGwsJBHVHa4yAYjteykRF0sNETrjgGqp4r3dXD0TNFO8y62S6SvfZURLSXePk0iPMPoMIQuIYIBwdn69qvsv8TNGndd-EHXnfTX5KEbZP9W1yDmtTbmBO-7PPAlWacdaL-wj65LOksu95idiyimosVMkd3JvsNiosh_O2YNN_4wl91XX-ROcKSvqTy0sHF_t-hHutTx9hwmTgxzw3yoiij1WyUPMXw18LxHZJoXa2C-rHVIeGAJCpQ4tamZuvhcibTdTsnPwai5wtGU51SO3ClSFNs6xdcQHh089UsVU8THKC0_1VWR3phglupu7D2lbdq8J_GQRec0XsuYbjhL0kYwlOdSGgimWyhKm_tKYgzqbuZ-ftmz-S6LGWDGfJtwJdS_mvwdTU166ryUp9n-3rzbhu_RkWUog-6moU5qCXI_XPLpXl_lFzXzU66Hw_i6cTHkxaS-OcMu1sKlcjydycbKDWW47xFkkUwFKVvXVoadX7XWz5veUm3Tbjn240PsxlUWnr2e2HMgnPBmDYi8Iemi7d-h4Q7K8gWZ5zHg9uVH3k3y6ybqVXasE9foALEYTXfF7CyVU3Toj7hRCETbS3yUibyUI_0TZ8eR3SQq8p01_BCZB8FeJ2AeP0JpKKKDEIFtlj9tHAj5M36A_oGcDSe0udjuOUTe-tNtJoltazaqmlOKq8OvIYrvlLIaN2KPCCcOC_N5mr1knnYyISl2zj2z3n1FahhOxIgxGPJ10046q-h0FB5ssAGl5qnWs6kviq64Xm3quUfwJRV5qkmZxR7Hh4azYk4bt2pLhU4J3W4q8WI0QS-hvQRs9sYlyQr9alRETjuuaUiR3bUsQ7tJrybqrUE63Q1q6JDf94vg6oy7179ULDia9W-gDW9KEyNs05Myj4m2WKoR2C7hzlWb2xdjcHbTymTfyCCCZLEzE5oxyLZPDdxp-LqSiNbWb41o6hd9BYc690WvyoE-Ek9kFx8aWzZj6c9vckmBbDmb17D2jX-2wZo_NA3rpcpYAvt4FZ-90Ou3MRwA2C7OkvyQsLaAfuX5VounKUhhyHuxYjg1tXJtg-f6st0eIgn9xayfKMao0k4LljukyQGthIlu5yVv-6Z2QhIqgfwUuummAJIa1Je_XIxQFB5QRIEd4Id7XeknvfqAC5PHKuYp2Co6jLNzbqa4ko5AG7pUQ6ToF7FPq8B36_ojU3dkUxPHiknDqtiFKitmnq8x6YI5AsiKnwkuQ7kMSXV9F4_wtMjghUbGKcEBiHKO_H0DYhV8k34QalGl6HtKDC_2AUGy0342oXD-BQpr1d1um4fdTa_9FCMMOlXvrWc2Bqc20eq274SQ6ejFv9eIKzWW6_8BNobZwEB78iwTILgi3OnRHeyTwnLelawPHkaccgOvPcRjwbsRk-DuUJ77qNuEjs9lpGIocCkSR8osccwe1lWWaxOdJ7KnEcl9dQrIuXiQBWtERF4aSMIawEwr5fKkLFLhPWHGVki6wVjYXgC194C8DjKyGpvL2-w4VAD4ZtyUaUjJPt9Lp_SFP4k7cHcrMc1oUpuf4NToxLzG-K_mpP6X37ynWWJOL8JtJm6ZSo-Qe-Z_GND_AGLKRWdv6DFVGuTzhVMHBOM_EAkba5ZmJhx_Bp86-Vmp5v2WgtZWRKhO4rR-m2BQa43G_jRMa0zjd5oL3pRQIweGBwQ8HFERbq2yPM1wqhk_kh7E2qOGtJI5_eudjh-D1cdk7fgsY_K22wDYPgrb2H5pmF3bniVdixLezIP0NMTQ8n1gO7ar-6IlYfGrKPS4gNBhjil10m4MiImhYrDkYYmQOLq9g5v27EzBSBh1N3GfE6qoFcuISZaVr77-V8tcWYeEGz_KP5HGzhz29buPB54pAYgklgMQO4dVzh3TtiIC3w_bHLmBiVSJm1b_0LoIlakWa-EzXDo6Cm2e1AMlztTh2lUIPR2KPvZ7ff3j-qKcCZUY_z4LnuIj9-ndw_oDNZDHCME3s0UaKxitMSaOXCB43D5nW_IyVFUvgZZ0YuIg6cpxATpPs3dJSnVKBBVN_JGiH8ye6Lm69K_awc8vRpktcP3ZhgbNTLt1k8PG-S9JFGCSSp1O4lissqE47Mj0tspyGKTG6fhEXzDT8HuYRPcBPiHOdjxBCn4KZZE34_zFVFzWQcfn3zc64k4vlBadj10eYrs6aFf7Rjvs5UjfrxhQbM0Egjok81BATKqjqHo9TF-FalbhPowmaKtoqi9q0aZVFM__-e7y2fn9JjzSsNUdJdXJbLI0Q-T7MauLbVd-M7EFL-RbfOMscvUZ34uKctMcyhT6I2mFbQeyASU5SlFsaUzayI1WZqXpcgOWtAhfLo2A8XeQqEv1qU71U8fqjGhOEPTIAgxXynKTbL93pSSpUDptlHlCOvDVqF8sdP_CBl8Su-0hxKM-6KK6oDAA0kP9s8FWfgXMMQZ5kG08rFhm45gB8FSX7_NFHTk3xufkE3BRUD0-zRET5bJ0GQuN-lk6OvlCUPAo_3I1OWX8sEQFjxGZf7It27opL-AD2TSjXf5y8nSU_dGmTOo8UfXxmfDoLA55GibGr5auLMrZRt3Hl0MKpDX1etMUu-Bzpq1kR-B9gHT2LK2Ed0UII-NS4FFuHRHZo-4FpeMvsrivC2cA92Xj2yJ6YLWPkxNsaxsaPSjPuzkVBcL2CG8rqXM2Jp9xFJAQlO227IQicIIGDAZt8h6omxcwy3jb4hJVqZjb1WObUfUi_WjFokyejzvRiPtN7GCtydsIt870YbGY9aw_56MQAEXYLSv17emk5o9SAzeyjO6yIcz8-PJSHD3zXgvFiXv4RKLN8f8nXvtITWPVO0Iz9BY0U8FRRXSjWFw7EV6zLiJZiK15WReAiGcgODsGYyIz2B296uw-VYMNWtNHITA6wMZmyx356rBbL2SBzXFA0rhhnMXXeM_K80tlzoaasqzcR8wJLcuJ1ah8040xhXx0dit3X9bzD-5Sxcc7RmOV_uThU-ei1fs1I1EknJhRqT5K5AT4ZMhN7vKJDSvcvy5HlKRAvy4gu9qfpugsKRQh42Fg3v6gr8X0udfcFi15K-q9YOIHyz9pZE3ViWlRN4DJp3k_49uTUEs8d9OVVEDZxpZtnzOL5JdwaQjSIMblT_Jrmqhs3_LvjFlEbh6EjA8iCpbICfA8oNcTuAG3sQm7-ERypaYthBqQND2Ya_dc15Dc3IXMfNWmnRB7-eJTBpwdQqz5TQWde_MvhpBrgrTA3hANGy1IXV01MUoiLSvzxex_M-oxovR1KrwaVO4NDWSgsXYoAApeUrDu8JeJqQ8Iz3TWkuzUROLiMgflakyw2Eufsml6R3BTcgEG3jtYWh5ogbpH8tNAlvJUDYVxk1p5znm8RE-RVCvgzJOQw3T6ZjMvDf-_hBCLMOA63_zmHWl3dBr717hK7IEIA_bpzmr2givozOG38JMIlFv8Iv3Fs8NnUgW7N0mjyU_OmwGIyWz6DTUd_BQu-eMzx2poMrP55GBCYggtXRx0Lofgjza-nbKb0M4k5ymC3j26h5sdwKPkFLEcWaposT6owI05d_4gN_-LYwa8NV8AhPoQVXiyXgG2RK4M5I4tigkp3otNKyAuUb0TvKH6vk-zI8VeuGIrBoySEMoiVuUPfUAnvNz0OEVpKfhlDOnRWg9ZbLEm7sNXqwMD5mSEyNLlxXm9XoHsy8TGzEzfZm44ujs9aavw8zvCiZQmuPnGiE7RU9pc4qXmcPxCEKz0Cb0AAAAAAAAAAAAAAAAAAAACxAWIiYo",
		},
		{
			name:      "MLDSA87_IgnoredKID",
			alg:       jwtmldsa.MLDSA87,
			strategy:  jwtmldsa.IgnoredKID,
			seedHex:   mldsa87SeedHex,
			pubHex:    mldsa87PublicKeyHex,
			iss:       "joe",
			fixedNow:  &mldsaNow,
			signedJwt: "eyJhbGciOiJNTC1EU0EtODcifQ.eyJpc3MiOiJqb2UifQ.gzMgXvYKDesEtx3ocSyv8OfdlOv4UrsQFHkfUb1KJO0aQfqegYmmS7PRAkA8-j7E4YH48H2L_yCBJr-_W2Fm55XZFR4llmKBhdF_duagowjyjIkiax9iutWys4K4rz-luDD_NCow3AEjgizgc9nAKPbpJvpTBiqiHG9uu7JAvDiQh1ltuuvlicZ9A18grzyCy0vjMG2EyolphAVtwzxo1hDRuSHmxFiMmQvdLT6wInJ_TaaMgv3YlyIiqeBv-snuMxejoacumGqHUZ-r_q57C6IgWU76ddw4VkF1eb2-3yxaVwSrHp86tq9oD94tTlftT5ijW9GBCqBtRIv9JJYmUcRnUcvmxFjOQt4tst3_cwyVuAawtjC-rkCR1suvksTG8ulc_7C35ui07divgqA7O-gn5dhaFNA4fahHCBounUm3YJUTJOyVoZttOHd9hHjyTiBUFLJQMnGxmvePaB-FvyGRyc01tpJ_gqAB2skqS7SAqW4pfy8ZHFnRScT5CwZHKhKqxl06e8i585oc63AwxOik1kKv79lgCog5sQyDKF-ylGyDa1JUgs5PEJEf-_6LMmAnT5JYOsruFIfwM9G_rJY64l-Afflj3i_Ng5NE8c5pjhO_0GX7cet-31C_aX_1lre8H0V3qLybat_4pEthQW9iawJQcr9l68xT6hUdzMAWPnDuHHxjyPOtrs-M4N1eQJctyMhyux0Mvua3J1-hFjer7SFKcFziAbR0A78lbG9y6PKv7h9L6mK98Mjvlqb82Fy5Ud_A6hVAXricOzIew-NxRN6ypntj5FFDHqlZJYpaGZwave3qI07CD8jXshJNmk0t-myaqIBwnqgZfpguhFHueCApA6DblK3hjJMt-0pvwM8gEZyYyNc4yANlO18TQy9HN4HSeQBBLtM5Db1UoSQAjd6vJUbaaFwyYmKXPiynZi-rzifdmkoXYGX0xKLBBbdS7kepkGFCEIiLWtXNhWPGEWmknkUQDoVgSsHxikyIyPcVR_KL-yqZ-E31RwTovyKcdQQvrtuERzLn6YWB6qMywVU4DHtM0x0dsWLvbvS52ilpwaFZcMXwm7ZftRP3lxZ3aGwq9PjPqJDd4svnCpGWng5lb8gPiQWXBRuUyfNuoWARYcyZQF-fABndg-C_xfraJqAsyAEgrg5rF2tmeMV2WbnR63hI6AF-nkb2jg_kQA1WdxC2vcwmtdZuzFhtkg6HRrtsLiwg1kFI9hLzncLo2u7gUXeQL7jwZqHUAa6oiVd2sbrJ95IQfskt5JKAD7--zJjxEwCH1_sYU9kCB_oOVfLOs8kj_kL9I5l5XFyT-JY2O8kXK-v7NA7W9fAjghRBqCDyF1-E2-julo7sptr2vTGy609PGcPyBK4R_bivSVrFenb4Itjpv3CAp0cfIwnHtlXjUBSfJ7W5kOR-FhrdQ77UwDAS0tCDfk9D3Ac19PCb2JQAdaeHIoo5tShnaqBEDQ-rxUIH7hqAbNCvrVuOmKZq2YCr05rWs75hUy7dZQ_EfeGqNkazG2yR881jTXBf0dXuA7LkbxLkiKWnTXoryvA2mQW8F_5qJUeYLdV_Ckznv0uYvCiKVB-6IhM0rWoG0gqio_R-kQkTVElZSpMqCH_-E6mO1EnPo3FUH8m51nYIfMdfuP4-rOvrnz-LJE4ofOifd45pnFCvPuSxI8GULYl7gJNLyIX0Envrc-1MAX0w1Aaq0RbnP6cLqkK3j0HWjq_fVbn6zPZYr6plrKD7oToygsZ4VBqQ_Xy2P9csjTe72YdIZCfQD4_d7sNtQIlpTpgDdIkz2bG9vOPy34mULK6SzgUurU6vj4bHd3m-oJr4N4yKLMHjdDAOPsoGUrLocedIlSFJc7iBzpWwDPHfLzXtV0-VbApvYIjsreVo0D0FOpcXNoO26K3vnwHwzw4tDTa11sG3XZDIESkNNKFKvErin8QUUbFesB9Ebqy0RuzgbBPyqh6Si1Q-wS6mYHzFf2pfKzbYiGI3U5dKjo_GvhCd4LHGi6bh9RxnpJ8CSyoQnt_1stRgeX1uUIjzNU_n0v0dWplqmYha4VzI0kzO4ME0h7MZS23mZBsBo5EN0MCt-DvoJ7mLt07He6735p9KAYlatUMzAdNj6UZUMykO90llv7UF8DE-nFCFJ2823DkchwSmF_qrB-QXz9C2Zvsl74NWddWmmkd5-hlEXN2mLm2BgtQbwdB485vOBoMOWvPSHU3EZyQ7ivpjp5fGSQfLnbUQDZtZqDZEBYsAMRRpwmH7WlTzQgrlxg9WsIHkbK3ff0C9y-axGgMfVbSOcspDArGLKkuPwWczYNmtR8SyGL8UXUQGvwMDDpdQ-lgjjAhEechJdJ_NtRuPv_dKtxE2JfrT_wAYRKF7jsyXbvBijeFqtsjyoci0Q0d-X46qG4DG-H_7sDrePTPFTlPM9Q8-GNY28Bt5kMRe5ZphzRCSuwLTBq3w6XUm-yPzo-reVR-5hYTIEigREa9tvTtMl59HljzRqouUftwo-m3kjlLYdAJzQTWpfSX7qD9NA5o66E8DIsXZgiJ_agBy9LWRWeB0yp7lUP9vDEItD-YVQIMk61CLVwQHkBeIMTI6qqRv-ZT_F4x8GuYbFNJUD6zc0K7EXurATEYHgso4fZxDIH0SH6-b2vfEpkLWY30QJvF8C8z0WswXECoPHx8a1DDYxqVUSmSKGNnKyY6MSecACGQ-I_7Chm9tu0wnuVbSKcHAvAC0XW-MvralI_WsOUj-H2peCpKpxpmlkJbBsez76iKGIEXfkmkHDJObQXR7OnbtS9YC-ZjRjXtnU8XFvrnOzJFc84n0wNOrU5tin9DQTgCBXlr22YkcZy29uvNsPy3sqKWaxM8KK9voLQcY8QP35wpBXS7dJ3HHDbojlPT2wYs1ivxvAXvXeyFlZ4673DQ-41rGjOhSRz9JBTEPt9zjx0_5U29dZj0Fh9wFIpx52gXC3wGUJe635blt9Os_jNmdd3uRXkpj-YtGucYETsvp0hBwA0jUQilnB5DgZ2L70tOzvEQ_lX2f-PsFbIm8awTwn4eSBO-RYxCkNYarFBrbLbv30rX1IOlOez1OKCtVxA2S_TdBF3a3qqA8D9eawLKkPwo9Xm1jMXiatyvcR6NOKbV19rnPd8iMkmsx57sAmq5JemZr40a9luUK5z7IdmR3I0NQImpCURi41t0KD1mHESWpxnFRWXQb94MySk8BwZZbpqHAdpkxj5q0ylk0U1GbTbsaK-rkd29GQKl3RVC2lXxIqPD_Z2LPQH8TC4-8BJPBb3uPI8ZXg4Ci28VGxCL8xe1tHvEc_qdBUJR4inxUoUD3OcTFjHrNWJZTcXbemwAU3NsMDEU-mmdITjz5fHvIodKkqIneyIh4TtxxyPnc5MOND-QuJXmlAr-5mLtVz4LNoGJaFdn32qWz8IcCI4huF9uqQrR2CLVjR-FP5hjV9Z5vEA09bTz06SFWDBO3wfczfwWgn_DemSIutmCHEZ65rc9cLh82E_IYbSO2Zuyl--PYOrgBCtD4xdRN4T8U3MkfO2KZQlu-A_V1hwrEvesnvMcpX3PXXYBOqWyAG0DTsduWVVUNCs33bU-yh4Xo11WKPXxjaj72Jk7TfmbE-oH6r7aYVH7fDA4CAjo0VwmV7ucTTiKC-uMot3Lq_LPXlkaP51rVpLuIpwXgeJUvACMrkgVrk7U24jYPVTdydhQc3rsqlwJgz-NSi4Bu8Gio0XXK0Q1NINN1dxk3hXU0l99g4pK_rUrb043n7XmU-LYnpezH6UICTDJYrcLM8Z5CozmKjeiqD28G87WVjFpwaQTXNSvfVN7ikQ-1Mg-XcjNz2oZPN_U-YvKrke5lca5YsjMHPllBxWVqrfIJLgHvr8u6AxiKtYV3S83jraNpKZ14s8rzbfAKA9DMYDBrvpaAEjB67y_1odhn8sDFjQUmc9sFHNfNXefHFqUHZTLGv0LyS-sKBLIducmHrgNY2ZteDa1WcmYW1oHkxJgO0XrRqCaV-7fR4lOXXJuinFzBWVUyO9Gl6iKCdqAyYeUvvYAdMyFovonQVGcXhPOh22MLyjeXTW8iN90IAs8aF2xpof-D3Vz4iIKBAeu7oVuahA31TScgzISFt4OgPMHgY83903cK8OqcCTkqjFr0mbriru0h0FbtMTzPqZ3ijMqiVDcXWFwq9xpYiij-wQLmLTk8cRWzzB7HKcmq5UkYSCP_0C2fu4t-WiAV24NGW36mS0DCq8FSS-n_RodEbIpalBRE3FYfRQCsDa-o1Elnb1-kiUVXzbGHf2544j9kZk56iETGgw5SHnO6wo7q-ELhxZtpxsC3sfYTo8ld4O_kPu2-gi_iqB-MAgwgCN9Z0MHzwpLF7mRQQFFNcDlyQMsBwvd07ZBuiimvZg0ZfID7-EW8rX1fz44gnASpxJTbBsu2W2s8XyH3LoCJFo7dPg0xQKvznZ9FAyiS1DRXvVF7n6923mqraxE5KJcf9JOGdUjRM_uzhT_B0-QfH5bujyerloicos7ldmn51LYPiz1N3Cbk1Y_wD4W0iWb7SC7BfgqPXDMz7Omeij0CKYm4lOBfMRJ_-hCh7_lrmZHe7SOdesfgD0l1TuWSQW9tTgFEu78uO0t1C0OBwAyh2tc6ehrsz5efA1DMcLOnqpK5ldWvvNS7Q0oT1yHBsF_PS_Iw--8IZZD6qOPr9jNl-8NlOI5VZI-ULgz0YwBRSZhj3jyBIBsrG3jJksO-Zo1sOMKswW88mpdBEOjxv3mvYdrYEL4iOlvRs6weUgIAOK-nqnrQMZM3gkOSrKbyCvsv8FeUwC1uMl2IDjMXdZAUjzxKtj_k5cEyZUJAB4jVaom_PrwOKz74Vwf-ov2OVSGqln8pqALODKJTXN-SpS67Tr8gsAzG-W53csvffwJ48I9c7_ndUaC6TZJ-oQBmUBltaIXnuPWzlDOtXn_6TIWWvmU2tZmj3svOtTiYEqmYqxab0L4qCrH9mPvOylST62WFto2TNwflJOH5s2neTcb94HJx3Oug46n6v0ND998CXXKyVGFal3ETI6P9Ww78nTQ77hwVYZFXdI8aOENFeoi-hiGRZhcglKf_0zRErCkfY2qMVN-XImJbmaWVcmdstg6iU6XlpozMgTXen_eO63Yr1zjGIEo6ZXDC4xGEocxtmifhQqqPC4HEhwpyhHGft2xrf_MFUvqmL4wVoDOk4ofjhYcSBCTPtDM-N7ApnKtn43yXknTxb-2eejrwoEP7erukfzKEI00Js3TnCcOJaP_J8Kq-7nrdRg-IvvHfUlBMKXu7jeXL77vNa0Y37pPljJwajQcgLiSkEEeD9aOLUEU2dLJ5jWN0v_2gMnQiZSNrpp2A9BpMesh2lUAJ1s4Z2c7gyu8-AfZhLVW28TwDJEp2GqJELfY4eOuRw3jO2ZUynhxZDHI-X6AUvB084p1jX4XW7cCSdRBtC_nh6QNDI-dvLoGrZHy-yNlOtn7euSC8pIdtf-5tMP3I0ChEbKdxhihyX940L5NKTqKGGY_n22S6m3oTiAkaZtIm40sIdyrmeBN3Qb_jy9a9KzsAKt3uHwFOsub9ixTSm6fW5df3-9FmqrK9PdRlBuIMJnPGEx1Jf9Z-fgCs__jaPA2DvB8JcH5wJI8tRUZF3qSwlgAOCX7jNyCFbFyiHy2Z_sr8gFrt-EhSnzyrFj_lFeMimPp6nTNiTDk_xSZdDh12t4DAeGaLvCZvik6PyyujL7Muw-rJO3MXBynjHovdH4iOnfq2fyd7c7bwrchvfkmHwFaG-LQSarFJjxvJ8LjRYUYc0kQUyd7MsuMPUvMkaGDsNL7KJRQDvMxB5oKgUI1mvCdf6muoTUZrDzZ0p6aphFpqGttF39TrIp-IxIWLO52nRhfI2RobfJ3VanatdoF4gWraVHJY4a6rjjLPSRMGBvTYgyYUKVCx3a0M9EBuFpVShzZSo7PayWSrIaMNNbLcBuSO_TDWdSThiQv5FKUPXTmHZ4a_6MRqi04oddp1RV--tWizXYJPzQC3Ce9b4lmHEdH5vcG7nokm5ncsvbaXCpoVGS81vN_q8gEQZqnIycrLzw4RIjNBQ2R-jsH7ECEqKzE9QExml8ErT1Zcn_AfIiswODk_XGGTqNtZX5CXx9Pi5Q0ji7__AAAAAAAIERwnLTlBRg",
		},
		{
			name:          "MLDSA87_Base64EncodedKeyIDAsKID",
			alg:           jwtmldsa.MLDSA87,
			strategy:      jwtmldsa.Base64EncodedKeyIDAsKID,
			seedHex:       mldsa87SeedHex,
			pubHex:        mldsa87PublicKeyHex,
			idRequirement: 0x01020304,
			iss:           "issuer",
			signedJwt:     "eyJhbGciOiJNTC1EU0EtODciLCJraWQiOiJBUUlEQkEifQ.eyJpc3MiOiJpc3N1ZXIifQ.jELM4WuhNjtjhvgMGiwt-IVU62cp43z8VjunjLHX5zZH-fWmW1dOBxONW0lbodaddPzyGZ3fyJhqMfGGppCci7Gnt3iQxty8xZDYgy3JeVpxn4ieMfAcL2hkSQaFu3X41WDbV2mfOkM-p7a5dFP9b_FPpjzEjt9o36dRntwKqcqZ0RR2EIAw6s2eAm4_co1RtsxhQvsz9dg8CO2u4UZwnqAW29fh5dxORQoLr-Hc73tD36sYEeD4iBqNcWGd0GTc9bhEhcbVi811AbpThOEsh5B6Su3RJUFD0wZZJTrY1pZeS8ekKIF2MjiTDq8-a0MMIwGHOFh5LJNuBwwLdDdPCNEbme4Nxs_sof3_jhvId44g_Jwimj3JEv-0iEKLGVl-0tIxy3eOi8o748vczpgy3DWI96WsMFI8tiLbUl96lLGOrFeRjKfZGNocNUTlOJ5Mw-qKJxcXjzBiM9F8PPmRB8BdAR2qXub77lXYz-FNuFffaO7P1CPxWp-g4uiSaXxUt024noX1nY-7dH2YGSWDVMul8-GLQee1AID4HTXaonBsntpr0fulR8ZTye3pM9BqhfH6UYwpE2gBPJmrBCJRTreT_zMUy-M4klm9ivTGLIoqcphF47ULMJQrKeZUotZ8vhQokZvKKwh_fWi_AaVZmrS7zBaOWMymCtH1LM7afjbDvilhUQF7qowvcXGUhfe-njzAiIrRw5rvxbgM-7u7F_fp5fYzIUYeCibcEWOPkm0YZ-JF2vHU1booMLEOt10VwVccyU-sTwtQkq5q297TFxgc2BIQV1gRXkf92gCbitY2zS5dUsVFI-FPSzkjm7janYMK8fB36_6icDG3UHU86dMBngF3Xa9yHhdOxHamilzS9ZLTT64FS8HWhJHv6T3atJ3f5NwTZaLdEeZ0XD2r9u-bpXnqGdI8J-feu17rKLok_fylj-nzfAz7qlSAZPi9lKs8U68U1Ex26rsZyuWtJX7WhaIBa-MNj4xykPVSvE5vAve0ix7yK8DXocJDloUtoZGVxEWqrTJPFlJCH8rCKKGQPc1QkOpjxiq71e0nzJvcUFdpxAdApNlwDdOZJIDd8laugCcVqklRcdLAT2nch8WJ3A09Vt-i6rVfHTvfJ0mO9O-5kh-B0MLsSdLa25JjVivUYh6apsMZwP0ypDxiWkEVNvBjUm0etAYpKtyyKLjPIedyvIT3TMQnEXYq6Q9b74_xV0QzQvbhYroOaCkvnR-vP9HWwdJJztMJ8gXzGzWJIHffSUEh6U6-03RftPyI-uIHU9IIXsgTp-JPXBK8U5E-to9Oeu5_cz8WERevSSuM_NZa8AMoTefe913abmOWWwY73hn376IzlDBPiC7M83Kq-TUyF9alS1zaWPTY8D--28rLdWhKY9DKUFj7jXu3ztIkMDB1q1fjlsNtpJMkSIpgVzKy5ArZZkUpEPfjDRdhcfWRSDYxP1U0ExplRRijYAVG3obZr6CSofFbx6YLOfbCsynIcOVp7Foz-xR3uWxUqYQzFc-fs-Hy1nRRaxyjBR9rlIgeJ2nP6tQFrT0kTpd6llX0vwvGoW85rQnktmnP8uwHLsa9eIyJ2smmqTfoCZDZaPaPZSLdgoHSqoKjhkgj6da721UjAe6O5F594womUYqo7Co6c_Q_8MXnEPBcCeQ-r2beWTQqvt-9a39aDluX6CM7WZCyKCVd2hEb2bBOSh-LlO7YSBVqE1F_7iI1otv3Qq-BY5emLxBOSTnIv__HwY_w4ee4iXHAkWxBpuDqp6ymn0ieI5M_kPwz290jMDL_effa3E7Ox3g1DdCerb_yn5m2yrWJJC8Ec8P8cGfSawtgQT7aV2b5P7uiUBrwfZw4u6waC7yh0mwD65wv7FOdb1d9vJ6V0EZNRrhdiKORNxO4tleAD-9lhXRsdI80LTMnFG4Ix9q-w1NVfHwu8lkZCdD_JQBUXulZobi453jo-J8xrTVrz1gPvNlVX0ScsZWax4TJkC9OjpRD6znOIuq3mFXGgvJZXpoh1Jzy-v-NI8-JhO6M8JA9O9JQjagSjKuSbryxvQN18RJIApcg39nDN92ff2ar8uSYE45tkOLFvMZfN2HU78T-gdUKpJTrXWUUW7REyp49cQ2nnVa8OPdlCxWPMBMccV-oCN7383RGCx0Y_eeh49YB9GH7QKNlKHriGymMsobznUthwYifiKe_FYosaN8-A2Pt5nmPKHJDBA6Olq4V-YNmFfIUCiH0A7jLJ4LVY2QQzQdJqi3ur8fOMDeH9RnihNh5GEB4wqwxf7RlJMxH6Ikt_eWpbUMISYXlABtP2skDW90_iN5DlNG9LJjIG1p6GtCIp5RdTwSIA95GhF1TvOHF8rlcaMggPy9ZIBsKr9a6duoij7_kZhI1hovTocbyshBpbizRKCfpQKtirt4yFTnJ7GCqWzIOCzK6tL_hJsoDfHTzjuYgDuGTvtOu5CiaZQXQPCrw0ASboCGNiOnQrWBJZU8BLszBS3fGecWgHjWtqcy748EFjwF_YtzxB7T6zevOaTdEHCcDf28NXB2vh9RAXJMHbUkmweanLA7HBGiQ-Pd82ihnC0Ol2nJOV89P0DkaC6fRUmyGmkmEalD9m-dxSkGUt9K1cuOOmCAIYVWiQS3M_SLGsagqA2WSa0w9cqls_XmQVP63z5McJYhinRhRvdx17rmBcbkJRnCT8uLFOQh79N-YA5eXL4LHvgjxQUO0siQV7Y20FnYSRw8N2NsWcsrCl0GONtAC2GZGa_kNtGkAXxreB9Tz5hsU2NcyF007WOLW5JpB_HNgLEpESeKxF58jgxEDX1exBieGC-kE8ghfGb51bEbc3mHPVgVq5zzD2eqoErMekDm9iajPh65_Giln_2zNZCiTXmsnvEaC3f_uiatthnKJKsYvcgkJ6y-E8GT1nB3pN3AN9VBL6ITXnltYwJJAsYnGBLyzdBIrJZGWKDFM88tN1POBTYYFP-9k28W9ZR_X49aAO8pNmB9VjjlEOGsaii50gz0VSCpxoO20GDaUeeQTRWnxiq4HSpmrahbw0uQysUtCd1RAfdtQwyM0dci2NRkmvvvfDdcCPP8GjptbpnQRdG1jqXeHzfbwp3fJRfcflTCIlwPWYfyYnl2JUrOcBtekDsWmKLaKwTsj-gCyXFVI4cypn8MHgsnJ6BKVfhsKEJ7LM5U7Jf2PN-HX2o7SMFJlU8b9SVxfzcoZevsK7XNMJLrMswnBszsZ-IAQTpjWOsLSMPsymSnnk9BIzA9Eo74Q7vv7VoWRmUdzeiIMZfQiashpWHF11EvLUA3AuTXYqdQwqihrYWr4j3HusoQlMbePH9AFXhJhwszQOZ36Cw-K40h-rB7T-0Y60Nf3DvTclXHZFv2ZvDvkIv3g4w0kmHE5pk3WqGJrK2mHaBQQpR-aa6oQm1eTHthJhq8-xO8g5YF5y0qAxiBxItmwosxVOsVl6onCVkbqYFi13eMR1JlYY9LATbckSPpEUjrAa1fgmAWBBz3_voPXyN99hNYPvhozvOF-O8D62lC7lpq-JvmjTrPZ2PrF6sxLytDHhZPUoMfNmyTTJvCzNWCoAePPrYc-0vALTCYlikJsWdWSh_So6W45vtTjOFzwPKkg0A3Ee7x4zb6GWgDXbwsvedWh1itKsdpiae1lLw6bJyn9R-ng_3P5aQwaLd7m1IF4ZVZ-9iqETU_zAJBEp59lOp6PIS69QNPxLh66Mc_QiGh5ONZeLHtE8gSOcKIGveTEvlqtlfFqzn5Gjhc0wLejRMidZ6BEB9oN-lrnTZV2hB1PpT19hmQiyAUzU-TdopJD3-nmznakBq9bUnvjk9WGi0GfhB0UNzIA_yHVJTC5NlI0FzPQoTBXdRm2w2FjoI665wP37rBd5kURY9rFTAnaJt5rLExRwLFX291K3wpEOlm6Hqs29p5H07rqI3-P6Ar0WcnIOgkmoI9hLA979hxITzoiUFa7kpduVMb94fdk-qg83Y6Rhk7eKZEycjVp_6C9OZ4KvB4gh_WsmZr7xhAedbdqsGymqO9gfdYgwveTd0xFrzJyQLad-12W-ADI0pxXWu8wsKRqz2cwtgo3Az38TB5zfqajxqdH_OXc_W4ZUXFL9b2roz8oovuHBfS8rusyEU5_Xsu1_gvYOlDDpppTEcmM84LQvkm0xqefgoOe0JPPNHsR07c2zP0I9TrLh0Pg7dmCKgMx4VtFhKWucV8xR9dEkNvGbv6OQIFf9OdIiLz-zjU5_WaJJaBKvJGeXlJne_sYYeT8VNvxc6nM4aIPhIu40EnkOKiyweG2PXe3LoXdQ8Q4KnSaW4bI81ZkPYzSyP8N3-oHy9NtPACgWNeFDbVG172FUduiVqtqbIoNJHL8WgoM_fSXUsS3R30BmXmL5Mogj_t5YA9c6tf6cw5Xei9fjcFFMRgiCngNxEjGDxMorOwoR1dIivw3Ayl0b7XUUF4cBcsa3792-UwqiLZ6LSDMotBm1N28TJe9DfvCMkKrHMWAU3vRkFyhS466Odezgd8bCmMkdIkGlHNH045g2Xg-GVicTbdGE4BQyTZJTxW_ZJiOe9oNqLB1tN8B2TklTZHQ9Ke8-nRAx3k_QuV1IzEkEewOLaMNGj8F7HyZcCpHXS2bgkQ9ESZnj8PzQOAEe1YZMeJMa2VyR2ZU4Ik_X76g3ZhZyW-T0hMqcXIkv7vm4O0-hWzKK9neHCKnamO4wKwPxQjRvnVjQUoFwu62M1W-zxi6qPmtR_5dz__1cl1lQ0qVjQVl8wuRYpeU-d54TLqr5n6E--Imy8pd7wIpJpcZnRRfLMSEBN1OHOWNpY-RhjE1qdBAv6g2hCeazSh0JjUECTbf4dd7-grQ7KqKi0J1RRcZVvcnzNDwxanYY0d_faJt8_JOLMxeFTV2iYF6pZw6OReV5VJJs259KjdWr_XtL1V_ejIwPRYlbdpEAaJ8oPQZgk_-dON4a004a8OYORENE7FBHtmRdTYIo6u7gg8GZin2NYsEHtMbh23K9uFfYR91y0v3bZJgjH5Qordt5PwIJCMJ9qt8yUDBy3gUzxlxq78GDulmkeoZjWGkQMrSVtqeYl-mrCsehmHoInAflwg_hqHVuJdw3e25GIBC9Vfyo0v0eVfPKXAzqPEI5c5IRRGc1Xn84JO6rz_4D_9mesa5C0bLv5vx6IRW7ekGYaGMBQYm3IhRGxRvMMxFGjfwAYAwMGspisHE7wIjqGmUSu0Z_ufd0zsOS5enT8Ua8PW3h4hucdCcLH26Cz8GyxSobYLwPvKlSojZWsV5g6GU2wbGoyUPKUibEiA8s7PDHEfpI-jaLItOicVe8ilDs9dSbdSSZaELknlhUtk1wNtphMFV1C-JnzefpdXeBvDD-EdmFnb0LZnXrYK2odBDq8kDlvRaFSZjVA7-mSjM17VjKy0_aKBxEy_GspRW434-WMGxbMIjyk8tvWvHuaXhKvUXEdtw5Q3zzBREHghilOUGhZtCR04xNhrMJK1tsepHdOW_lL0Hr2NayA3CqkABDgeh9mnF5jAEZQactjVK5iXN6ySZDxyWIe9egwc_anVJITa1sr8u_7kuyv5wgct4lKQlXyCkhAFCJP0l01BSCyMmjxqxsPoZmwZy_MEDv3TmSZVkNDF94g5RUShHqkxQwtO2fBErVtBKfo9MotGypHQL_Rf_kRywd6zfhSliFkoL0DHWVUZMqQ6Z7DHcCQFVvEan6Jxe7R1qHYDqB0micpDhVGYEx2r6783enxl3rJtRLf8gSc60izLczi1rQSQVNyqZEg6ua73KHTubsnsBHYpsYIHRnDxSiSzz1CDj_HF_2xHttFl5TGMDg16UUtdD6W2832E2CpvrBGe_6fMiLhb-U80nNbHGWu-ykgy3fMOmg7UtfQ2POIJPZ8w1Bp8-66wYabM5i5N-ZZoZW5QXGyR25xzOzDFNDH4R1xpxNbq99zlX1auC15jb4O1PeVVrzlifgPr0y5fj8g54ISYqD_9F0hDTOr3DbymgVHLdWfVQAwWSgzS1A1AOUEFZLXcT68uRMYmN7VDMy2XqPZReN0Bk2kwjZ3B9goWZnh1RXMgDHy5FaqPW1-Lw-AsdR5WntsbvPklQYNEVGT1CdLrs8fcFIyo6Sk1SaKutvtgKLD218vMAAAAAAAAAAAAAAAAIDBcfJC05Pw",
		},
		{
			name:         "MLDSA87_CustomKID",
			alg:          jwtmldsa.MLDSA87,
			strategy:     jwtmldsa.CustomKID,
			seedHex:      mldsa87SeedHex,
			pubHex:       mldsa87PublicKeyHex,
			customKID:    "custom-kid",
			hasCustomKID: true,
			signedJwt:    "eyJhbGciOiJNTC1EU0EtODciLCJraWQiOiJjdXN0b20ta2lkIn0.eyJpc3MiOiIifQ.OdcPi9lzF5Z_HyDmYeSRjoioU6uobSAuJFVIpLQ_SGqWqtWSZGRczqh4yYDLvY5S2RYeByOhiiVGxKyp0pgWYFekxrFEHr3q_qdZcfbKp3xKC91kYfU8GAi6H2SDm-uOWfN7Dkky7MTOAAXJ5SheDNF9mJpP06qANwJeMSm11pk-aFpITrjNCEv8GGZP1EJb4tzE0eLGqp-ZLSL7MJp1YZpxs1QZAIR3JuZaJAwJ8wxxvHsVDxiknf9r8i4yPG9QWqF8KnF1N25XfxJ2wvokS-kyTnioqvi6_Cxn-JXve33dQh8OULm4sBVzNRBWRW9OrFJnDLwuGEA1asRgS5-3hF4ODwRnVtev-AEoj6JDUE6qexqrR_g5VDDEk-Brbd4KRT4fBNdFNorwaUSnbU1A3D0WrfDQFSwWvsM7SJUKhM2HzaINiomz4iFgoffcqIaeN-gJJGYZyjnCkpxOxSFWsScOVu7v9D2kbxtgMMRBsDSS3kHnNt1KVJlHo7rNPMNv7prS_JMlSMkji3dSgz8QCSOYPCp4RbVhwxulD_ppJhFbpjg4UJTA3iMI2DORdmrd7ixzef3Skb6t4Lrk8XssXCfhr35ZuBd3gy58YeRmfpGLSj4E-Gf5Wxx6QGn3MsPthL3kX1Wo-KtvGHUyBypq23nCAd0BUk7RbNIWOwRdyletsYDAyTOQc_x9Tf8t3OACUhjptVJa3wKI49yNUgOof9StEgMRS0WjXe_0vBMVIUXwr6zdaYWTM4Zxve_JRBWgKwWYEKvV8lKDanEpiyVmj2lZgNIP6Z4d0w-JYFZ4-kUB3-gj-fuzGaYW4aL6v5Dmum6uxcVDAI4fsfvBypw60jx4fYZ7065CfF4hfruUUgOBkOIgmOBn6XbYsc2JdR09hgq-CUFJWq8pDZHZ7WLDvDCXTP0CWSiLjBhEz7q8EDgSr-5SMVNk5h53v4oWsx1nHrSCsOAKEijAI_n29UEGSlVEsFYDfOWVYtfchkm6FFtTMkWddDP__WDtUf9snRRoHKOLYX2awx4RbCe5UpkL1kVBk7q58Cv4wrJ9syXxhrOVw33GziRog8YXW5sVqhn2ZbPvMxGRclSmATbt0YFzNj7KZQfZcBTCVwHK-qx8CHxYL49OEla3my7LbWNVilUaU_x2-xjn4STI7qC5jcMsxQABsO5sinj35yr0tjiEsgzSdK82X-6RtqX2La_49dOkzkLLMpScCTlA0a7iQ0QoeUsF1dHj5bAIolgtZTt0BTlCLBQpPSOgwxCK1lEoKYkTHXbbPScQ_h1mWyyBo8dLbqZC3tcqOKlMtvLnsmAJy2ovVEV0BbTAg5wz83MnDenTMt1Z4Gez4NzrGowr7byo7BxUtCN8_Yb-h6zHmi7wun5qbSRBPleKLYzdxQt1cIzrK-TzS7U_T4K3qf2SFYY6Kz4lw5HvAE_jPc3hVyVMsiQtpHXBMvoVk1ej07mpnTdmtJV21vt8_coYXGFZCewWK3J2E-SCm2t7cvDNUi6VcTVFraDJPniIpJUg0DU7JHfwY-Fwgi4LO81m5JxwHW3R10F4X8KHnCLYEdGGDYVstHy0isIdeJHUdGsDgQJ398hKowsM58rxmhoTbNRQtfO2rj78pHkSQXTtxd7TH0T-wfX94qTJPl6a5mNw2efxYaMQkGOaM88TfGnzgzxU3fJ4METgU-G8wr1P32rMfYqXIVSd6otVdT579wGtbQuviliBXmToEAXkd0miPJBaalmIyy9wGbtKZXaapKW0aulOSStsPxW02i7R-1Boej27zEquBGfpxX9eLaYD8YJF6R1LTP9siN8Jbz3nXdArGJ7gH03FqfLT9Sg1bCodl6kYIY5bTH3n_ai_6Z94gGEC3lcZtzIYbxnu4ftOiZln_xnys13lUOuZDCmWFSvVQT5hV690-UJY4Vwfl3ulixDX5es6grKCQDmK7SsNNJbknQwWcPjEsasIXFy_G8JLTsCZlLdZSZwj9BUv3e2PaHlJGOBMuSh1Nvv-fyMEtBW6fmuJHEopox1gbvM78Drl7VoO1cjvpefKJIEJHurau4pAWiVpnkSNLWP4kqJkPqnaehN2qZGa64QFsrqGL4wZVpvZ129PDjuFNo0yxxirVm158p-svt_X2WkYt7m6eS5geYVgFfFu-PG7VMS8s05Hw6ERnziwStwNhNG4capnbgIxLmYbP5jhezdshlXnP_VuSJErjHlGBCRgBDy_7clRlHU2lAv9jyN8bb0vm2aBV1qBT-EvI6fCHQMtpD70oCeWUCu3xFpk9nL4F85KzxFFJUjX4KShHETSp_lHGG0cG6FThFklsXG0X1mDdxLODOh2mHYF0eKeHavRIe1LiNF7ZmSOlzvx9sF1ievgw99ZrEqtT10OiiEuamYPkyQNhIL13RDlBBCX7DoDmtFlnAmqDjr4Ohqif1LRiV3ZwNYV6TM7AyZLHa4E8mgzuyT1vbLZswGwHJ0XF-l9PGHfzBChYT3IceF9VBGC2It0KBSnn2--cHNcxpVfWEfoVanBS5im9oHt3R49RRQkpPLnoWBJbdCiB8cgxla0D6qPz7TtxSBn0imh52Yph21Jnfh-IWcXycJbKx_YTnduHV_JdSTKZAmskRFrGnWVQ_uadsJfkwk1nVw1SxMWO-OXz2QGnrGc-idNfx32_bq5q7SDD8GH1aaf4If-K1cxyZ1C1FVizSg_2O3wH0INvFQRlTxavlTiNzvCdnQmLETDsaI210pGI5y6XwLe6RbsiGabWSNrXwyCcTR93Mhx3NzRu0UvKztjDkpDpz7gVJrygle94RnMtQasKUxC-2Trg9HlnXe4SZmY-wI3lS_BgjA5VFJaIqMrzil5960OnZFGHtuDM9VlSatVPiOxioKvne4_6ySbwYdi3tcVCRm5dn13OsIiD0PwwFaK4ZzQE7byl7dO1wOYCyP1zxFHavvKHA4cogwpcUy6rQKL1ePZ1N0o9at-fd0_W9ybDKRT4hjsUnRdLNoka3C_l4xXBKPpvjYfbMK-qYvEs1zpEh3JpRUx9NxyACEpqTyMtK6Kx4q6lZZhSECKfqBZbhyyOVHiJNaaq6F5-BWv1EfgBNdI2-aYBkd7JCxOSNUdZSBXZLtIeRLtOgxwCAAh-1XjcwnsCggdyb1c4x2b0vzl6xotX4iBOqence48rcWGNcNz3kCFZktSaonOFUMBbk9lD3jfgr3QKVl6UxO1TPasMv7Y8yISjb7kJpW6rUUpDbLxSAqIcDb1OZlpZ8eogL3t4zK8cif5dj6RdEhxeAH134Vfkq4Mj1fe-LorUEozD_5PsZlQCbxMVkh9u4-wci_Uiqdxh6WKdY5mdon8_B-04yTlLQAKpExneIuTTLAFlnC_O9hn7dYJgPWwl7VRyK_G-H7CC1x07i1ztiyNfadBp4phvazXiIDnyFp6kPxu18dxCGTnXK34IqloYSn7qAP5q_kFx2a3XqU1nc18DxfIyml-2Fv9oPISasPudPDUybfspP-yk-I2YW26uK6PRCsIyTbESMjYwsJLImS6kt2OS8O5_8PY1YQTneS1Nz0chRqd8o7j8HzzaAkKGn1_5D5QSs0Fh8IH3k9Fd-z-cN5Gq9DNEqc5Ne30ZVejAYOwbx-gBsh3NnzrexG4tk_ruK8YXtBZBtHla4x4wjwPsBuJtK6_HmAeljj0JcjIs594ZPT_2T4Y6KeJmzn7dK5rScL2rTq4sMdSXWb73Mu4ImPQ6BHYg_q5h8NyPwE-oesSmKqVdqufsbyi4jPSG77xcbJggVJbg3rGWp_N6mnLwI__lHrMFOaTLjncLdsMGeWjy07gelp1lu9MMT4hrAJ_cLbxhMdnhT2OmIfeT_tS44b9QTmwv5XLgLy9KVrgWHsu9TS_vpb300qzRMXSi97KPY_BlhwbW4VyXmmQ5taBtVidwF34csHtNutd8tSaMZT2JwRL6C03Nyqwj-A6OB1RGNhoKFiPJq_h32_e9r8dGXKwFRt_z8aLtoopHi4CHiEBQjHMmF7f04RnhYjo-dD_yy0_0BCZZzGqDZ7jzGnMG_O97hOPNUo4L6gKhoSIb6Jtg5OF5s8LTd_0gX0xOM3TeS_A0etLO6wk7oAwBJGJFwQ59GcYUtmLjuf2vS98AnlseJN4AvbR-XxgcfpCxMJcwTb1GCgVvsXJ1a1Eajh36BS8fvKMRFSMAde9lN9l3M9A5dpH4eYSO9JcG4LP5o3jTcOQFZb-VCHUHt7AyFw9me59-8WhFHbrsPPnT1dMriZ_enjwpU3K2TgEDn4T1AvLzJoZdAppn_WcayMwYYBfSA4bapPWQyn2r5wQUBw3PZL6snCuBvDwURLYQkvfrxgfTJKrh_JywRb06V9G5RD3Ivni92aUUhNlcDz6cp6hHhvpdmU97pqSMc-CLnc_mDZMAORpsyU_ycTULIOOuK4GPoQYSEj3ZtxSg2oZ1BZyOTRBJyUfxIIpYzyKhEpOV-kz7J-7fvrACTPL64RplMCJb0gFqt276hHwvMWE5eqwrVBnJCLsnMCMWcNOjz19Ku_DRjUz80Qp8cO42HIq19uVZBKQ2E2J33rEbHc_C6zeflJOPsMvYxG0SdegEq6lfLO7I9GKLWQCuR2NV2YmRJi83_mj6QcO7BHsKJN-ikIyFC0nwIxA61iZ15VlyB4xyzObCXtXdSVwbKedHx8VKd6xIwq8iY2ivDmWLMry6BWEv0r_Kcey75HOM5D48pokyLsOotyFuSWF5qfaVbv5uuOZVlLy7kNgyhtG_ndUG6z-zCAN8Ys3LmpfcKuRSIR5r4MHas70ASqYJ6yW6FTQ3C9dM97X9LGBILnppFtuzFQXYLX1-Xc0DZz-AJ-RKg0rxTh_dIgdBPTZo7fS7JOKJ1q01DuUDvGpOzuxg6w8BhYosTSIrwlWarjSQ4TJ_kzXWv2ED1odNFceEcrh4KSqEif8Y6jKL1S2_lUjhxXhXnTB9iccb_Ucur_DqSsdRREVzS3fLiw9MU_D6ZfJnsOWUX_XGPIQElgDq_nEIswyZyNYBY2aSvljcoxUwfKVvSaUiyaXxMiOx1BAAQTHgNpI0ELoSFbaqyg_bWBNfUJlKgle7bP6nJ1mn8lnoX-CWM98F95217-0efFmXMv6hW-e1um-46m5BzHkAiFZl3waRr16MHLg6uV59y2ph1yMaXYwQtsuVIDQJ_Mfp1FBQY2-7kIy8XGqsn_GYSzTak-8i92wQWnJE5lv9Fg_d2RcCUAE5BxQiMgFCUjtHNYCBiLOdKi6qy9ssZXVd1rMAzPChkYoupxA44RlsA2z6G5WZva6sLpQZm7Bs795vDSbj7qlsXtbWvsnupsH1oNY4idSWVL_J-Q7-ixjcKDTte84p_gmWncsCUjJLg4zn6zQNOpzStOedQf2S4_23dG5EMBBPRTUm8JHvplIZHfvWAXnxE-8xszNrE63vPzTWxqqaXNhdQ5ooey14R2eHTO1x92BOCN5LRUnkwWQJWrDyc8Twwgu156ebOjf76o3sNBTpZgj1a0VPcfbChjhjdaYoMvkBTQuNPN6R_mRXs0GzpxjrW4WV65a4o60aHmsBekI9URgz3yzn_0gAqNCu1RLR6SVdtwcXgLa2TCnb7zU3Mp6zcBiMq5dYcXghqkNkdTCpkFmFpPzUwUC04ScYMglLhNTZVF13gk-x6xtXM26U3tnahSdHdOdlb_j40u66xnMUBTR7RkHolj870MC_6QTCCQ6iQJ3t0B1UI6PT9MXPY4AxM3FjteX_Iwq8b8TT_Ujm3glRaK7X_lNBuHrwMZp56lxQKQw_D5Lhj1yHXJWDtuWts_2VJ88vzDK5_JxSilZ38Otr7TZ6Q13n-GnvRnnWIxvLUbwFj222kN-PximsTrLg9B_-jLhCYAQoRuL0Kxzt_y5s7LUVafbbqHXsHCFrp9T5NR5mG2yoDB6TqSXhtrOk0vmDAr2wMo9tkqv8EbKtEf2ItxwXr_Dj8bJhy2XwEg8I4WJ8mqwn3yYQ5GTICUaNPrHC1TEXyKT9JtqprSO6aruv2Ww64A4R9C42lUtqTGUzLxRaQio5lMsLUd0kN3h_BdGVZGzy9cdJDAzcHV9jrPL3ideX4iOlKCyxMbRAyIwQ0aEpyMoOklLZ37U5wcPGB0oUYKvyRA2RW6v2N_vAAAAAAAIDxolLDU-Rg",
		},
	}

	for _, tc := range mldsaTestCases {
		params, err := jwtmldsa.NewParameters(tc.strategy, tc.alg)
		if err != nil {
			t.Fatalf("jwtmldsa.NewParameters() err = %v, want nil", err)
		}
		seedBytes := mustHexDecode(t, tc.seedHex)
		pubKeyBytes := mustHexDecode(t, tc.pubHex)

		publicKey, err := jwtmldsa.NewPublicKey(jwtmldsa.PublicKeyOpts{
			Parameters:    params,
			KeyBytes:      pubKeyBytes,
			IDRequirement: tc.idRequirement,
			CustomKID:     tc.customKID,
			HasCustomKID:  tc.hasCustomKID,
		})
		if err != nil {
			t.Fatalf("jwtmldsa.NewPublicKey() err = %v, want nil", err)
		}
		privateKey, err := jwtmldsa.NewPrivateKeyFromPublicKey(secretdata.NewBytesFromData(seedBytes, insecuresecretdataaccess.Token{}), publicKey)
		if err != nil {
			t.Fatalf("jwtmldsa.NewPrivateKeyFromPublicKey() err = %v, want nil", err)
		}
		iss := tc.iss
		opts := &ValidatorOpts{
			ExpectedIssuer:         &iss,
			AllowMissingExpiration: true,
		}
		if tc.fixedNow != nil {
			opts.FixedNow = *tc.fixedNow
		}
		validator, err := NewValidator(opts)
		if err != nil {
			t.Fatalf("NewValidator() err = %v, want nil", err)
		}

		testVectors = append(testVectors, jwtSignatureTestVector{
			name:       tc.name,
			privateKey: privateKey,
			publicKey:  publicKey,
			validator:  validator,
			signedJwt:  tc.signedJwt,
		})
	}

	return testVectors
}

func mustCreateKeysetHandles(t *testing.T, secretKey key.Key, publicKey key.Key) (*keyset.Handle, *keyset.Handle) {
	privateKeysetManager := keyset.NewManager()
	if _, err := privateKeysetManager.AddKeyWithOpts(secretKey, internalapi.Token{}, keyset.AsPrimary()); err != nil {
		t.Fatalf("privateKeysetManager.AddKey() err = %v, want nil", err)
	}
	privateKeyset, err := privateKeysetManager.Handle()
	if err != nil {
		t.Fatalf("privateKeysetManager.Handle() err = %v, want nil", err)
	}

	publickKeysetManager := keyset.NewManager()
	if _, err := publickKeysetManager.AddKeyWithOpts(publicKey, internalapi.Token{}, keyset.AsPrimary()); err != nil {
		t.Fatalf("publickKeysetManager.AddKey() err = %v, want nil", err)
	}
	publicKeyset, err := publickKeysetManager.Handle()
	if err != nil {
		t.Fatalf("publickKeysetManager.Handle() err = %v, want nil", err)
	}

	return privateKeyset, publicKeyset
}

func TestSignerVerfierTestVectors(t *testing.T) {
	for _, tc := range jwtSignatureTestVectors(t) {
		t.Run(tc.name, func(t *testing.T) {
			privateKeyset, publicKeyset := mustCreateKeysetHandles(t, tc.privateKey, tc.publicKey)
			signer, err := NewSigner(privateKeyset)
			if err != nil {
				t.Fatalf("NewSigner(privateKeyset) = %v, want nil", err)
			}
			verifier, err := NewVerifier(publicKeyset)
			if err != nil {
				t.Fatalf("NewVerifier(publicKeyset) = %v, want nil", err)
			}

			// Verify the test vector
			if _, err := verifier.VerifyAndDecode(tc.signedJwt, tc.validator); err != nil {
				t.Errorf("verifier.VerifyAndDecode() = %v, want nil", err)
			}

			// Sign and verify
			iss := "issuer"
			rawJWT, err := NewRawJWT(&RawJWTOptions{
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
			validator, err := NewValidator(&ValidatorOpts{
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

func TestSignerVerfierCreator(t *testing.T) {
	for _, tc := range []struct {
		name               string
		privateKey         key.Key
		otherVerifyingKeys []key.Key
	}{
		// ES256
		{
			name: "ES256_Base64EncodedKeyIDAsKID",
			privateKey: mustCreateJWTECDSAPrivateKey(t, mustHexDecode(t, p256PrivateKeyHex), mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
				Parameters:    mustCreateJWTECDSAParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES256),
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0x01020304,
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
					Parameters:  mustCreateJWTECDSAParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES256),
					PublicPoint: mustHexDecode(t, p256PublicKeyPointHex),
				}),
			},
		},
		{
			name: "ES256_CustomKID",
			privateKey: mustCreateJWTECDSAPrivateKey(t, mustHexDecode(t, p256PrivateKeyHex), mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
				Parameters:    mustCreateJWTECDSAParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES256),
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0,
				HasCustomKID:  true,
				CustomKID:     "custom-kid",
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
					Parameters:  mustCreateJWTECDSAParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES256),
					PublicPoint: mustHexDecode(t, p256PublicKeyPointHex),
				}),
			},
		},
		{
			name: "ES256_IgnoredKID",
			privateKey: mustCreateJWTECDSAPrivateKey(t, mustHexDecode(t, p256PrivateKeyHex), mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
				Parameters:    mustCreateJWTECDSAParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES256),
				PublicPoint:   mustHexDecode(t, p256PublicKeyPointHex),
				IDRequirement: 0,
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
					Parameters:   mustCreateJWTECDSAParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES256),
					HasCustomKID: true,
					CustomKID:    "custom-kid",
					PublicPoint:  mustHexDecode(t, p256PublicKeyPointHex),
				}),
			},
		},
		// ES384
		{
			name: "ES384_Base64EncodedKeyIDAsKID",
			privateKey: mustCreateJWTECDSAPrivateKey(t, mustHexDecode(t, p384PrivateKeyHex), mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
				Parameters:    mustCreateJWTECDSAParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES384),
				PublicPoint:   mustHexDecode(t, p384PublicKeyPointHex),
				IDRequirement: 0x01020304,
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
					Parameters:  mustCreateJWTECDSAParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES384),
					PublicPoint: mustHexDecode(t, p384PublicKeyPointHex),
				}),
			},
		},
		{
			name: "ES384_CustomKID",
			privateKey: mustCreateJWTECDSAPrivateKey(t, mustHexDecode(t, p384PrivateKeyHex), mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
				Parameters:    mustCreateJWTECDSAParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES384),
				PublicPoint:   mustHexDecode(t, p384PublicKeyPointHex),
				IDRequirement: 0,
				HasCustomKID:  true,
				CustomKID:     "custom-kid",
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
					Parameters:  mustCreateJWTECDSAParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES384),
					PublicPoint: mustHexDecode(t, p384PublicKeyPointHex),
				}),
			},
		},
		{
			name: "ES384_IgnoredKID",
			privateKey: mustCreateJWTECDSAPrivateKey(t, mustHexDecode(t, p384PrivateKeyHex), mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
				Parameters:  mustCreateJWTECDSAParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES384),
				PublicPoint: mustHexDecode(t, p384PublicKeyPointHex),
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
					Parameters:   mustCreateJWTECDSAParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES384),
					HasCustomKID: true,
					CustomKID:    "custom-kid",
					PublicPoint:  mustHexDecode(t, p384PublicKeyPointHex),
				}),
			},
		},
		// ES512
		{
			name: "ES512_Base64EncodedKeyIDAsKID",
			privateKey: mustCreateJWTECDSAPrivateKey(t, mustHexDecode(t, p521PrivateKeyHex), mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
				Parameters:    mustCreateJWTECDSAParameters(t, jwtecdsa.Base64EncodedKeyIDAsKID, jwtecdsa.ES512),
				PublicPoint:   mustHexDecode(t, p521PublicKeyPointHex),
				IDRequirement: 0x01020304,
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
					Parameters:  mustCreateJWTECDSAParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES512),
					PublicPoint: mustHexDecode(t, p521PublicKeyPointHex),
				}),
			},
		},
		{
			name: "ES512_CustomKID",
			privateKey: mustCreateJWTECDSAPrivateKey(t, mustHexDecode(t, p521PrivateKeyHex), mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
				Parameters:    mustCreateJWTECDSAParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES512),
				PublicPoint:   mustHexDecode(t, p521PublicKeyPointHex),
				IDRequirement: 0,
				HasCustomKID:  true,
				CustomKID:     "custom-kid",
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
					Parameters:  mustCreateJWTECDSAParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES512),
					PublicPoint: mustHexDecode(t, p521PublicKeyPointHex),
				}),
			},
		},
		{
			name: "ES512_IgnoredKID",
			privateKey: mustCreateJWTECDSAPrivateKey(t, mustHexDecode(t, p521PrivateKeyHex), mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
				Parameters:  mustCreateJWTECDSAParameters(t, jwtecdsa.IgnoredKID, jwtecdsa.ES512),
				PublicPoint: mustHexDecode(t, p521PublicKeyPointHex),
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTECDSAPublicKey(t, jwtecdsa.PublicKeyOpts{
					Parameters:   mustCreateJWTECDSAParameters(t, jwtecdsa.CustomKID, jwtecdsa.ES512),
					HasCustomKID: true,
					CustomKID:    "custom-kid",
					PublicPoint:  mustHexDecode(t, p521PublicKeyPointHex),
				}),
			},
		},
		// RS256
		{
			name: "RS256_Base64EncodedKeyIDAsKID",
			privateKey: mustCreateJWTRSASSAPKCS1PrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
					}),
					Modulus:       mustBase64Decode(t, n2048Base64),
					IDRequirement: 0x01020304,
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n2048Base64),
				}),
			},
		},
		{
			name: "RS256_CustomKID",
			privateKey: mustCreateJWTRSASSAPKCS1PrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.CustomKID,
					}),
					Modulus:       mustBase64Decode(t, n2048Base64),
					IDRequirement: 0,
					HasCustomKID:  true,
					CustomKID:     "custom-kid",
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n2048Base64),
				}),
			},
		},
		{
			name: "RS256_IgnoredKID",
			privateKey: mustCreateJWTRSASSAPKCS1PrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n2048Base64),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS256,
						KidStrategy:       jwtrsassapkcs1.CustomKID,
					}),
					Modulus:      mustBase64Decode(t, n2048Base64),
					HasCustomKID: true,
					CustomKID:    "custom-kid",
				}),
			},
		},
		// RS384
		{
			name: "RS384_Base64EncodedKeyIDAsKID",
			privateKey: mustCreateJWTRSASSAPKCS1PrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 3072,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS384,
						KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
					}),
					Modulus:       mustBase64Decode(t, n3072Base64),
					IDRequirement: 0x01020304,
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d3072Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p3072Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q3072Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 3072,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS384,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n3072Base64),
				}),
			},
		},
		{
			name: "RS384_CustomKID",
			privateKey: mustCreateJWTRSASSAPKCS1PrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 3072,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS384,
						KidStrategy:       jwtrsassapkcs1.CustomKID,
					}),
					Modulus:       mustBase64Decode(t, n3072Base64),
					IDRequirement: 0,
					HasCustomKID:  true,
					CustomKID:     "custom-kid",
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d3072Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p3072Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q3072Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 3072,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS384,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n3072Base64),
				}),
			},
		},
		{
			name: "RS384_IgnoredKID",
			privateKey: mustCreateJWTRSASSAPKCS1PrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 3072,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS384,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n3072Base64),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d3072Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p3072Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q3072Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 3072,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS384,
						KidStrategy:       jwtrsassapkcs1.CustomKID,
					}),
					Modulus:      mustBase64Decode(t, n3072Base64),
					HasCustomKID: true,
					CustomKID:    "custom-kid",
				}),
			},
		},
		// RS512
		{
			name: "RS512_Base64EncodedKeyIDAsKID",
			privateKey: mustCreateJWTRSASSAPKCS1PrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 4096,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS512,
						KidStrategy:       jwtrsassapkcs1.Base64EncodedKeyIDAsKID,
					}),
					Modulus:       mustBase64Decode(t, n4096Base64),
					IDRequirement: 0x01020304,
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d4096Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p4096Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q4096Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 4096,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS512,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n4096Base64),
				}),
			},
		},
		{
			name: "RS512_CustomKID",
			privateKey: mustCreateJWTRSASSAPKCS1PrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 4096,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS512,
						KidStrategy:       jwtrsassapkcs1.CustomKID,
					}),
					Modulus:       mustBase64Decode(t, n4096Base64),
					IDRequirement: 0,
					HasCustomKID:  true,
					CustomKID:     "custom-kid",
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d4096Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p4096Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q4096Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 4096,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS512,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n4096Base64),
				}),
			},
		},
		{
			name: "RS512_IgnoredKID",
			privateKey: mustCreateJWTRSASSAPKCS1PrivateKey(t, jwtrsassapkcs1.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 4096,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS512,
						KidStrategy:       jwtrsassapkcs1.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n4096Base64),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d4096Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p4096Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q4096Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPKCS1PublicKey(t, jwtrsassapkcs1.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPKCS1Parameters(t, jwtrsassapkcs1.ParametersOpts{
						ModulusSizeInBits: 4096,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapkcs1.RS512,
						KidStrategy:       jwtrsassapkcs1.CustomKID,
					}),
					Modulus:      mustBase64Decode(t, n4096Base64),
					HasCustomKID: true,
					CustomKID:    "custom-kid",
				}),
			},
		},
		// PS256
		{
			name: "PS256_Base64EncodedKeyIDAsKID",
			privateKey: mustCreateJWTRSASSAPSSPrivateKey(t, jwtrsassapss.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS256,
						KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
					}),
					Modulus:       mustBase64Decode(t, n2048Base64),
					IDRequirement: 0x01020304,
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS256,
						KidStrategy:       jwtrsassapss.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n2048Base64),
				}),
			},
		},
		{
			name: "PS256_CustomKID",
			privateKey: mustCreateJWTRSASSAPSSPrivateKey(t, jwtrsassapss.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS256,
						KidStrategy:       jwtrsassapss.CustomKID,
					}),
					Modulus:       mustBase64Decode(t, n2048Base64),
					IDRequirement: 0,
					HasCustomKID:  true,
					CustomKID:     "custom-kid",
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS256,
						KidStrategy:       jwtrsassapss.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n2048Base64),
				}),
			},
		},
		{
			name: "PS256_IgnoredKID",
			privateKey: mustCreateJWTRSASSAPSSPrivateKey(t, jwtrsassapss.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS256,
						KidStrategy:       jwtrsassapss.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n2048Base64),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 2048,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS256,
						KidStrategy:       jwtrsassapss.CustomKID,
					}),
					Modulus:      mustBase64Decode(t, n2048Base64),
					HasCustomKID: true,
					CustomKID:    "custom-kid",
				}),
			},
		},
		// PS384
		{
			name: "PS384_Base64EncodedKeyIDAsKID",
			privateKey: mustCreateJWTRSASSAPSSPrivateKey(t, jwtrsassapss.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 3072,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS384,
						KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
					}),
					Modulus:       mustBase64Decode(t, n3072Base64),
					IDRequirement: 0x01020304,
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d3072Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p3072Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q3072Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 3072,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS384,
						KidStrategy:       jwtrsassapss.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n3072Base64),
				}),
			},
		},
		{
			name: "PS384_CustomKID",
			privateKey: mustCreateJWTRSASSAPSSPrivateKey(t, jwtrsassapss.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 3072,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS384,
						KidStrategy:       jwtrsassapss.CustomKID,
					}),
					Modulus:       mustBase64Decode(t, n3072Base64),
					IDRequirement: 0,
					HasCustomKID:  true,
					CustomKID:     "custom-kid",
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d3072Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p3072Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q3072Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 3072,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS384,
						KidStrategy:       jwtrsassapss.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n3072Base64),
				}),
			},
		},
		{
			name: "PS384_IgnoredKID",
			privateKey: mustCreateJWTRSASSAPSSPrivateKey(t, jwtrsassapss.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 3072,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS384,
						KidStrategy:       jwtrsassapss.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n3072Base64),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d3072Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p3072Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q3072Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 3072,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS384,
						KidStrategy:       jwtrsassapss.CustomKID,
					}),
					Modulus:      mustBase64Decode(t, n3072Base64),
					HasCustomKID: true,
					CustomKID:    "custom-kid",
				}),
			},
		},
		// PS512
		{
			name: "PS512_Base64EncodedKeyIDAsKID",
			privateKey: mustCreateJWTRSASSAPSSPrivateKey(t, jwtrsassapss.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 4096,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS512,
						KidStrategy:       jwtrsassapss.Base64EncodedKeyIDAsKID,
					}),
					Modulus:       mustBase64Decode(t, n4096Base64),
					IDRequirement: 0x01020304,
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d4096Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p4096Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q4096Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 4096,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS512,
						KidStrategy:       jwtrsassapss.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n4096Base64),
				}),
			},
		},
		{
			name: "PS512_CustomKID",
			privateKey: mustCreateJWTRSASSAPSSPrivateKey(t, jwtrsassapss.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 4096,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS512,
						KidStrategy:       jwtrsassapss.CustomKID,
					}),
					Modulus:       mustBase64Decode(t, n4096Base64),
					IDRequirement: 0,
					HasCustomKID:  true,
					CustomKID:     "custom-kid",
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d4096Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p4096Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q4096Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 4096,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS512,
						KidStrategy:       jwtrsassapss.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n4096Base64),
				}),
			},
		},
		{
			name: "PS512_IgnoredKID",
			privateKey: mustCreateJWTRSASSAPSSPrivateKey(t, jwtrsassapss.PrivateKeyOpts{
				PublicKey: mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 4096,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS512,
						KidStrategy:       jwtrsassapss.IgnoredKID,
					}),
					Modulus: mustBase64Decode(t, n4096Base64),
				}),
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d4096Base64), insecuresecretdataaccess.Token{}),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p4096Base64), insecuresecretdataaccess.Token{}),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q4096Base64), insecuresecretdataaccess.Token{}),
			}),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTRSASSAPSSPublicKey(t, jwtrsassapss.PublicKeyOpts{
					Parameters: mustCreateJWTRSASSAPSSParameters(t, jwtrsassapss.ParametersOpts{
						ModulusSizeInBits: 4096,
						PublicExponent:    65537, // f4
						Algorithm:         jwtrsassapss.PS512,
						KidStrategy:       jwtrsassapss.CustomKID,
					}),
					Modulus:      mustBase64Decode(t, n4096Base64),
					HasCustomKID: true,
					CustomKID:    "custom-kid",
				}),
			},
		},
		// MLDSA44
		{
			name: "MLDSA44_Base64EncodedKeyIDAsKID",
			privateKey: mustCreateJWTMLDSAPrivateKey(t, mustHexDecode(t, mldsa44SeedHex), mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
				Parameters:    mustCreateJWTMLDSAParameters(t, jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA44),
				KeyBytes:      mustHexDecode(t, mldsa44PublicKeyHex),
				IDRequirement: 0x01020304,
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
					Parameters: mustCreateJWTMLDSAParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA44),
					KeyBytes:   mustHexDecode(t, mldsa44PublicKeyHex),
				}),
			},
		},
		{
			name: "MLDSA44_CustomKID",
			privateKey: mustCreateJWTMLDSAPrivateKey(t, mustHexDecode(t, mldsa44SeedHex), mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
				Parameters:   mustCreateJWTMLDSAParameters(t, jwtmldsa.CustomKID, jwtmldsa.MLDSA44),
				KeyBytes:     mustHexDecode(t, mldsa44PublicKeyHex),
				HasCustomKID: true,
				CustomKID:    "custom-kid",
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
					Parameters: mustCreateJWTMLDSAParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA44),
					KeyBytes:   mustHexDecode(t, mldsa44PublicKeyHex),
				}),
			},
		},
		{
			name: "MLDSA44_IgnoredKID",
			privateKey: mustCreateJWTMLDSAPrivateKey(t, mustHexDecode(t, mldsa44SeedHex), mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
				Parameters: mustCreateJWTMLDSAParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA44),
				KeyBytes:   mustHexDecode(t, mldsa44PublicKeyHex),
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
					Parameters:   mustCreateJWTMLDSAParameters(t, jwtmldsa.CustomKID, jwtmldsa.MLDSA44),
					HasCustomKID: true,
					CustomKID:    "custom-kid",
					KeyBytes:     mustHexDecode(t, mldsa44PublicKeyHex),
				}),
			},
		},
		// MLDSA65
		{
			name: "MLDSA65_Base64EncodedKeyIDAsKID",
			privateKey: mustCreateJWTMLDSAPrivateKey(t, mustHexDecode(t, mldsa65SeedHex), mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
				Parameters:    mustCreateJWTMLDSAParameters(t, jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA65),
				KeyBytes:      mustHexDecode(t, mldsa65PublicKeyHex),
				IDRequirement: 0x01020304,
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
					Parameters: mustCreateJWTMLDSAParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA65),
					KeyBytes:   mustHexDecode(t, mldsa65PublicKeyHex),
				}),
			},
		},
		{
			name: "MLDSA65_CustomKID",
			privateKey: mustCreateJWTMLDSAPrivateKey(t, mustHexDecode(t, mldsa65SeedHex), mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
				Parameters:   mustCreateJWTMLDSAParameters(t, jwtmldsa.CustomKID, jwtmldsa.MLDSA65),
				KeyBytes:     mustHexDecode(t, mldsa65PublicKeyHex),
				HasCustomKID: true,
				CustomKID:    "custom-kid",
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
					Parameters: mustCreateJWTMLDSAParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA65),
					KeyBytes:   mustHexDecode(t, mldsa65PublicKeyHex),
				}),
			},
		},
		{
			name: "MLDSA65_IgnoredKID",
			privateKey: mustCreateJWTMLDSAPrivateKey(t, mustHexDecode(t, mldsa65SeedHex), mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
				Parameters: mustCreateJWTMLDSAParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA65),
				KeyBytes:   mustHexDecode(t, mldsa65PublicKeyHex),
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
					Parameters:   mustCreateJWTMLDSAParameters(t, jwtmldsa.CustomKID, jwtmldsa.MLDSA65),
					HasCustomKID: true,
					CustomKID:    "custom-kid",
					KeyBytes:     mustHexDecode(t, mldsa65PublicKeyHex),
				}),
			},
		},
		// MLDSA87
		{
			name: "MLDSA87_Base64EncodedKeyIDAsKID",
			privateKey: mustCreateJWTMLDSAPrivateKey(t, mustHexDecode(t, mldsa87SeedHex), mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
				Parameters:    mustCreateJWTMLDSAParameters(t, jwtmldsa.Base64EncodedKeyIDAsKID, jwtmldsa.MLDSA87),
				KeyBytes:      mustHexDecode(t, mldsa87PublicKeyHex),
				IDRequirement: 0x01020304,
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
					Parameters: mustCreateJWTMLDSAParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA87),
					KeyBytes:   mustHexDecode(t, mldsa87PublicKeyHex),
				}),
			},
		},
		{
			name: "MLDSA87_CustomKID",
			privateKey: mustCreateJWTMLDSAPrivateKey(t, mustHexDecode(t, mldsa87SeedHex), mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
				Parameters:   mustCreateJWTMLDSAParameters(t, jwtmldsa.CustomKID, jwtmldsa.MLDSA87),
				KeyBytes:     mustHexDecode(t, mldsa87PublicKeyHex),
				HasCustomKID: true,
				CustomKID:    "custom-kid",
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
					Parameters: mustCreateJWTMLDSAParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA87),
					KeyBytes:   mustHexDecode(t, mldsa87PublicKeyHex),
				}),
			},
		},
		{
			name: "MLDSA87_IgnoredKID",
			privateKey: mustCreateJWTMLDSAPrivateKey(t, mustHexDecode(t, mldsa87SeedHex), mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
				Parameters: mustCreateJWTMLDSAParameters(t, jwtmldsa.IgnoredKID, jwtmldsa.MLDSA87),
				KeyBytes:   mustHexDecode(t, mldsa87PublicKeyHex),
			})),
			otherVerifyingKeys: []key.Key{
				mustCreateJWTMLDSAPublicKey(t, jwtmldsa.PublicKeyOpts{
					Parameters:   mustCreateJWTMLDSAParameters(t, jwtmldsa.CustomKID, jwtmldsa.MLDSA87),
					HasCustomKID: true,
					CustomKID:    "custom-kid",
					KeyBytes:     mustHexDecode(t, mldsa87PublicKeyHex),
				}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicKey, err := tc.privateKey.(privateKey).PublicKey()
			if err != nil {
				t.Fatalf("tc.privateKey.(privateKey).PublicKey() err = %v, want nil", err)
			}
			privateKeyset, publicKeyset := mustCreateKeysetHandles(t, tc.privateKey, publicKey)
			signer, err := NewSigner(privateKeyset)
			if err != nil {
				t.Fatalf("NewSigner(privateKeyset) = %v, want nil", err)
			}
			verifier, err := NewVerifier(publicKeyset)
			if err != nil {
				t.Fatalf("NewVerifier(publicKeyset) = %v, want nil", err)
			}

			// Try to sign and verify a JWT with the issuer set.
			issuer := "https://www.example.com"
			rawJWT, err := NewRawJWT(&RawJWTOptions{
				Issuer:            &issuer,
				WithoutExpiration: true,
			})
			if err != nil {
				t.Fatalf("NewRawJWT() err = %v, want nil", err)
			}
			signedToken, err := signer.SignAndEncode(rawJWT)
			if err != nil {
				t.Fatalf("signer.SignAndEncode() err = %v, want nil", err)
			}
			validator, err := NewValidator(&ValidatorOpts{
				ExpectedIssuer:         &issuer,
				AllowMissingExpiration: true,
			})
			if err != nil {
				t.Fatalf("NewValidator() err = %v, want nil", err)
			}
			verifiedJWT, err := verifier.VerifyAndDecode(signedToken, validator)
			if err != nil {
				t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
			}
			gotIssuer, err := verifiedJWT.Issuer()
			if err != nil {
				t.Fatalf("verifiedJWT.Issuer() err = %v, want nil", err)
			}
			if gotIssuer != issuer {
				t.Errorf("verifiedJWT.Issuer() = %q, want %q", gotIssuer, issuer)
			}

			// Check other verifying keys.
			for _, publicKey := range tc.otherVerifyingKeys {
				_, publicKeyset := mustCreateKeysetHandles(t, tc.privateKey, publicKey)
				verifier, err := NewVerifier(publicKeyset)
				if err != nil {
					t.Fatalf("NewVerifier(publicKeyset) = %v, want nil", err)
				}
				if _, err := verifier.VerifyAndDecode(signedToken, validator); err != nil {
					t.Errorf("verifier.VerifyAndDecode() err = %v, want nil", err)
				}
			}
		})
	}
}

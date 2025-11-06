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

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtecdsa"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapss"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
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
	secretDataKeyValue := secretdata.NewBytesFromData(keyBytes, testonlyinsecuresecretdataaccess.Token())
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
			D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), testonlyinsecuresecretdataaccess.Token()),
			P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), testonlyinsecuresecretdataaccess.Token()),
			Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), testonlyinsecuresecretdataaccess.Token()),
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
			D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), testonlyinsecuresecretdataaccess.Token()),
			P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), testonlyinsecuresecretdataaccess.Token()),
			Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), testonlyinsecuresecretdataaccess.Token()),
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
			D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), testonlyinsecuresecretdataaccess.Token()),
			P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), testonlyinsecuresecretdataaccess.Token()),
			Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), testonlyinsecuresecretdataaccess.Token()),
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
			D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), testonlyinsecuresecretdataaccess.Token()),
			P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), testonlyinsecuresecretdataaccess.Token()),
			Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), testonlyinsecuresecretdataaccess.Token()),
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
			D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), testonlyinsecuresecretdataaccess.Token()),
			P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), testonlyinsecuresecretdataaccess.Token()),
			Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), testonlyinsecuresecretdataaccess.Token()),
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
			D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), testonlyinsecuresecretdataaccess.Token()),
			P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), testonlyinsecuresecretdataaccess.Token()),
			Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d3072Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p3072Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q3072Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d3072Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p3072Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q3072Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d3072Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p3072Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q3072Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d4096Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p4096Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q4096Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d4096Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p4096Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q4096Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d4096Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p4096Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q4096Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d3072Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p3072Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q3072Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d3072Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p3072Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q3072Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d3072Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p3072Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q3072Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d4096Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p4096Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q4096Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d4096Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p4096Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q4096Base64), testonlyinsecuresecretdataaccess.Token()),
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
				D: secretdata.NewBytesFromData(mustBase64Decode(t, d4096Base64), testonlyinsecuresecretdataaccess.Token()),
				P: secretdata.NewBytesFromData(mustBase64Decode(t, p4096Base64), testonlyinsecuresecretdataaccess.Token()),
				Q: secretdata.NewBytesFromData(mustBase64Decode(t, q4096Base64), testonlyinsecuresecretdataaccess.Token()),
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

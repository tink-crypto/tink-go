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

package rsassapss_test

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapss"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
)

type primtiveTesCase struct {
	name       string
	privateKey *rsassapss.PrivateKey
	publicKey  *rsassapss.PublicKey
	signature  []byte
	message    []byte
}

func hexDecode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex decoding failed: %v", err)
	}
	return decoded
}

func TestSignVerify(t *testing.T) {
	for _, tc := range primitiveTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := rsassapss.NewSigner(tc.privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("New_RSA_SSA_PSS_Signer() err = %v, want nil", err)
			}
			verifier, err := rsassapss.NewVerifier(tc.publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("New_RSA_SSA_PSS_Verifier() err = %v, want nil", err)
			}
			data := random.GetRandomBytes(20)
			signature, err := signer.Sign(data)
			if err != nil {
				t.Fatalf("Sign() err = %v, want nil", err)
			}
			if err := verifier.Verify(signature, data); err != nil {
				t.Errorf("Verify() err = %v, want nil", err)
			}
		})
	}
}

func primitiveTestCases(t *testing.T) []primtiveTesCase {
	t.Helper()
	// Test vectors from
	// https://github.com/tink-crypto/tink-java/tree/v1.15.0/src/main/java/com/google/crypto/tink/signature/internal/testing/RsaSsaPssTestUtil.java#L35.
	// Only test vectors with no prefix are used.
	n2048Base64 := "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRy" +
		"O125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP" +
		"8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0" +
		"Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0X" +
		"OC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1" +
		"_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q"
	p2048Base64 := "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHf" +
		"QP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8" +
		"UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws"
	q2048Base64 := "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6I" +
		"edis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYK" +
		"rYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s"
	d2048Base64 := "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfS" +
		"NkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9U" +
		"vqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnu" +
		"ToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsu" +
		"rY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2a" +
		"hecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ"

	n4096Base64 := "AK9mcI3PaEhMPR2ICXxCsK0lek917W01OVK24Q6_eMKVJkzVKhf2muYn2B1Pkx_yvdWr7g0B1tjNSN66-A" +
		"PH7osa9F1x6WnzY16d2WY3xvidHxHMFol1sPa-xGKu94uFBp4rHqrj7nYBJX4QmHzLG95QANhJPz" +
		"C4P9M-lrVSyCVlHr2732NZpjoFN8dZtvNvNI_ndUb4fTgozmxbaRKGKawTjocP1DAtOzwwuOKPZM" +
		"WwI3nFEEDJqkhFh2uiINPWYtcs-onHXeKLpCJUwCXC4bEmgPErChOO3kvlZF6K2o8uoNBPkhnBog" +
		"q7tl8gxjnJWK5AdN2vZflmIwKuQaWB-12d341-5omqm-V9roqf7WpObLpkX1VeLeK9V96dnUl864" +
		"bap8RXvJlrQ-OMCBNax3YmtqMHWjafXe1tNavvEA8zi8dOchwyyUQ5xaPM_taf29AJA6F8xbeHFR" +
		"sAMX8piBOZYNZUm7SHu8tJOrAXmyDldCIeob2O4MRzMwfRgvQS_NAQNwPMuOBrpRr3b4slV6CfXs" +
		"k4cWTb3gs7ZXeSQFbJVmhaMDSjOFUzXxs75J4Ud639loa8jF0j7f5kInzR1t-UYj7YajigirKPaX" +
		"nI1OXxn0ZkBIRln0pVIbQFX5YJ96K9-YOpJnBNgYY_PNcvfl5SD87vYNOQxsbeIQIE-EkF"
	p4096Base64 := "AOQA7Ky1XEGqZcc7uSXwFbKjSNCmVBhCGqsDRdKJ1ErSmW98gnJ7pBIHTmiyFdJqU20SzY-YB05Xj3bfSY" +
		"ptJRPLO2cGiwrwjRB_EsG8OqexX_5le9_8x-8i6MhY3xGX5LABYs8dB0aLl3ysOtRgIvCeyeoJ0I" +
		"7nRYjwDlexxjl9z7OI28cW7Tdvljbk-LAgBmygsMluP2-n7T58Dl-SD-8BT5eiGFDFu76h_vmyTX" +
		"B1_zToAqBK2C5oM7OF_7Z7zuLjx7vz40xH6KD7Rkkvcwm95wfhYEZtHYFwqUhajE1vD5nCcGcCNh" +
		"quTLzPlW5RN2Asxm-_Dk-p7pIkH9aAP0k"
	q4096Base64 := "AMTv-c5IRTRvbx7Vyf06df2Rm2AwdaRlwy1QG3YAdojQ_PhICNH0-mTHqYaeNZRja6KniFKqaYimgdccW2" +
		"UhGGKZXQhHhyucZ-AE0NtPLFkd7RhegcrH5sbHOcDtWCSGwcne9Wzs54VyhIhGmOS5HYuLUD-sB0" +
		"NgMzm8vNsnF_qIt458x6L4GE97HnRnLdSJBFaNkEdLJGXN1fbtJIGgdKN1aOc5KafTi-q2DAHEe3" +
		"SmTzFPWD6NJ-jo0aJE9fXRQ06BUwUJtZXwaC4FCpcZKne2PSglc8AlqQOulcFLrsJ8fnG_vc7trS" +
		"_pw9zCxaaJQduYPyTbM9_szBj206lJb90"
	d4096Base64 := "QfFSeY4zl5LKG1MstcHg6IfBjyQ36inrbjSBMmk7_nPSnWo61B2LqOHr90EWgBlj03Q7IDrDymiLb-l9Gv" +
		"bMsRGmM4eDCKlPf5_6vtpTfN6dcrR2-KD9shaQgMVlHdgaX9a4RelBmq3dqaKVob0-sfsEBkyrbC" +
		"apIENUp8ECrERzJUP_vTtUKlYR3WnWRXlWmo-bYN5FPZrh2I0ZWLSF8EK9__ssfBxVO9DZgZwFd-" +
		"k7vSkgbisjUN6LBiVDEEF2kY1AeBIzMtvrDlkskEXPUim2qnTS6f15h7ErZfvwJYqTPR3dQL-yqz" +
		"RdYTBSNiGDrKdhCINL5FLI8NYQqifPF4hjPPlUVBCBoblOeSUnokh7l5VyTYShfS-Y24HjjUiZWk" +
		"XnNWsS0rubRYV69rq79GC45EwAvwQRPhGjYEQpS3BAzfdodjSVe_1_scCVVi7GpmhrEqz-ZJE3BY" +
		"i39ioGRddlGIMmMt_ddYpHNgt16qfLBGjJU2rveyxXm2zPZz-W-lJC8AjH8RqzFYikec2LNZ49xM" +
		"KiBAijpghSCoVCO_kTaesc6crJ125AL5T5df_C65JeXoCQsbbvQRdqQs4TG9uObkY8OWZ1VHjhUF" +
		"b1frplDQvc4bUqYFgQxGhrDFAbwKBECyUwqh0hJnDtQpFFcvhJj6AILVoLlVqNeWIK3iE"

	var testCases []primtiveTesCase
	publicKey2048 := &rsa.PublicKey{
		N: new(big.Int).SetBytes(base64Decode(t, n2048Base64)),
		E: 65537,
	}
	privateKey2048 := &rsa.PrivateKey{
		PublicKey: *publicKey2048,
		D:         new(big.Int).SetBytes(base64Decode(t, d2048Base64)),
		Primes: []*big.Int{
			new(big.Int).SetBytes(base64Decode(t, p2048Base64)),
			new(big.Int).SetBytes(base64Decode(t, q2048Base64)),
		},
	}
	privateKey2048.Precompute()

	privateValues2048 := rsassapss.PrivateKeyValues{
		D: secretdata.NewBytesFromData(base64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
		P: secretdata.NewBytesFromData(base64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
		Q: secretdata.NewBytesFromData(base64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
	}

	// Test vector 0.
	testVec0PublicKey := mustCreatePublicKey(t, base64Decode(t, n2048Base64), 0, mustCreateParameters(t, rsassapss.ParametersValues{
		ModulusSizeBits: 2048,
		SigHashType:     rsassapss.SHA256,
		MGF1HashType:    rsassapss.SHA256,
		PublicExponent:  f4,
		SaltLengthBytes: 32,
	}, rsassapss.VariantNoPrefix))
	testVec0PrivateKey, err := rsassapss.NewPrivateKey(testVec0PublicKey, privateValues2048)
	if err != nil {
		t.Fatalf("rsassapss.NewPrivateKey() err = %v, want nil", err)
	}
	testCases = append(testCases, primtiveTesCase{
		name:       fmt.Sprintf("2048-SHA256-RAW-salt32"),
		publicKey:  testVec0PublicKey,
		privateKey: testVec0PrivateKey,
		signature: hexDecode(t, "97db7e8f38015cb1d14530c0bf3a28dfdd61e7570f3fea2d2933ba0afbbe6358f7d0c39e9647fd27c9b441"+
			"557dc3e1ce34f8664bfdf93a7b1af78650eae4ed61f16c8583058296019fe968e92bcf35f38cb85a"+
			"32c2107a76790a95a715440da281d026172b8b6e043af417852988441dac5ea888c849668bdcbb58"+
			"f5c34ebe9ab5d16f7fa6cff32e9ed6a65c58708d887af791a33f34f7fc2da8885a9c867d347c6f92"+
			"996dcb24f99701d2b955bb66f38c057f4acd51ff02da59c3bc129593820552ca07825a7e9920c266"+
			"8c8eb99f2a541d9ef34f34054fda0d8a792822cc00f3f274fa0fcbf3c6a32f9fb85cba8dc713941f"+
			"92a7a4f082693a2f79ff8198d6"),
		message: hexDecode(t, "aa"),
	})
	// Test vector 1.
	testVec1PublicKey := mustCreatePublicKey(t, base64Decode(t, n2048Base64), 0, mustCreateParameters(t, rsassapss.ParametersValues{
		ModulusSizeBits: 2048,
		SigHashType:     rsassapss.SHA512,
		MGF1HashType:    rsassapss.SHA512,
		PublicExponent:  f4,
		SaltLengthBytes: 32,
	}, rsassapss.VariantNoPrefix))
	testVec1PrivateKey, err := rsassapss.NewPrivateKey(testVec1PublicKey, privateValues2048)
	if err != nil {
		t.Fatalf("rsassapss.NewPrivateKey() err = %v, want nil", err)
	}
	testCases = append(testCases, primtiveTesCase{
		name:       fmt.Sprintf("2048-SHA512-RAW-salt32"),
		publicKey:  testVec1PublicKey,
		privateKey: testVec1PrivateKey,
		signature: hexDecode(t, "b21a035305dbe9119803932330dbfcc4ab11bf15f1b89b974e53e5e48d54433a230ec189da5f0c77e53fb0"+
			"eb320fd36a9e7209ffc78759cc409c15d67b858782afa5f9c67d3880275d67cd98c40064adf08d9a"+
			"58f0badb5c47b88a06ed81a23ffb131380c2f3bbc16a9290d13d31df54e2061b2f0acb3629a3693f"+
			"03b3f2004b451de3e1ae2861654d145a5723f102f65533598aa5bc8e40b67190386a45fe99bf17c4"+
			"610b2edf2538878989cacffd57b4c27c82ab72d95f380e50f0282423d759a6d06241cd88a817e3c9"+
			"67ff0e2dd1cbbacc9402ffee0acf41bbec54ea2bbe01edadf0382c8ab2a897580c1cdf4e412032a0"+
			"83d1e5d47a625a38aac8c552e1"),
		message: hexDecode(t, "aa"),
	})
	// Test vector 2.
	testVec2PublicKey := mustCreatePublicKey(t, base64Decode(t, n2048Base64), uint32(0x99887766), mustCreateParameters(t, rsassapss.ParametersValues{
		ModulusSizeBits: 2048,
		SigHashType:     rsassapss.SHA256,
		MGF1HashType:    rsassapss.SHA256,
		PublicExponent:  f4,
		SaltLengthBytes: 32,
	}, rsassapss.VariantTink))
	testVec2PrivateKey, err := rsassapss.NewPrivateKey(testVec2PublicKey, privateValues2048)
	if err != nil {
		t.Fatalf("rsassapss.NewPrivateKey() err = %v, want nil", err)
	}
	testCases = append(testCases, primtiveTesCase{
		name:       fmt.Sprintf("2048-SHA256-TINK-salt32"),
		publicKey:  testVec2PublicKey,
		privateKey: testVec2PrivateKey,
		signature: hexDecode(t, "0199887766"+
			"97db7e8f38015cb1d14530c0bf3a28dfdd61e7570f3fea2d2933ba0afbbe6358f7d0c39e9647fd27"+
			"c9b441557dc3e1ce34f8664bfdf93a7b1af78650eae4ed61f16c8583058296019fe968e92bcf35f3"+
			"8cb85a32c2107a76790a95a715440da281d026172b8b6e043af417852988441dac5ea888c849668b"+
			"dcbb58f5c34ebe9ab5d16f7fa6cff32e9ed6a65c58708d887af791a33f34f7fc2da8885a9c867d34"+
			"7c6f92996dcb24f99701d2b955bb66f38c057f4acd51ff02da59c3bc129593820552ca07825a7e99"+
			"20c2668c8eb99f2a541d9ef34f34054fda0d8a792822cc00f3f274fa0fcbf3c6a32f9fb85cba8dc7"+
			"13941f92a7a4f082693a2f79ff8198d6"),
		message: hexDecode(t, "aa"),
	})
	// Test vector 3.
	testVec3PublicKey := mustCreatePublicKey(t, base64Decode(t, n2048Base64), uint32(0x99887766), mustCreateParameters(t, rsassapss.ParametersValues{
		ModulusSizeBits: 2048,
		SigHashType:     rsassapss.SHA256,
		MGF1HashType:    rsassapss.SHA256,
		PublicExponent:  f4,
		SaltLengthBytes: 32,
	}, rsassapss.VariantCrunchy))
	testVec3PrivateKey, err := rsassapss.NewPrivateKey(testVec3PublicKey, privateValues2048)
	if err != nil {
		t.Fatalf("rsassapss.NewPrivateKey() err = %v, want nil", err)
	}
	testCases = append(testCases, primtiveTesCase{
		name:       fmt.Sprintf("2048-SHA256-CRUNCHY-salt32"),
		publicKey:  testVec3PublicKey,
		privateKey: testVec3PrivateKey,
		signature: hexDecode(t, "0099887766"+
			"97db7e8f38015cb1d14530c0bf3a28dfdd61e7570f3fea2d2933ba0afbbe6358f7d0c39e9647fd27"+
			"c9b441557dc3e1ce34f8664bfdf93a7b1af78650eae4ed61f16c8583058296019fe968e92bcf35f3"+
			"8cb85a32c2107a76790a95a715440da281d026172b8b6e043af417852988441dac5ea888c849668b"+
			"dcbb58f5c34ebe9ab5d16f7fa6cff32e9ed6a65c58708d887af791a33f34f7fc2da8885a9c867d34"+
			"7c6f92996dcb24f99701d2b955bb66f38c057f4acd51ff02da59c3bc129593820552ca07825a7e99"+
			"20c2668c8eb99f2a541d9ef34f34054fda0d8a792822cc00f3f274fa0fcbf3c6a32f9fb85cba8dc7"+
			"13941f92a7a4f082693a2f79ff8198d6"),
		message: hexDecode(t, "aa"),
	})
	// Test vector 4.
	testVec4PublicKey := mustCreatePublicKey(t, base64Decode(t, n2048Base64), uint32(0x99887766), mustCreateParameters(t, rsassapss.ParametersValues{
		ModulusSizeBits: 2048,
		SigHashType:     rsassapss.SHA256,
		MGF1HashType:    rsassapss.SHA256,
		PublicExponent:  f4,
		SaltLengthBytes: 32,
	}, rsassapss.VariantLegacy))
	testVec4PrivateKey, err := rsassapss.NewPrivateKey(testVec4PublicKey, privateValues2048)
	if err != nil {
		t.Fatalf("rsassapss.NewPrivateKey() err = %v, want nil", err)
	}
	testCases = append(testCases, primtiveTesCase{
		name:       fmt.Sprintf("2048-SHA256-LEGACY-salt32"),
		publicKey:  testVec4PublicKey,
		privateKey: testVec4PrivateKey,
		signature: hexDecode(t, "0099887766"+
			"433065815d23c7beff4780228b0e6212d7cedd6998c5528bd5b0a3ce90066a4a1f76c703745c23b4"+
			"f7d92a5c84871dc9e6b2800d2bebd3d651afa86b1eb68924bacabc0699358417319f5f9f7b326e63"+
			"6457c6098676f61c549b25c40975ee5cefa4c3c2b7d5d81efa0a78e4c777908762a0348022d425aa"+
			"fcdc4f6ada902d359758ad75ae8988eb522ea11771c9d84fc9ffe6f3b317872335b1d4af5f60e40e"+
			"1a0d2588cb6640383b5b193f094754c21250485eb9430b056bab0d781ba261bd6cf80ad520402b83"+
			"bc30a81d9ce38b7de9844d7d1310696de099dbf2b642cfca8edb6b098c71d50710668870f3e47b11"+
			"5ecf4a0933573c92027d737647daa9f8"),
		message: hexDecode(t, "aa"),
	})
	// Test vector 5.
	testVec5PublicKey := mustCreatePublicKey(t, base64Decode(t, n2048Base64), 0, mustCreateParameters(t, rsassapss.ParametersValues{
		ModulusSizeBits: 2048,
		SigHashType:     rsassapss.SHA256,
		MGF1HashType:    rsassapss.SHA256,
		PublicExponent:  f4,
		SaltLengthBytes: 64,
	}, rsassapss.VariantNoPrefix))
	testVec5PrivateKey, err := rsassapss.NewPrivateKey(testVec5PublicKey, privateValues2048)
	if err != nil {
		t.Fatalf("rsassapss.NewPrivateKey() err = %v, want nil", err)
	}
	testCases = append(testCases, primtiveTesCase{
		name:       fmt.Sprintf("2048-SHA256-RAW-salt64"),
		publicKey:  testVec5PublicKey,
		privateKey: testVec5PrivateKey,
		signature: hexDecode(t, "aa5310c40c83878e0116ccc09efda3be6a88c667c797e61b6831e109fd6b5fbed9df08cf05711d79cb3841"+
			"64fc5ddfb0de10a5110053c2b073449603bb11994fc0847d929806d5034e24db0662df5c0963fbac"+
			"1d214842c4de1d7f4bfb741d8a2866e24819e8073042d17bccef92bbcdc6b34ca052486d60d12e9d"+
			"992cebaaca5df2d7ea31c08af4d35338cdaa460a0ee568ff2bdaab1d72d6a8360713d98a0923ae92"+
			"9cff9950fd48bf0fa05e4324f4f9561defbb8e2c4854122394dd55bda740d57064956255e36c6c1c"+
			"c1970947d630121df570ba577957dd23116e9bf4c2c826ec4b52223735dd0c355165485ff6652656"+
			"aa471a190c7f40e26c85440fc8"),
		message: hexDecode(t, "aa"),
	})

	publicKey4096 := &rsa.PublicKey{
		N: new(big.Int).SetBytes(base64Decode(t, n4096Base64)),
		E: 65537,
	}
	privateKey4096 := &rsa.PrivateKey{
		PublicKey: *publicKey4096,
		D:         new(big.Int).SetBytes(base64Decode(t, d4096Base64)),
		Primes: []*big.Int{
			new(big.Int).SetBytes(base64Decode(t, p4096Base64)),
			new(big.Int).SetBytes(base64Decode(t, q4096Base64)),
		},
	}
	privateKey4096.Precompute()
	// Test vector 6.
	testVec6PublicKey := mustCreatePublicKey(t, base64Decode(t, n4096Base64), 0, mustCreateParameters(t, rsassapss.ParametersValues{
		ModulusSizeBits: 4096,
		SigHashType:     rsassapss.SHA256,
		MGF1HashType:    rsassapss.SHA256,
		PublicExponent:  f4,
		SaltLengthBytes: 32,
	}, rsassapss.VariantNoPrefix))
	privateValues4096 := rsassapss.PrivateKeyValues{
		D: secretdata.NewBytesFromData(base64Decode(t, d4096Base64), insecuresecretdataaccess.Token{}),
		P: secretdata.NewBytesFromData(base64Decode(t, p4096Base64), insecuresecretdataaccess.Token{}),
		Q: secretdata.NewBytesFromData(base64Decode(t, q4096Base64), insecuresecretdataaccess.Token{}),
	}
	testVec6PrivateKey, err := rsassapss.NewPrivateKey(testVec6PublicKey, privateValues4096)
	if err != nil {
		t.Fatalf("rsassapss.NewPrivateKey() err = %v, want nil", err)
	}
	testCases = append(testCases, primtiveTesCase{
		name:       fmt.Sprintf("4096-SHA256-RAW-salt32"),
		publicKey:  testVec6PublicKey,
		privateKey: testVec6PrivateKey,
		signature: hexDecode(t, "20c933ec5b1c7862d3695e4e98ce4494fb9225ffcca5cb6ff165790c856a7600092b8dc57c1e551fc8a85b"+
			"6e0731f4e6b148c9b2b1ab72f8ea528591fa2cfc35a1d893d00aabff2d66471bcfa84cafa033d33c"+
			"a9964c13ee316ddfdde2d1766272d60440f5df0eba22f419f2b95c2decf3621f0c3cb311b7f72bf2"+
			"ca740414b31f74d3dd042abd005a1adc9aa4e57b65ef813476d7294aa516f04f96211dcc74497fd7"+
			"f876997595ef1d3e9be241c0455acda0d004ecfbd66bba5b98fcec6d8bba4ede1d88ab585e422142"+
			"167ac6fc096ddf389598f35a7b361f1946212e71b0d6f5ae5ae594bd4bc4ed52a8aa21607d845f2f"+
			"9b921cc05edd12a8ecdb40d1265c4e038855dbcf895c9ce0012f62194eafa3aec3ae38fcf9922e80"+
			"b3f123bfa6f5eea4d90036057eeabf3219fefd6bb9205489a9fb55e1ff280ab946350ca3dd7cd328"+
			"c033a4e5756bffaa83f94767d02dcd2ba0c78af4e4dc51fae1125f683278c659fb9e2b269131af86"+
			"410599d798e0d626477fb94af9be8e7c95f12467434b12fb415cea98c4eb05d879ef1e7eebf79268"+
			"68f21d9e51c184bdc679c8aceda400bb4edc29c029b4b939b2ac43d712ef4b68a058f5f45ac70022"+
			"abc5fec9389333a8b67a54b4a994f3ca7fdf14c73b5b130220fcc2607b27bdfa2b37e115bc8ccfe2"+
			"489f51642f8556b0240ad86f7620d3e7664f76ac671da08e92b76f512b"),
		message: hexDecode(t, "aa"),
	})
	// Test vector 7.
	testVec7PublicKey := mustCreatePublicKey(t, base64Decode(t, n2048Base64), 0, mustCreateParameters(t, rsassapss.ParametersValues{
		ModulusSizeBits: 2048,
		SigHashType:     rsassapss.SHA384,
		MGF1HashType:    rsassapss.SHA384,
		PublicExponent:  f4,
		SaltLengthBytes: 32,
	}, rsassapss.VariantNoPrefix))
	testVec7PrivateKey, err := rsassapss.NewPrivateKey(testVec7PublicKey, privateValues2048)
	if err != nil {
		t.Fatalf("rsassapss.NewPrivateKey() err = %v, want nil", err)
	}
	testCases = append(testCases, primtiveTesCase{
		name:       fmt.Sprintf("2048-SHA384-RAW-salt32"),
		publicKey:  testVec7PublicKey,
		privateKey: testVec7PrivateKey,
		signature: hexDecode(t, "8c87ec23317b97c5d5e3692da3aa7037c183d757d0aa79ed1a2ccc46cde8397e2a8b231057034b24358135"+
			"87314335bf308f9c930682e7575ec54968fdf15d9a689230ee2822338a97f08af3ce85b81f1c4826"+
			"17a2f3316b78b59ec3243541eb4e32bc3a33e20729f4019085dda89f7a6c4584ab9f4288755e6511"+
			"7f3f1dca298ef9605804ee69a88bc7d7addb99b9dbee9f858d1f7df01f0b12fa9a9534bdeaf7f197"+
			"c1cafcb0853f32bfed7cb9495f073fcaa2d73eab5f9398b07300dbc9b80dbff248106e6c8a52e564"+
			"fd9de73e0122f576e5fa3c4bdb477663b616372568492b4f00b6261800b132a04a3dc735e44fc4ce"+
			"9a72e3afaca5a0d50ea77388c9"),
		message: hexDecode(t, "aa"),
	})
	// Test vector 8.
	testVec8PublicKey := mustCreatePublicKey(t, base64Decode(t, n2048Base64), 0, mustCreateParameters(t, rsassapss.ParametersValues{
		ModulusSizeBits: 2048,
		SigHashType:     rsassapss.SHA256,
		MGF1HashType:    rsassapss.SHA256,
		PublicExponent:  f4,
		SaltLengthBytes: 0,
	}, rsassapss.VariantNoPrefix))
	testVec8PrivateKey, err := rsassapss.NewPrivateKey(testVec8PublicKey, privateValues2048)
	if err != nil {
		t.Fatalf("rsassapss.NewPrivateKey() err = %v, want nil", err)
	}
	testCases = append(testCases, primtiveTesCase{
		name:       fmt.Sprintf("2048-SHA256-RAW-salt0"),
		publicKey:  testVec8PublicKey,
		privateKey: testVec8PrivateKey,
		signature: hexDecode(t, "5bfef53336a5148a2f880e28c92c71fa0523707390d075d7608a8eeab44cff5166946850f5818b00e48769"+
			"22bf7cc0fedfdc1f8e265200c4c10e41686f62f8a621b8ca2771106deb28fa9b0ec2b2687f106b8f"+
			"68695dddc0b80dc15bec32e7ad2de73edb2789a8222866521230f2795b6c74de777050f02a031577"+
			"6855f4bb1e063c93ef8d1c4a91abe393017b0cfa09548f6f5bfd565d02bdce2116ffca232ede6f4e"+
			"869aac226f703ae0ef739fe926f0f15f916a7fa17b407118d9a54353794835c224fa8c7b92137715"+
			"26a7acb7575ddbd4ea3aaad6c827a5d1378773a4556763ed1442fddc76e29585c9d1992d42a8b730"+
			"e744e44f3bfe5ddddc47b5d728"),
		message: hexDecode(t, "aa"),
	})
	return testCases
}

func TestVerifyCorrectness(t *testing.T) {
	for _, tc := range primitiveTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			verifier, err := rsassapss.NewVerifier(tc.publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("rsassapss.NewVerifier() err = %v, want nil", err)
			}
			if err := verifier.Verify(tc.signature, tc.message); err != nil {
				t.Errorf("Verify() err = %v, want nil", err)
			}
		})
	}
}

func TestVerifyFails(t *testing.T) {
	for _, tc := range primitiveTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			verifier, err := rsassapss.NewVerifier(tc.publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("rsassapss.NewVerifier() err = %v, want nil", err)
			}

			prefix := tc.signature[:len(tc.privateKey.OutputPrefix())]
			rawSignature := tc.signature[len(tc.privateKey.OutputPrefix()):]

			// Modify the prefix.
			for i := 0; i < len(prefix); i++ {
				modifiedPrefix := slices.Clone(prefix)
				for j := 0; j < 8; j++ {
					modifiedPrefix[i] = byte(modifiedPrefix[i] ^ (1 << uint32(j)))
					s := slices.Concat(modifiedPrefix, rawSignature)
					if err := verifier.Verify(s, tc.message); err == nil {
						t.Errorf("verifier.Verify(%x, tc.message) err = nil, want error", s)
					}
				}
			}

			// Modify the signature.
			for i := 0; i < len(rawSignature); i++ {
				modifiedRawSignature := slices.Clone(rawSignature)
				for j := 0; j < 8; j++ {
					modifiedRawSignature[i] = byte(modifiedRawSignature[i] ^ (1 << uint32(j)))
					s := slices.Concat(prefix, modifiedRawSignature)
					if err := verifier.Verify(s, tc.message); err == nil {
						t.Errorf("verifier.Verify(%x, tc.message) err = nil, want error", s)
					}
				}
			}

			// Append a byte to the signature.
			for j := 0; j < 8; j++ {
				appendedSignature := slices.Concat(tc.signature, []byte{byte(j)})
				if err := verifier.Verify(appendedSignature, tc.message); err == nil {
					t.Errorf("verifier.Verify(%x, tc.message) err = nil, want error", appendedSignature)
				}
			}

			// Truncated signature.
			if err := verifier.Verify(tc.signature[:len(tc.signature)-1], tc.message); err == nil {
				t.Errorf("verifier.Verify(%x, tc.message) err = nil, want error", tc.signature[:len(tc.signature)-1])
			}

			// Modify the message.
			for i := 0; i < len(tc.message); i++ {
				modifiedData := slices.Clone(tc.message)
				for j := 0; j < 8; j++ {
					modifiedData[i] = byte(modifiedData[i] ^ (1 << uint32(j)))
					if err := verifier.Verify(tc.signature, modifiedData); err == nil {
						t.Errorf("verifier.Verify(signature, %x) err = nil, want error", modifiedData)
					}
				}
			}
		})
	}
}

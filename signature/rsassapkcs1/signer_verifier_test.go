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
	"encoding/hex"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
)

func TestVerifyWorks(t *testing.T) {
	// Test vectors from https://github.com/tink-crypto/tink-java/tree/v1.15.0/src/main/java/com/google/crypto/tink/signature/internal/testing/RsaSsaPkcs1TestUtil.java#L35
	modulus2048Base64 := "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRy" +
		"O125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP" +
		"8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0" +
		"Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0X" +
		"OC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1" +
		"_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q"
	modulus4096Base64 := "AK9mcI3PaEhMPR2ICXxCsK0lek917W01OVK24Q6_eMKVJkzVKhf2muYn2B1Pkx_yvdWr7g0B1tjNSN66-A" +
		"PH7osa9F1x6WnzY16d2WY3xvidHxHMFol1sPa-xGKu94uFBp4rHqrj7nYBJX4QmHzLG95QANhJPz" +
		"C4P9M-lrVSyCVlHr2732NZpjoFN8dZtvNvNI_ndUb4fTgozmxbaRKGKawTjocP1DAtOzwwuOKPZM" +
		"WwI3nFEEDJqkhFh2uiINPWYtcs-onHXeKLpCJUwCXC4bEmgPErChOO3kvlZF6K2o8uoNBPkhnBog" +
		"q7tl8gxjnJWK5AdN2vZflmIwKuQaWB-12d341-5omqm-V9roqf7WpObLpkX1VeLeK9V96dnUl864" +
		"bap8RXvJlrQ-OMCBNax3YmtqMHWjafXe1tNavvEA8zi8dOchwyyUQ5xaPM_taf29AJA6F8xbeHFR" +
		"sAMX8piBOZYNZUm7SHu8tJOrAXmyDldCIeob2O4MRzMwfRgvQS_NAQNwPMuOBrpRr3b4slV6CfXs" +
		"k4cWTb3gs7ZXeSQFbJVmhaMDSjOFUzXxs75J4Ud639loa8jF0j7f5kInzR1t-UYj7YajigirKPaX" +
		"nI1OXxn0ZkBIRln0pVIbQFX5YJ96K9-YOpJnBNgYY_PNcvfl5SD87vYNOQxsbeIQIE-EkF"
	message, err := hex.DecodeString("aa")
	if err != nil {
		t.Fatalf("hex.DecodeString(%v) = %v, want nil", "aa", err)
	}
	for _, tc := range []struct {
		name      string
		publicKey *rsassapkcs1.PublicKey
		signature []byte
		message   []byte
	}{
		{
			name:      "2048-SHA256-RAW",
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, modulus2048Base64), 0, mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantNoPrefix)),
			signature: func() []byte {
				signatureHex := "3d10ce911833c1fe3f3356580017d159e1557e019096499950f62c3768c716bca418828dc140e930ecceff" +
					"ebc532db66c77b433e51cef6dfbac86cb3aff6f5fc2a488faf35199b2e12c9fe2de7be3eea63bdc9" +
					"60e6694e4474c29e5610f5f7fa30ac23b015041353658c74998c3f620728b5859bad9c63d07be0b2" +
					"d3bbbea8b9121f47385e4cad92b31c0ef656eee782339d14fd6350bb3756663c03cb261f7ece6e03" +
					"355c7a4ecfe812c965f68890b2571916de0e2cd40814f9db9571065b5340ef7aa66d55a78cd62f4a" +
					"1bd496623184a3d29dd886c1d1331754915bcbb243e5677ea7bb21a18d1ee22b6ba92c15a23ed6ae" +
					"de20abc29b290cc04fa0846027"
				decoded, err := hex.DecodeString(signatureHex)
				if err != nil {
					t.Fatalf("hex.DecodeString(%v) = %v, want nil", signatureHex, err)
				}
				return decoded
			}(),
			message: message,
		},
		{
			name:      "2048-SHA512-RAW",
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, modulus2048Base64), 0, mustCreateParameters(t, 2048, rsassapkcs1.SHA512, f4, rsassapkcs1.VariantNoPrefix)),
			signature: func() []byte {
				signatureHex := "67cbf2475fff2908ba2fbde91e5ac21901427cf3328b17a41a1ba41f955d64b6358c78417ca19d1bd83f36" +
					"0fe28e48c7e4fd3946349e19812d9fa41b546c6751fd49b4ad986c9f38c3af9993a8466b91839415" +
					"e6e334f6306984957784854bde60c3926cc1037f764d6182ea44d7398fbaeefcb8b3c84ba8277003" +
					"20d00ee28816ecb7ed90debf46183abcc55950ff9f9b935df5ffaebb0f0b12a9244ac4fc05012f99" +
					"d5df4c2b4a1a6cafab54f30ed9122531f4322ff11f8921c8b716827d5dd278c0dea49ebb67b188b8" +
					"259ed820f1e750e45fd7767b9acdf30b47275739036a15aa11dfe030595e49d6c71ea8cb6a016e41" +
					"67f3a4168eb4326d12ffed608c"
				decoded, err := hex.DecodeString(signatureHex)
				if err != nil {
					t.Fatalf("hex.DecodeString(%v) = %v, want nil", signatureHex, err)
				}
				return decoded
			}(),
			message: message,
		},
		{
			name:      "2048-SHA256-TINK",
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, modulus2048Base64), uint32(0x99887766), mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantTink)),
			signature: func() []byte {
				signatureHex := "01998877663d10ce911833c1fe3f3356580017d159e1557e019096499950f62c3768c716bca418828dc140" +
					"e930ecceffebc532db66c77b433e51cef6dfbac86cb3aff6f5fc2a488faf35199b2e12c9fe2de7be" +
					"3eea63bdc960e6694e4474c29e5610f5f7fa30ac23b015041353658c74998c3f620728b5859bad9c" +
					"63d07be0b2d3bbbea8b9121f47385e4cad92b31c0ef656eee782339d14fd6350bb3756663c03cb26" +
					"1f7ece6e03355c7a4ecfe812c965f68890b2571916de0e2cd40814f9db9571065b5340ef7aa66d55" +
					"a78cd62f4a1bd496623184a3d29dd886c1d1331754915bcbb243e5677ea7bb21a18d1ee22b6ba92c" +
					"15a23ed6aede20abc29b290cc04fa0846027"
				decoded, err := hex.DecodeString(signatureHex)
				if err != nil {
					t.Fatalf("hex.DecodeString(%v) = %v, want nil", signatureHex, err)
				}
				return decoded
			}(),
			message: message,
		},
		{
			name:      "2048-SHA256-CRUNCHY",
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, modulus2048Base64), uint32(0x99887766), mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantCrunchy)),
			signature: func() []byte {
				signatureHex := "00998877663d10ce911833c1fe3f3356580017d159e1557e019096499950f62c3768c716bca418828dc140" +
					"e930ecceffebc532db66c77b433e51cef6dfbac86cb3aff6f5fc2a488faf35199b2e12c9fe2de7be" +
					"3eea63bdc960e6694e4474c29e5610f5f7fa30ac23b015041353658c74998c3f620728b5859bad9c" +
					"63d07be0b2d3bbbea8b9121f47385e4cad92b31c0ef656eee782339d14fd6350bb3756663c03cb26" +
					"1f7ece6e03355c7a4ecfe812c965f68890b2571916de0e2cd40814f9db9571065b5340ef7aa66d55" +
					"a78cd62f4a1bd496623184a3d29dd886c1d1331754915bcbb243e5677ea7bb21a18d1ee22b6ba92c" +
					"15a23ed6aede20abc29b290cc04fa0846027"
				decoded, err := hex.DecodeString(signatureHex)
				if err != nil {
					t.Fatalf("hex.DecodeString(%v) = %v, want nil", signatureHex, err)
				}
				return decoded
			}(),
			message: message,
		},
		{
			name:      "2048-SHA256-LEGACY",
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, modulus2048Base64), uint32(0x99887766), mustCreateParameters(t, 2048, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantLegacy)),
			signature: func() []byte {
				signatureHex := "00998877668aece22c45c0db3db64e00416ed906b45e9c8ffedc1715cb3ea6cd9855a16f1c25375dbdd902" +
					"8c79ad5ee192f1fa60d54efbe3d753e1c604ee7104398e2bae28d1690d8984155b0de78ab52d90d3" +
					"b90509a1b798e79aff83b12413fa09bed089e29e7107ca00b33be0797d5d2ab3033e04a689b63c52" +
					"f3595245ce6639af9c0f0d3c3dbe00f076f6dd0fd72d26579f1cffdb3218039de1b3de52b5626d2c" +
					"3f840386904009be88b896132580716563edffa6ba15b29cf2fa1503236a5bec3f4beb5f4cc96267" +
					"7b4c1760d0c99dadf7704586d67fe95ccb312fd82e5c965041caf12afce18641e54a812aa36faf14" +
					"e2250a06b78ac111b1a2c8913f13e2a3d341"
				decoded, err := hex.DecodeString(signatureHex)
				if err != nil {
					t.Fatalf("hex.DecodeString(%v) = %v, want nil", signatureHex, err)
				}
				return decoded
			}(),
			message: message,
		},
		{
			name:      "4096-SHA256-RAW",
			publicKey: mustCreatePublicKey(t, mustDecodeBase64(t, modulus4096Base64), 0, mustCreateParameters(t, 4096, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantNoPrefix)),
			signature: func() []byte {
				signatureHex := "122a08c6e8b9bf4cb437a00e55cf6ac96e216c4580af87e40be6227504e163c0c516b747d38a81f087f387" +
					"8242008e4d0ef400d02f5bdc6629bb2f323241fcbbaa84aa173324359bdf7e35becd68b3977367ae" +
					"ecf8cfb4a9497f883547c2f9e151ee47cddcc25359ccf6ca28bef3daf116543343f63898ea514049" +
					"620ddb91616e9ec4891ade53fec4c06dc463a663e7c1008b2b9295a5478735e1fdb385a4fcc03485" +
					"3eb27602e96dfea7f620b22085f3e345ed57f33e044aeb4450fe10346459b8fc4d306bf59038bd17" +
					"2da6c32f4d6785c6e120a3da08988cf79a9e8a43fe97e6b64693776c209425a6d36cbfbf45ece68b" +
					"ffe7089bc5dc1c3ef265c0a88989ec279993a7e5c75f669768a1520791cc72f35268fa67654064d5" +
					"77d9d225da04c9694055df09cf3f14d8572a94c1793c32c0ecde034d24687a711d123f499f17f27f" +
					"ce41376100e854409ff647651633b1ec050cf4893e8fea4a956e2ba0e177dcaf8176974e21396337" +
					"6b5fec2e4dac76f8ef5f2371d9f3124eea512b934e5b09d6528d26c2f0d3767af7d3320d1e73b6a9" +
					"3ac4404a880603fdde06007a11f3ac554aceb0e40fff40702b6a5aa1fa492d630317ecc31aadd79e" +
					"6564c16a3f323f7fa4f58d4bfe27a09744f4ced12cddead3afa4dc6836afbbe2388dd933b8759d95" +
					"8d6334038eee7904bb907310726a0845ebddba81fb88db11c3853b251a"
				decoded, err := hex.DecodeString(signatureHex)
				if err != nil {
					t.Fatalf("hex.DecodeString(%v) = %v, want nil", signatureHex, err)
				}
				return decoded
			}(),
			message: message,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier, err := rsassapkcs1.NewVerifier(tc.publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("rsassapkcs1.NewVerifier(%v, internalapi.Token{}) = %v, want nil", tc.publicKey, err)
			}
			if err := verifier.Verify(tc.signature, tc.message); err != nil {
				t.Errorf("Verify() err = %v, want nil", err)
			}
		})
	}
}

func TestSignVerify(t *testing.T) {
	for _, tc := range privateKeyTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			privKey, err := rsassapkcs1.NewPrivateKey(tc.publicKey, tc.privateKeyValues)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewPrivateKey(%v, %v) = %v, want nil", tc.publicKey, tc.privateKeyValues, err)
			}
			signer, err := rsassapkcs1.NewSigner(privKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("rsassapkcs1.NewSigner(%v, internalapi.Token{}) = %v, want nil", privKey, err)
			}

			data := random.GetRandomBytes(20)
			signatureBytes, err := signer.Sign(data)
			if err != nil {
				t.Fatalf("Sign() err = %v, want nil", err)
			}
			if !bytes.HasPrefix(signatureBytes, privKey.OutputPrefix()) {
				t.Errorf("signatureBytes = %x doesn't have the expected prefix %x", signatureBytes, privKey.OutputPrefix())
			}

			// Create a verifier from the public key.
			verifier, err := rsassapkcs1.NewVerifier(tc.publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("rsassapkcs1.NewVerifier(%v, internalapi.Token{}) = %v, want nil", tc.publicKey, err)
			}
			if err := verifier.Verify(signatureBytes, data); err != nil {
				t.Errorf("Verify() err = %v, want nil", err)
			}
		})
	}
}

func TestVerifyFails(t *testing.T) {
	for _, tc := range privateKeyTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			privKey, err := rsassapkcs1.NewPrivateKey(tc.publicKey, tc.privateKeyValues)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewPrivateKey(%v, %v) = %v, want nil", tc.publicKey, tc.privateKeyValues, err)
			}
			signer, err := rsassapkcs1.NewSigner(privKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("rsassapkcs1.NewSigner(%v, internalapi.Token{}) = %v, want nil", privKey, err)
			}
			verifier, err := rsassapkcs1.NewVerifier(tc.publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("rsassapkcs1.NewVerifier(%v, internalapi.Token{}) = %v, want nil", tc.publicKey, err)
			}
			data := random.GetRandomBytes(20)
			signatureBytes, err := signer.Sign(data)
			if err != nil {
				t.Fatalf("signer.Sign(%x) err = %v, want nil", data, err)
			}

			prefix := signatureBytes[:len(privKey.OutputPrefix())]
			rawSignature := signatureBytes[len(privKey.OutputPrefix()):]

			// Modify the prefix.
			for i := 0; i < len(prefix); i++ {
				modifiedPrefix := slices.Clone(prefix)
				for j := 0; j < 8; j++ {
					modifiedPrefix[i] = byte(modifiedPrefix[i] ^ (1 << uint32(j)))
					s := slices.Concat(modifiedPrefix, rawSignature)
					if err := verifier.Verify(s, data); err == nil {
						t.Errorf("verifier.Verify(%x, data) err = nil, want error", s)
					}
				}
			}

			// Modify the signature.
			for i := 0; i < len(rawSignature); i++ {
				modifiedRawSignature := slices.Clone(rawSignature)
				for j := 0; j < 8; j++ {
					modifiedRawSignature[i] = byte(modifiedRawSignature[i] ^ (1 << uint32(j)))
					s := slices.Concat(prefix, modifiedRawSignature)
					if err := verifier.Verify(s, data); err == nil {
						t.Errorf("verifier.Verify(%x, data) err = nil, want error", s)
					}
				}
			}

			// Append a byte to the signature.
			for j := 0; j < 8; j++ {
				appendedSignature := slices.Concat(signatureBytes, []byte{byte(j)})
				if err := verifier.Verify(appendedSignature, data); err == nil {
					t.Errorf("verifier.Verify(%x, data) err = nil, want error", appendedSignature)
				}
			}

			// Modify the message.
			for i := 0; i < len(data); i++ {
				modifiedData := slices.Clone(data)
				for j := 0; j < 8; j++ {
					modifiedData[i] = byte(modifiedData[i] ^ (1 << uint32(j)))
					if err := verifier.Verify(signatureBytes, modifiedData); err == nil {
						t.Errorf("verifier.Verify(signature, %x) err = nil, want error", modifiedData)
					}
				}
			}
		})
	}
}

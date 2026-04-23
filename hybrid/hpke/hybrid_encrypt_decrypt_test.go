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

package hpke_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/hybrid/hpke"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
)

type hybridEncryptTestVector struct {
	name        string
	privateKey  *hpke.PrivateKey
	plaintext   []byte
	contextInfo []byte
	ciphertext  []byte
}

// hybridTestVectors creates test vectors for HPKE.
//
// This are the same as
// https://github.com/tink-crypto/tink-cc/blob/v2.3.0/tink/hybrid/internal/testing/hpke_test_vectors.cc.
func hybridTestVectors(t *testing.T) []hybridEncryptTestVector {
	t.Helper()
	return []hybridEncryptTestVector{
		hybridEncryptTestVector{
			name: "DHKEM(P256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, No Prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 0, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantNoPrefix,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9ba742"+
				"34494b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c1"+
				"15cf17875f59b069dffc8427cfb7f277ed4e370ae78f916e22"),
		},
		hybridEncryptTestVector{
			name: "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, No Prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"),
				mustCreatePublicKey(t, mustHexDecode(t, "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"), 0, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantNoPrefix,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "c202f5f26a59c446531b9e4e880f8730ff0aed444699cb1cd69a2c60e"+
				"07aba42d77a29b62c7af6b2cfda9c1529bb8d23c8"),
		},
		hybridEncryptTestVector{
			name: "DHKEM(P256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, No Prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 0, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantNoPrefix,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "04b2de5915aa2bde7ad85745a632258caba46ed5be81297177dae45cd"+
				"cbcf49c92431ea80763f92f6b22115723a7d092994d40376f7618e9f2"+
				"ef82d5c44036e29eca440814ade6c8d5d9246abddaf5740331"),
		},
		hybridEncryptTestVector{
			name: "DHKEM(P256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, No Prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 0, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.ChaCha20Poly1305,
					Variant: hpke.VariantNoPrefix,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "04e0f41a312164058e2c36f1bc977e12a6fec8b13dc5fabc2441ec905"+
				"bc432145a0a5e50929815ec6944a3da1a186c0b9b428232086b218af0"+
				"61e9f814d8bd27808bce0bdb3c656d307f87ffe3bf13b0eb19"),
		},
		hybridEncryptTestVector{
			name: "DHKEM(P256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, Tink",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 0x886688aa, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "01886688aa04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9ba7423"+
				"4494b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c115cf17875f59"+
				"b069dffc8427cfb7f277ed4e370ae78f916e22"),
		},
		hybridEncryptTestVector{
			name: "DHKEM(P256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, Crunchy",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 0x886688aa, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantCrunchy,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "00886688aa04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9ba7423"+
				"4494b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c115cf17875f59"+
				"b069dffc8427cfb7f277ed4e370ae78f916e22"),
		},
		hybridEncryptTestVector{
			name: "X-Wing, HKDF-SHA256, AES-128-GCM, No Prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"),
				mustCreatePublicKey(t, mustHexDecode(t, "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534"), 0, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.X_WING,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantNoPrefix,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext:  mustHexDecode(t, "514c360edf02d99781e0779293f4d0b193d0dbe2fb9dae031f43a24543fd4c859dcb505493034e288acb606f3c81a1e39513b7a56db24188a1341f50870fcab15407c85f1779fe7b6529329c243ae50c932c1642c4b6acca7aaf6df233f051ca9b4a37eb239e42eb6a375338ab10131fca40334b4e8dc86366281055d3fd7bbfb6c7efdce2f0662fd0f12959c2d3721dc71698145822d27a3a1aa1847a95318a0f5ecbd8244f39f0be1bbb1446bb38d63be5a2494e5a7dbe936b875e0f15b88d9c5d4ad7679fa951b620f8d3a39bf8666db5730bd11692afd5d8b396d005ef7ea279752a4273f054205d017f26034884097d0deaa2cf5f64c567fdef3e3906ddbe97c8fb1bc883a3e926b2a9ee2773463410bad0b635cdc415c498870be7a2996fa573e16702d178a6d85f0c5a1d6e395f173a0ea09024dd96cce3cc560d1f9100286a842e229046530cf4ed5463294423b43289d108bbc6733dac84198562b0b570e05d3d8db6fb6b4073e09b20f0e6a92327ea37ad6b821fa7ae7c6e0f9d6c692ce8fed10b22f35c67a994b6b37985979d20bac851f108a3a987888936af70be31cf956a1b7bdef9030c76d3bba16ad03d6f8533c4d8b20d073b2d216967b3f28f47c746659c4fb33068f81462c361e19b46cc508145d9b8902c0bd2c01568ea8144fb1d7652763325877f95237fc30489ab28ed54bb926f2f7bee864f48a2f515c0ca904082b08e8bdf7e75f5ec9fd68981b2590a6203d9dc64f4f59e4f23943d23f17d642cd939c04d57fee34d893d6369f7a68447137e17742606488f7acc83ce7078cc4a41b2c44a70dd179c4da2f00efd1deaa2c38fe84049059e5421bd3a0359f01d3370929a26a273d35a43b5790246d6c322e128d74ba5659acc101585345d3b79c991496a5981b8f7cd1a5a15ff4574bfda5e7aad62940a4b526d269f8774b482d658515888a8836793cb23b037fdc94fdd933a133be285f1f68c5390cf01010e506921ea65389ebc519198151a45c75350dcb74bc1b47cc7534d4d90801c77594c50f00794e16b3550046e1d0692bbf2a4849fc0a88ae5408505fe93f4c4d654f097e2f32ca3fb0f898e76439ca85b9a76cab6ff2c99ce003f8f4c39be35cab17cbcee33f48dbfa8a2005f8ad4e9c5cfeeebcb6a805981b8fe18d2211b103e2226bf44cff9eb4cfc916ac6a5ffee3d7f27f7579b907e8df8dfff80d0531e413688a924a4fe921a9fec951358ba4b05b68dc45969893dde80d721c5773cb17a281635599ec4a1ecd857a5e65cc4f961f683c687960d004bc2527614798dfcf9d32fbf67b96bf760bd4a32fe0f961389163d91504a67176026b5378f3abc412f495ff3bf841ee419e1d47ddf06859cb9ddd6737754bd5ce29f633523ee7c1724a2612847dca2d81927e1975f9d577cfeffcf1d993e3aad1ff537fc918fecd3ced05f5459e8657107fff0818f532e3252990996401dfc212af043be280208df4b32490786484295126ba0a70fbf15976f214b76a53c3e4ea5e477fbf9f2993feeebd208b4a5b9c55954506f5fe3f8bbddd03f782fd73c28749a29626bcc91fb11b3467423822da9802fd6a4e7"),
		},
	}
}

func TestEncryptDecrypt(t *testing.T) {
	for _, tc := range hybridTestVectors(t) {
		t.Run(tc.name, func(t *testing.T) {
			publicKey, err := tc.privateKey.PublicKey()
			if err != nil {
				t.Fatalf("tc.privateKey.PublicKey() err = %v, want nil", err)
			}
			encrypter, err := hpke.NewHybridEncrypt(publicKey.(*hpke.PublicKey), internalapi.Token{})
			if err != nil {
				t.Fatalf("hpke.NewHybridEncrypt() err = %v, want nil", err)
			}
			decrypter, err := hpke.NewHybridDecrypt(tc.privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("hpke.NewHybridDecrypt() err = %v, want nil", err)
			}
			// Decrypt the ciphertext generated by the encrypter.
			{
				gotCiphertext, err := encrypter.Encrypt(tc.plaintext, tc.contextInfo)
				if err != nil {
					t.Fatalf("encrypter.Encrypt() err = %v, want nil", err)
				}
				gotDecrypted, err := decrypter.Decrypt(gotCiphertext, tc.contextInfo)
				if err != nil {
					t.Fatalf("decrypter.Decrypt() err = %v, want nil", err)
				}
				if diff := cmp.Diff(gotDecrypted, tc.plaintext); diff != "" {
					t.Errorf("decrypter.Decrypt() returned unexpected diff (-want +got):\n%s", diff)
				}
			}
			// Decrypt the test case ciphertext.
			{
				gotDecrypted, err := decrypter.Decrypt(tc.ciphertext, tc.contextInfo)
				if err != nil {
					t.Fatalf("decrypter.Decrypt() err = %v, want nil", err)
				}
				if diff := cmp.Diff(gotDecrypted, tc.plaintext); diff != "" {
					t.Errorf("decrypter.Decrypt() returned unexpected diff (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func mustEncrypt(t *testing.T, publicKey *hpke.PublicKey, plaintext, contextInfo []byte) []byte {
	t.Helper()
	encrypter, err := hpke.NewHybridEncrypt(publicKey, internalapi.Token{})
	if err != nil {
		t.Fatalf("hpke.NewHybridEncrypt() err = %v, want nil", err)
	}
	ciphertext, err := encrypter.Encrypt(plaintext, contextInfo)
	if err != nil {
		t.Fatalf("encrypter.Encrypt() err = %v, want nil", err)
	}
	return ciphertext
}

func TestDecryptFails(t *testing.T) {
	data := []byte("plaintext")
	contextInfo := []byte("context")
	for _, tc := range []struct {
		name       string
		publicKey  *hpke.PublicKey
		privateKey *hpke.PrivateKey
		ciphertext []byte
	}{
		{
			name: "different prefix type",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				}))),
			ciphertext: mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123, mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES128GCM,
				Variant: hpke.VariantCrunchy,
			})), data, contextInfo),
		},
		{
			name: "missing prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				}))),
			ciphertext: mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 0, mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES128GCM,
				Variant: hpke.VariantNoPrefix,
			})), data, contextInfo),
		},
		{
			name: "mismatched key ID",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				}))),
			ciphertext: mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 456, mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES128GCM,
				Variant: hpke.VariantTink,
			})), data, contextInfo),
		},
		{
			name: "different DEM",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				}))),
			ciphertext: mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123, mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			})), data, contextInfo),
		},
		{
			name: "invalid ciphertext",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
				mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				}))),
			ciphertext: func() []byte {
				ciphertext := mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 456, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				})), data, contextInfo)
				ciphertext[5] ^= 1
				return ciphertext
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decrypter, err := hpke.NewHybridDecrypt(tc.privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("hpke.NewHybridDecrypt(%v) err = %v, want nil", tc.publicKey, err)
			}
			if _, err := decrypter.Decrypt(tc.ciphertext, contextInfo); err == nil {
				t.Errorf("decrypter.Decrypt(%v, %v) err = nil, want error", tc.ciphertext, contextInfo)
			}
		})
	}
}

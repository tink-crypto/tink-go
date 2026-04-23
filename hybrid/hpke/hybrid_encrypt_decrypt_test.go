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
		hybridEncryptTestVector{
			name: "ML-KEM-768, HKDF-SHA256, AES-128-GCM, No Prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "e3408aae322a3628a4d641c2690d4eb212fd66f369782f2dd22fa293476c69957716be20e83920cd26a7710110a34ac3d5da7d90efdc9759812f5cf1a47e85bf"),
				mustCreatePublicKey(t, mustHexDecode(t, "0665cd16340cd373c7a7290f9ce315ddb57b61778aebd15fae817be1622f5f13380cbbaa61f9749141133606802d69a62d979d1aa04dcd6b073bc4b96612a8435a6578f86a8aa763fc2abdfbf30d35a6aeb8919cf0b7cad876bb1bc410a72159bf927b9e8a0ef56463162a45479166a98336412c4eb8042a70965df419a62163bc70cb567a3344dd86b3a282a32bd57d9518b82245aa8c0c603d36a057f0bffbb39ca67c18b8ac06344a441d2a6027dc7f261804cb2b94e9557820f7518e8b9f97952b953903ef89ae49eb34e4c0a9bf54797ce1535ca8a84a94c55730a909faa7cf467f1c72414a99a41a439e74499c51689f9ea7938fac45813749c42b7d6ba13acc447d31052ceb9730e86b046fb47c18935c55f22d88e8a8987b7c02d0452c3b56d492a7f6718c7ce0c7916a3f905818df6a3caac037ec49a964d965e147aea4a273e9fca7dd57af51638eac08bc77388aa4091ec9b12ab8929d72fabf7deca2469b25862b197406c9f0e479c40c257c809656465f076914cd3a2195c2629880c323a97236da39795985ced810e420527e1418dcabb2b5f8944d4433ba172b4100a7393a5263324b2f9008d90957e5cb0f9c7a924851121ec0808a8c4ea53a9f853a6b2f4a1ba4496d40c746ee646317025d477127f897379ae8b683318038a932902668f0147af7f05cc7b37c4c90b7525062d468bc1106529d39673ffba1cad6c2e93c327d92ac44485e84c768b34743eee6781e45261025af650ab85da3c0af7a66d616a5eafc3bf7b30ce94a4740412384966edd992beb8ba695dbc225f52c72e64d1e6c40dbe1013b840f9fc61d72530e0396048e1980c99751423a25874518be123a6f89556c8c270a736d1cc45fa4a5a6ad142e570c4d8974caa0368f1501a8a3d72a39cbafd441532d612901b454dc523de86b97aac84350a703db44869f4ac3a0dc7533723a31d9166bd33b72e8caf2f13364cc1934047952b370b0bc37664b772fa91e262b95ec40519dd46515b99284d193c4738f854b3d6ba56cc819badb8b61bc0b86a2e2039dd7995bac3e38143fc744a89b351b3ba6a967019842b0099e02ae87ca7c5c929935ea27180a9f02849b34e7396149c6d6db40b4b69aef0c85f7725f7218b31795bc98829c512b689914a50c1c9e15489e54ea8c57b28c4a2142c1c72b88424a7b9ac7c4f612a0725daf095c8de7a0d2a92ac34c042fd223b3f7a937704c6e60bab4887b46635bc0084ce5d8862088563a196522ca7fc6e917a5ca895424778c6624c237425f4b2c98d206defa82335638a42abeb97b46f327312ce23140243433118079d0bdd95c5ae806761f9774948321c4f081c300451e5542195b0a07999f225b2e9b6a3b125336d3fc9fd0884ce0a1068de158fab229d73a865d550786542af6c54095b88f21ecb207da9c5dc74ca88124ef4b76e6d46ce9ac12a4ecadfb322526d8b42f0aa8f2329783961cccfa1ad3c0430a8a262a211563360e68104a8e903337b03fb715a728db5e6b861656e730a54a1a3f887c17b29050c4a9fefc70f7565ff1804a81b48b2239b0dd01c1003b980ab48919ac496e823b227900286b3f9cc92df81bcfe5b146355a94cc93ab64c0b6df38eccab8b16f84038256c344dd4449aae52821a49ed62df1767d1a4b"), 0, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.ML_KEM768,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantNoPrefix,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext:  mustHexDecode(t, "6e08d6eefbfad9dee9b790cdc9915a59e6542801b520e85a255863ad4d5adf25616af144f2885d54238c3f757e463b71fb9cd8bbe2526a8ff51c936d7cf815ab71fa8373aa3868f2695d0b83dc79f31295b053edbcd0a6a0f5e14f0fd5022d10c319656a2c03ebd062bc07ba673c9d9c991cae7bc79db93d7bf26e2607a9346cb4a7f10d3b6cd8a9949bca76acdaa92b89b5621f1aa1a23bc7800874ac9ac539149ddd8f50ddc9303699fd45b616e6992d1e4f1a83063603101cb49abae7ad17d4a3923dcee581a21e42993b9cd0520d01f2ca1bd2524f489df750eb10d00acc9c9f36871e62098c6711779ee1ee304fe486a816223e3d6f01e99b027e6ee2831f92889c35a21652e238d18e817ec6c3fa2a1325753fa6b08ec22dd7dcad0f9a115ed3560a40a27a1a1e82f3982a979fe41bc4c2a41d402a01d0ec085b249fd00a48d0719204c383e417087b452e5f6ca2bffd092a21a32352fb04feb058d53650ecd6ae43e8415c0a28749c39cb39bc8ac9452b8a068a0e8ebf83a60d58760a2080489f8eeb64a602825f479fbdf9cde5581bfe538cbd98b38262936ec9d52dc63a4b5fe6b3cc5921fde14d7c7782ba4e6ef43ddbf1db0fd1cb595a115aabe6b758fcfbf3c8a7b008fe8ad713d09f1b059d0e5c653d1d89ea02ff65ff2f297f48f0dc64dbb39debce0e1d059220b7b3c429df489756f284e670b0ebabc0c5f904e0cdcdfedb4f32b53493d7aa509dc29353ae3040aa391f634b869e3bd19f914d219d77a56cc4d1c1aee0bb27a0759c5408d4186c7b0801716ea034254e14f313fa2b127f0ac70508934a869aa89b59df9627e3d90c191d39f4925e9551277fe88ab36beae89760ca67d205e13348a9c00b780c7a5af6f730ec9ab3d221ba61021a6c0700fd7b3de07dcffaff98b142927970fb73958c0d66b7b0cfd93c12d0dcb3f496c9e52f2bd994dfb7e8afffcc7dd0f67f7895e631fe1db997716e1d67c8d4e42cc633a66d179312a39aeb514c001aa3069cc1f20919113915526d2e22cd8b16cb0ad5a67a860f7ef93bef469e45cca744808105155c8451c0a046da7dffb876e09dc7d7c64c34b54ee1c0061a23c66458e5bd141b05b7d7aaadbd9b660ad86474a0ea21e0474b950ac1d8af8d56cc2b8961682975d0cc515ccca0d369f1a0a46e8ffc66c74754d18bff1984afdd63345c9318aa4fda7e8e642c6f218beb580b1cfdef259ecc8c8f01050acd32462c8f685eb51f9f8d1f90fd1a5410b2090bb228f7c91247de3ee28ecaa0a72a73ae0f776c1738bfd9800367cefd74892c8e90ec936cd220a8a36784584903bb14dd8967abb00338957f70c4b93df6160c97073bc51b734c6451872cc1f77444fede068b8069ef6a317605f65b1c8f5e8fd51fd7f7895f2e4b25d8f54dc711a97510f1b369ea3c2b0873b3392b5bbb1019c9e67a400e43c65c1684fe44f8ba3b2f3c33ef2e7418b95105632f2ca3b37a01824e7728937acd216d53c14e2a6bbb30fda102c3acf41633a6a49f64fe19986e42dbf4db214eef894b6b68fc28ff2db7"),
		},
		hybridEncryptTestVector{
			name: "ML-KEM-1024, HKDF-SHA384, AES-256-GCM, No Prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "c58f733ea1245a7a54723c30dbf0837acdd7e93c188692523b53b132b993a25af933368a76bbcbf1212e1d34d7128e32c387dc9b04a7ceb0e2b40e1e5769c57d"),
				mustCreatePublicKey(t, mustHexDecode(t, "94c27955cc5863380245cbb32d564f4d86579f130e96947391f382f9931843965a99db8724f08cd6128cfcd1c98be3733fc5b3171531f9060b9d90528770aff2dac0d37451beb30428161ef818b641273b62c4c83b0b84b75565fdb9433ea32ec4bac540e57c2c6422144511edd6b0623b5f5751c8d0954912dcceef4609520128f8f81ee77045860633ec597bc3d116a6251d30843a274945ffb70389f30587497898f82669b0baa3b17dae3167ece26040a24a20407547f49014a6a25732c4ef1259cbc78bb92c9e787668da8c53e9b4c189d451e9447c5053b0edf3964c6655ae919a00c49a09384d0a5cbf0e889e499255c7f9a71420768e5016fac579eb127b71e18df5ea4b7a53bca7d97ce9898ef59acf36a6237427ae06b80ad0a594c6f52003dcca5dd36efff979b3a67a2455917121414d27aeb4f1a627d45edafc1f064621d20c82299250a39570c2e4999429b71fb87681b693f5d330ee01c8e2531b4b4088adb3ab18c057f6e532e38a5b03d69f382c24e7140fe1876851f735e8442093226f56686cff4457141c68099cc942ac2956b06745881c29bc5571580d2e2c56b8946634b17a46882188e09949b49ffe29376192846bfb3177c7191c0137cdab79df179a6226456b883a3fb42768bb0ec7e5a808e1670582a6ad39281e88afd9b0514ee50956d5178e5b9f4265292b5b5f28644ec2dccf2850c567152e5dea88dc185a800559d545969be9c90fc366f441a1cc79bf95d0bafac1a4d491c5eb169dc26b6a2193b9500120bdd1492546a79db13a2df56f66ac40ab58937d9550b71aa5812038d284566932cd001a0af6a285c0540260bcc323528fb337a2768c840676536466b0ee24c42494a661b176e36a98c99c31190555d7951f4ce4ca342a70dc5a2896d4b35e3064f5a32556b85bfd807673c670c6840609932df7c83504dcc56a036836f9b55c14a948928622013382c96f875ba69ec7363e47420c08adfeb4b894578f2ec8a966e341a6838521bb533a604e0dc92745b39231035b722907797a531833437054545ea7c857b29f728a158f475b2be3774615a716b9799ef8091150afd3d0bef530498f849fa6b99033778945f9be8250334fbc79b6124c27e11bad9a7b7c1248fc5306a85c0d0aac8f71ac9e062500ae688ab7ea304c22123a8aca343c84248b9b19495885585730340132149b474c26d51c1f36f3789948adb18254424a73d7030f87e90fe98a93473a8e08b5070728adcd4cab4d3049bd7ca5313158e35c4eb5832cc7d50cca6661f6a7aaf0f8800a6559b332b13fa128d3371e0c2a42738a56385cbe64077f07c3386dd5c759186b4cd0387111a131dc35863371f6e389aba0888ff9a2e4999d18f9768ff74b6885a823ca53884759ff4ab630f46df7fb43ebc46c0d494b2a59987da2c4785944754b94875283c0cc11fb4b6418bc457416cf73e762da709b200b0adf448ec5b94911905d98b407d58942f9c09dfeb22f1f8c016b31ba0308494fc44a4e85b200ca227cb3a94c319ca09a3446258be00857f22640d3206adf5878dff9ba20255da9caaaf08725071b9218dc1e1a572cc89a11f00c3b3ca98a534471de38a1c9b618ded76547ccbf1fb538cf78ac4dd8a53898b9d0731111227e1807b06c639c111359c96c991ba709bb16139ed0c1fadacd3a9abb9247087f01aac5673b30a86861283728c0087e683a4c3b2ed0c645f7321521641bf823c2ea0263d1db9e56bbb485f715cfe0671902b5eab9ca2cc2277b36cb751cb471abb79e2410b73cb8ab14b4b47219ad59511ddb9572fc979a0306eecc50ef99a78c2b737d8143cc727632a0bb744753929b8792935228266666692adf276b2d4b8def0475e7685617a4892f6994b90293e9a49d92dc5d427487647625b0a38d8616acd1e590ccdb0a76287967765af9030cb56216b168a6fe21ae98578e08c0c387352612532216642f2017b09e7666df2c3ab7dc17d25b8f8b512b2e6ccd28778084b000d2e03139979bddb29c65d27a5be70dfd7a24d8d6149b604e715647072246384b3a2e42488a63124a41bef79672f3e103d2c302df819710e738cb252e04d37092d3bc5584abbdb76e70e6a59e50859cd6053cd4c44b71c7a23c0df90cafa8b116cbc831a5c4998048a86912c8ba4c3dd1399a1fd014fda88e38712368772684c68880728930425b37b5"), 0, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.ML_KEM1024,
					KDFID:   hpke.HKDFSHA384,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantNoPrefix,
				})),
			),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext:  mustHexDecode(t, "1b4d05b2f28021af9a216c4f80188c6bdc2c136d6fff3efac4f98f9b56cd48e0f6c2733fc943247dc29a9e0ab87c2dd309720e3b35e597a192dbf838b5bf34548a74ea1a98612f48a227259ee47711a94d61357c7d95699bc49bbba3b78a45a5c52496a9fbbfc4dae95d988d6137004a24831a154c95f770469219f12f71fffb20c67cc4f1ee2b153d8dd10926f27c51eefe3db2d59f4bd23bfe5d9d5e4c14b261900dd27f797978a2db76a7e46c555c85f263667c1f8c24cc451176a7716a064e4ebb7a3df634c7a07aa637d2993531ec140b46706913fbb5b1628ff120f3883478516339e2523395c4f12286b3898f7af17aeb926fa7b907237c9ea781f7457d0039f0425901a275c49936aa3caad640b0b7ef66789da66811dfc1052f470e92729ec5d9341f5fd7f7caef1beb1feae4dd9255262f54649ba70cb4122feca06d4e30835f18706931e358277a9674b34150f64452b13eace7cc32572143b0baeee6a3fd0075a08067960074ac883db525ce3011e53e7e9713401657cd17447547c74982a5b7b7aaeedfeb2d1767bb0121c3f97b461cfda0cac5227d72ec132a616e163836a169788a59fa4548ab5cb5c47db5c6a3842baf9ae9222de0b7ae051a145060956b2203fd58dc2be9a33889ecc95e2209f1b0fba6b64c84bd59dba1464aed1746b1e71fdb90cee4b48fcef0756edd4c553a203a945b32adb69f5fb6bd7fc95cfe32a58df811cae12341872da32eddded0b2f1878776071dfe00f99696e84a92a4ab8a33bf8a7d5f54b50c33f953d19dcde3d996530ba99f10c89d0f0f7f2cc66f77d90b3c784abdff344215eb292d7c95bcb991cb84aaf537ca660137a3ec20c5ba1e78f41092571f5550e39e862047859b0bf9bdc9b82a1d6e9e91bca296ed683f6866bb1b5cbcacbec1e56794241ad72403ed3cf71fb0414fa6300bb23b730be776acb3574422bfb1b2247835b07e85ce88baf70ea506c5c0870844d64ea8e3392d04724e511da151362f5139cb851c9e803b5630140f9d972029a0ccff84748c5f17fb8e1bcb8c0e2e9dc0347b915d1c6bb9fd8cadaaadd08d1b5df712b8ac63fcecdbbb6e5d3a76a47fa1c6c97c9c4e514e8c762e277f5e11692e2e29ee7fe30dae10096346857ed68b7cfa9d40ab11d21235a54a663ad66d4e9238bee4379ac0d2351553eed6a74a06a132da8a89ad30621ab259bef4012eed653a9fc69f3c7357e4b92f65f4ff85cdd7e82771d8b289fbe4cb25646df29c160bf80436a427f23bc3ce5ae6d2872ded323f823061921999238a50eb243ebc5b9bb15e28c87e096c32f0d79b932da8f58f0b082e4e0815944af906b7d13654532673ebe6ce9b3c12a15754945dfe138d51c3936c6991f305409d6e0adb98da69aa4d73cfc47e14ca3292c2f0247e6be23e255a453c47f9b45467f44ee091f53979dbcd40383906b276c5de1d096b2ac861eddd2bd8d64720013262835aeee5d930dd987ee1117cdc6425f07654c45c31c36b23c8c96074ac3b9aaf330df8da29d6849112bdffc38ae50c81b8ef9a731243812d30bf05a5f63d427f32222a25582b6fe964d3bd2d2e6b8e080c03e9438c7af0db51df653b208f49f71d68ab530aec376e94d5da4a842b903fe83daca59bef78c9cb58cd0729c1060198d6157e4608dea8b21b01f308ec95e6e77051034af3b06dda26a2860f92537226027d5299062f804ece07409a71302af3a74dd6fc805e479c56c7214d7ded3738cca54c6c9e94495fde784f456f7dc2a91fae8015c6fee70e694809911fea3ae01a5b09b769916fc9b500e77fc26fc4e726b7cb3393342df1a1ae391e8b3cdf63baec66309b60a7f073e9489580c33bf05c413931b645f20575e0a8230f30ce478113f03171f71e97d024ebd0406dd5c0c3aaf4440b12762f3e083e636dbf5aea767690e6bb20155049dfd5f795e8dc54a5f5299e4e2160c0ead869765911128575c1ea4522866e087a0211118ee5342dce697562af4a96859b79fc06601bda31bb9bff2cc22e54f0e2fb1fb3f047f09231f5de89513ae6f1a65aea3f279417b5260535199e95eecd898169b0021ee77d89eba96d8c3c538192ae9055ede96fed4277185a502c8b9ad07d23755a4071c275f26dbf8c352af034427858a1c533a0a46d158c276f9cdf08d5e05383a9f7e1785172f02bdf5d3d5dbed76734e58fc6b67eab9f11834386d442fda74fba465387f38746d0"),
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

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
	"bytes"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/hybrid/hpke"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

type keyTestCase struct {
	name            string
	params          *hpke.Parameters
	publicKeyBytes  []byte
	privateKeyBytes secretdata.Bytes
	idRequirement   uint32

	wantOutputPrefix []byte
}

func mustCreateParameters(t *testing.T, opts hpke.ParametersOpts) *hpke.Parameters {
	t.Helper()
	params, err := hpke.NewParameters(opts)
	if err != nil {
		t.Fatalf("hpke.NewParameters() err = %v, want nil", err)
	}
	return params
}

func mustHexDecode(t *testing.T, hexString string) []byte {
	t.Helper()
	b, err := hex.DecodeString(hexString)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", hexString, err)
	}
	return b
}

var (
	// From https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.1
	x25519PublicKeyBytesHex  = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
	x25519PrivateKeyBytesHex = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"

	// From https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.3
	p256SHA256PublicKeyBytesHex = "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32" +
		"5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
	p256SHA256PrivateKeyBytesHex = "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb"

	// From https://github.com/tink-crypto/tink-java/blob/v1.17.0/src/main/java/com/google/crypto/tink/hybrid/internal/testing/HpkeTestUtil.java#L60
	p384PublicKeyBytesHex = "04" +
		"9d92e0330dfc60ba8b2be32e10f7d2f8457678a112cafd4544b29b7e6addf0249968f54c732aa49bc4a38f467edb8424" +
		"81a3a9c9e878b86755f018a8ec3c5e80921910af919b95f18976e35acc04efa2962e277a0b2c990ae92b62d6c75180ba"
	p384PrivateKeyBytesHex = "670dc60402d8a4fe52f4e552d2b71f0f81bcf195d8a71a6c7d84efb4f0e4b4a5d0f6" +
		"0a27c94caac46bdeeb79897a3ed9"

	// From https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.6
	p521SHA512PublicKeyBytesHex = "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8" +
		"900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731" +
		"ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0" +
		"692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0"
	p521SHA512PrivateKeyBytesHex = "014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d5354" +
		"15a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b"

	// From https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.html.
	xWingPublicKeyBytesHex  = "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534"
	xWingPrivateKeyBytesHex = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"

	// From https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html
	mlKEM768PublicKeyBytesHex   = "0665cd16340cd373c7a7290f9ce315ddb57b61778aebd15fae817be1622f5f13380cbbaa61f9749141133606802d69a62d979d1aa04dcd6b073bc4b96612a8435a6578f86a8aa763fc2abdfbf30d35a6aeb8919cf0b7cad876bb1bc410a72159bf927b9e8a0ef56463162a45479166a98336412c4eb8042a70965df419a62163bc70cb567a3344dd86b3a282a32bd57d9518b82245aa8c0c603d36a057f0bffbb39ca67c18b8ac06344a441d2a6027dc7f261804cb2b94e9557820f7518e8b9f97952b953903ef89ae49eb34e4c0a9bf54797ce1535ca8a84a94c55730a909faa7cf467f1c72414a99a41a439e74499c51689f9ea7938fac45813749c42b7d6ba13acc447d31052ceb9730e86b046fb47c18935c55f22d88e8a8987b7c02d0452c3b56d492a7f6718c7ce0c7916a3f905818df6a3caac037ec49a964d965e147aea4a273e9fca7dd57af51638eac08bc77388aa4091ec9b12ab8929d72fabf7deca2469b25862b197406c9f0e479c40c257c809656465f076914cd3a2195c2629880c323a97236da39795985ced810e420527e1418dcabb2b5f8944d4433ba172b4100a7393a5263324b2f9008d90957e5cb0f9c7a924851121ec0808a8c4ea53a9f853a6b2f4a1ba4496d40c746ee646317025d477127f897379ae8b683318038a932902668f0147af7f05cc7b37c4c90b7525062d468bc1106529d39673ffba1cad6c2e93c327d92ac44485e84c768b34743eee6781e45261025af650ab85da3c0af7a66d616a5eafc3bf7b30ce94a4740412384966edd992beb8ba695dbc225f52c72e64d1e6c40dbe1013b840f9fc61d72530e0396048e1980c99751423a25874518be123a6f89556c8c270a736d1cc45fa4a5a6ad142e570c4d8974caa0368f1501a8a3d72a39cbafd441532d612901b454dc523de86b97aac84350a703db44869f4ac3a0dc7533723a31d9166bd33b72e8caf2f13364cc1934047952b370b0bc37664b772fa91e262b95ec40519dd46515b99284d193c4738f854b3d6ba56cc819badb8b61bc0b86a2e2039dd7995bac3e38143fc744a89b351b3ba6a967019842b0099e02ae87ca7c5c929935ea27180a9f02849b34e7396149c6d6db40b4b69aef0c85f7725f7218b31795bc98829c512b689914a50c1c9e15489e54ea8c57b28c4a2142c1c72b88424a7b9ac7c4f612a0725daf095c8de7a0d2a92ac34c042fd223b3f7a937704c6e60bab4887b46635bc0084ce5d8862088563a196522ca7fc6e917a5ca895424778c6624c237425f4b2c98d206defa82335638a42abeb97b46f327312ce23140243433118079d0bdd95c5ae806761f9774948321c4f081c300451e5542195b0a07999f225b2e9b6a3b125336d3fc9fd0884ce0a1068de158fab229d73a865d550786542af6c54095b88f21ecb207da9c5dc74ca88124ef4b76e6d46ce9ac12a4ecadfb322526d8b42f0aa8f2329783961cccfa1ad3c0430a8a262a211563360e68104a8e903337b03fb715a728db5e6b861656e730a54a1a3f887c17b29050c4a9fefc70f7565ff1804a81b48b2239b0dd01c1003b980ab48919ac496e823b227900286b3f9cc92df81bcfe5b146355a94cc93ab64c0b6df38eccab8b16f84038256c344dd4449aae52821a49ed62df1767d1a4b"
	mlKEM768PrivateKeyBytesHex  = "e3408aae322a3628a4d641c2690d4eb212fd66f369782f2dd22fa293476c69957716be20e83920cd26a7710110a34ac3d5da7d90efdc9759812f5cf1a47e85bf"
	mlKEM1024PublicKeyBytesHex  = "94c27955cc5863380245cbb32d564f4d86579f130e96947391f382f9931843965a99db8724f08cd6128cfcd1c98be3733fc5b3171531f9060b9d90528770aff2dac0d37451beb30428161ef818b641273b62c4c83b0b84b75565fdb9433ea32ec4bac540e57c2c6422144511edd6b0623b5f5751c8d0954912dcceef4609520128f8f81ee77045860633ec597bc3d116a6251d30843a274945ffb70389f30587497898f82669b0baa3b17dae3167ece26040a24a20407547f49014a6a25732c4ef1259cbc78bb92c9e787668da8c53e9b4c189d451e9447c5053b0edf3964c6655ae919a00c49a09384d0a5cbf0e889e499255c7f9a71420768e5016fac579eb127b71e18df5ea4b7a53bca7d97ce9898ef59acf36a6237427ae06b80ad0a594c6f52003dcca5dd36efff979b3a67a2455917121414d27aeb4f1a627d45edafc1f064621d20c82299250a39570c2e4999429b71fb87681b693f5d330ee01c8e2531b4b4088adb3ab18c057f6e532e38a5b03d69f382c24e7140fe1876851f735e8442093226f56686cff4457141c68099cc942ac2956b06745881c29bc5571580d2e2c56b8946634b17a46882188e09949b49ffe29376192846bfb3177c7191c0137cdab79df179a6226456b883a3fb42768bb0ec7e5a808e1670582a6ad39281e88afd9b0514ee50956d5178e5b9f4265292b5b5f28644ec2dccf2850c567152e5dea88dc185a800559d545969be9c90fc366f441a1cc79bf95d0bafac1a4d491c5eb169dc26b6a2193b9500120bdd1492546a79db13a2df56f66ac40ab58937d9550b71aa5812038d284566932cd001a0af6a285c0540260bcc323528fb337a2768c840676536466b0ee24c42494a661b176e36a98c99c31190555d7951f4ce4ca342a70dc5a2896d4b35e3064f5a32556b85bfd807673c670c6840609932df7c83504dcc56a036836f9b55c14a948928622013382c96f875ba69ec7363e47420c08adfeb4b894578f2ec8a966e341a6838521bb533a604e0dc92745b39231035b722907797a531833437054545ea7c857b29f728a158f475b2be3774615a716b9799ef8091150afd3d0bef530498f849fa6b99033778945f9be8250334fbc79b6124c27e11bad9a7b7c1248fc5306a85c0d0aac8f71ac9e062500ae688ab7ea304c22123a8aca343c84248b9b19495885585730340132149b474c26d51c1f36f3789948adb18254424a73d7030f87e90fe98a93473a8e08b5070728adcd4cab4d3049bd7ca5313158e35c4eb5832cc7d50cca6661f6a7aaf0f8800a6559b332b13fa128d3371e0c2a42738a56385cbe64077f07c3386dd5c759186b4cd0387111a131dc35863371f6e389aba0888ff9a2e4999d18f9768ff74b6885a823ca53884759ff4ab630f46df7fb43ebc46c0d494b2a59987da2c4785944754b94875283c0cc11fb4b6418bc457416cf73e762da709b200b0adf448ec5b94911905d98b407d58942f9c09dfeb22f1f8c016b31ba0308494fc44a4e85b200ca227cb3a94c319ca09a3446258be00857f22640d3206adf5878dff9ba20255da9caaaf08725071b9218dc1e1a572cc89a11f00c3b3ca98a534471de38a1c9b618ded76547ccbf1fb538cf78ac4dd8a53898b9d0731111227e1807b06c639c111359c96c991ba709bb16139ed0c1fadacd3a9abb9247087f01aac5673b30a86861283728c0087e683a4c3b2ed0c645f7321521641bf823c2ea0263d1db9e56bbb485f715cfe0671902b5eab9ca2cc2277b36cb751cb471abb79e2410b73cb8ab14b4b47219ad59511ddb9572fc979a0306eecc50ef99a78c2b737d8143cc727632a0bb744753929b8792935228266666692adf276b2d4b8def0475e7685617a4892f6994b90293e9a49d92dc5d427487647625b0a38d8616acd1e590ccdb0a76287967765af9030cb56216b168a6fe21ae98578e08c0c387352612532216642f2017b09e7666df2c3ab7dc17d25b8f8b512b2e6ccd28778084b000d2e03139979bddb29c65d27a5be70dfd7a24d8d6149b604e715647072246384b3a2e42488a63124a41bef79672f3e103d2c302df819710e738cb252e04d37092d3bc5584abbdb76e70e6a59e50859cd6053cd4c44b71c7a23c0df90cafa8b116cbc831a5c4998048a86912c8ba4c3dd1399a1fd014fda88e38712368772684c68880728930425b37b5"
	mlKEM1024PrivateKeyBytesHex = "c58f733ea1245a7a54723c30dbf0837acdd7e93c188692523b53b132b993a25af933368a76bbcbf1212e1d34d7128e32c387dc9b04a7ceb0e2b40e1e5769c57d"
)

func mustCreateKeyTestCases(t *testing.T) []keyTestCase {
	t.Helper()
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	x25519PrivateKeyBytes := mustHexDecode(t, x25519PrivateKeyBytesHex)

	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)
	p256SHA256PrivateKeyBytes := mustHexDecode(t, p256SHA256PrivateKeyBytesHex)

	p384PublicKeyBytes := mustHexDecode(t, p384PublicKeyBytesHex)
	p384PrivateKeyBytes := mustHexDecode(t, p384PrivateKeyBytesHex)

	p521SHA512PublicKeyBytes := mustHexDecode(t, p521SHA512PublicKeyBytesHex)
	p521SHA512PrivateKeyBytes := mustHexDecode(t, p521SHA512PrivateKeyBytesHex)

	xWingPublicKeyBytes := mustHexDecode(t, xWingPublicKeyBytesHex)
	xWingPrivateKeyBytes := mustHexDecode(t, xWingPrivateKeyBytesHex)

	mlKEM768PublicKeyBytes := mustHexDecode(t, mlKEM768PublicKeyBytesHex)
	mlKEM768PrivateKeyBytes := mustHexDecode(t, mlKEM768PrivateKeyBytesHex)
	mlKEM1024PublicKeyBytes := mustHexDecode(t, mlKEM1024PublicKeyBytesHex)
	mlKEM1024PrivateKeyBytes := mustHexDecode(t, mlKEM1024PrivateKeyBytesHex)

	testCases := []keyTestCase{
		keyTestCase{
			name: "DHKEM_X25519_HKDF_SHA256-AES256GCM-Tink",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
			publicKeyBytes:   x25519PublicKeyBytes,
			privateKeyBytes:  secretdata.NewBytesFromData(x25519PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "DHKEM_X25519_HKDF_SHA256-AES256GCM-NoPrefix",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
			publicKeyBytes:  x25519PublicKeyBytes,
			privateKeyBytes: secretdata.NewBytesFromData(x25519PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:   0,
		},
		keyTestCase{
			name: "DHKEM_P256_HKDF_SHA256-AES256GCM-Tink",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
			publicKeyBytes:   p256SHA256PublicKeyBytes,
			privateKeyBytes:  secretdata.NewBytesFromData(p256SHA256PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "DHKEM_P256_HKDF_SHA256-AES256GCM-NoPrefix",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
			publicKeyBytes:  p256SHA256PublicKeyBytes,
			privateKeyBytes: secretdata.NewBytesFromData(p256SHA256PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:   0,
		},
		keyTestCase{
			name: "DHKEM_P384_HKDF_SHA384-AES256GCM-Tink",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P384_HKDF_SHA384,
				KDFID:   hpke.HKDFSHA384,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
			publicKeyBytes:   p384PublicKeyBytes,
			privateKeyBytes:  secretdata.NewBytesFromData(p384PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "DHKEM_P384_HKDF_SHA384-AES256GCM-NoPrefix",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P384_HKDF_SHA384,
				KDFID:   hpke.HKDFSHA384,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
			publicKeyBytes:  p384PublicKeyBytes,
			privateKeyBytes: secretdata.NewBytesFromData(p384PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:   0,
		},
		keyTestCase{
			name: "DHKEM_P521_HKDF_SHA512-AES256GCM-Tink",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P521_HKDF_SHA512,
				KDFID:   hpke.HKDFSHA512,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
			publicKeyBytes:   p521SHA512PublicKeyBytes,
			privateKeyBytes:  secretdata.NewBytesFromData(p521SHA512PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "DHKEM_P521_HKDF_SHA512-AES256GCM-Crunchy",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P521_HKDF_SHA512,
				KDFID:   hpke.HKDFSHA512,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantCrunchy,
			}),
			publicKeyBytes:   p521SHA512PublicKeyBytes,
			privateKeyBytes:  secretdata.NewBytesFromData(p521SHA512PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		keyTestCase{
			name: "DHKEM_P521_HKDF_SHA512-AES256GCM-NoPrefix",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P521_HKDF_SHA512,
				KDFID:   hpke.HKDFSHA512,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
			publicKeyBytes:  p521SHA512PublicKeyBytes,
			privateKeyBytes: secretdata.NewBytesFromData(p521SHA512PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:   0,
		},
		keyTestCase{
			name: "X-Wing_HKDF_SHA256-AES128GCM-NoPrefix",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.X_WING,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES128GCM,
				Variant: hpke.VariantNoPrefix,
			}),
			publicKeyBytes:  xWingPublicKeyBytes,
			privateKeyBytes: secretdata.NewBytesFromData(xWingPrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:   0,
		},
		keyTestCase{
			name: "ML-KEM-768_HKDF_SHA256-AES128GCM-NoPrefix",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.ML_KEM768,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES128GCM,
				Variant: hpke.VariantNoPrefix,
			}),
			publicKeyBytes:  mlKEM768PublicKeyBytes,
			privateKeyBytes: secretdata.NewBytesFromData(mlKEM768PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:   0,
		},
		keyTestCase{
			name: "ML-KEM-1024_HKDF_SHA384-AES256GCM-NoPrefix",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.ML_KEM1024,
				KDFID:   hpke.HKDFSHA384,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
			publicKeyBytes:  mlKEM1024PublicKeyBytes,
			privateKeyBytes: secretdata.NewBytesFromData(mlKEM1024PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			idRequirement:   0,
		},
	}
	return testCases
}

func TestNewPublicKeyFailsWithInvalidValues(t *testing.T) {
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)

	for _, tc := range []struct {
		name           string
		params         *hpke.Parameters
		publicKeyBytes []byte
		idRequirement  uint32
	}{
		{
			name:           "invalid public key bytes",
			publicKeyBytes: []byte("invalid"),
			idRequirement:  0x123456,
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
		},
		{
			name: "corrupted public key bytes",
			publicKeyBytes: func() []byte {
				// Corrupt the last byte.
				key := slices.Clone(p256SHA256PublicKeyBytes)
				key[len(key)-1] ^= 1
				return key
			}(),
			idRequirement: 0x123456,
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
		},
		{
			name:           "incompatible public key bytes for X25519",
			publicKeyBytes: p256SHA256PublicKeyBytes,
			idRequirement:  0x123456,
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
		},
		{
			name:           "incompatible public key bytes for NIST P-256",
			publicKeyBytes: x25519PublicKeyBytes,
			idRequirement:  0x123456,
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hpke.NewPublicKey(tc.publicKeyBytes, tc.idRequirement, tc.params)
			if err == nil {
				t.Errorf("hpke.NewPublicKey(%v, %v, %v) err = nil, want non-nil", tc.publicKeyBytes, tc.idRequirement, tc.params)
			}
		})
	}
}

type stubKey struct{}

var _ key.Key = (*stubKey)(nil)

func (k *stubKey) Parameters() key.Parameters    { return nil }
func (k *stubKey) Equal(other key.Key) bool      { return true }
func (k *stubKey) IDRequirement() (uint32, bool) { return 123, true }

func TestPublicKey_Equal_FalseIfDifferentType(t *testing.T) {
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	params := mustCreateParameters(t, hpke.ParametersOpts{
		KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
		KDFID:   hpke.HKDFSHA256,
		AEADID:  hpke.AES256GCM,
		Variant: hpke.VariantTink,
	})
	publicKey := mustCreatePublicKey(t, x25519PublicKeyBytes, 0x01020304, params)
	if publicKey.Equal(&stubKey{}) {
		t.Errorf("publicKey.Equal(&stubKey{}) = true, want false")
	}
}

func TestNewPublicKey(t *testing.T) {
	testCases := mustCreateKeyTestCases(t)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := hpke.NewPublicKey(tc.publicKeyBytes, tc.idRequirement, tc.params)
			if err != nil {
				t.Fatalf("hpke.NewPublicKey(%v, %v, %v) err = %v, want nil", tc.publicKeyBytes, tc.idRequirement, tc.params, err)
			}
			if got, want := key.PublicKeyBytes(), tc.publicKeyBytes; !bytes.Equal(got, want) {
				t.Errorf("key.PublicKeyBytes() = %v, want %v", got, want)
			}
			if got, want := key.Parameters(), tc.params; !got.Equal(want) {
				t.Errorf("key.Parameters() = %v, want %v", got, want)
			}
			if got, want := key.OutputPrefix(), tc.wantOutputPrefix; !bytes.Equal(got, want) {
				t.Errorf("key.OutputPrefix() = %v, want %v", got, want)
			}
			gotIDRequirement, gotRequired := key.IDRequirement()
			if got, want := gotRequired, tc.params.HasIDRequirement(); got != want {
				t.Errorf("key.IDRequirement() = _, %v, want %v", got, want)
			}
			if got, want := gotIDRequirement, tc.idRequirement; got != want {
				t.Errorf("key.IDRequirement() = %v, _, want %v", got, want)
			}
			otherPubKey, err := hpke.NewPublicKey(tc.publicKeyBytes, tc.idRequirement, tc.params)
			if err != nil {
				t.Fatalf("hpke.NewPublicKey(%v, %v, %v) err = %v, want nil", tc.publicKeyBytes, tc.idRequirement, tc.params, err)
			}
			if !otherPubKey.Equal(key) {
				t.Errorf("otherPubKey.Equal(key) = false, want true")
			}
		})
	}
}

func TestPublicKeyNotEqual(t *testing.T) {
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	// From https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.2
	x25519PublicKeyBytes2 := mustHexDecode(t, "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)

	type keyTestCase struct {
		params         *hpke.Parameters
		publicKeyBytes []byte
		idRequirement  uint32
	}

	for _, tc := range []struct {
		name string
		key1 keyTestCase
		key2 keyTestCase
	}{
		{
			name: "Different HPKE parameters KDFID",
			key1: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
			key2: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA384,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
		},
		{
			name: "Different HPKE parameters variant",
			key1: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
			key2: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantCrunchy,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
		},
		{
			name: "Different ID requirement",
			key1: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				}),
				publicKeyBytes: p256SHA256PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
			key2: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				}),
				publicKeyBytes: p256SHA256PublicKeyBytes,
				idRequirement:  uint32(0x05060708),
			},
		},
		{
			name: "Different public key bytes",
			key1: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes,
				idRequirement:  uint32(0x01020304),
			},
			key2: keyTestCase{
				params: mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				}),
				publicKeyBytes: x25519PublicKeyBytes2,
				idRequirement:  uint32(0x01020304),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicKey1, err := hpke.NewPublicKey(tc.key1.publicKeyBytes, tc.key1.idRequirement, tc.key1.params)
			if err != nil {
				t.Fatalf("hpke.NewPublicKey(%x, %v, %v) err = %v, want nil", tc.key1.publicKeyBytes, tc.key1.idRequirement, tc.key1.params, err)
			}
			publicKey2, err := hpke.NewPublicKey(tc.key2.publicKeyBytes, tc.key2.idRequirement, tc.key2.params)
			if err != nil {
				t.Fatalf("hpke.NewPublicKey(%x, %v, %v) err = %v, want nil", tc.key2.publicKeyBytes, tc.key2.idRequirement, tc.key2.params, err)
			}
			if publicKey1.Equal(publicKey2) {
				t.Errorf("publicKey1.Equal(publicKey2) = true, want false")
			}
		})
	}
}

func mustCreatePublicKey(t *testing.T, publicKeyBytes []byte, idRequirement uint32, params *hpke.Parameters) *hpke.PublicKey {
	t.Helper()
	pk, err := hpke.NewPublicKey(publicKeyBytes, idRequirement, params)
	if err != nil {
		t.Fatalf("hpke.NewPublicKey() err = %v, want nil", err)
	}
	return pk
}

func TestNewPrivateKeyFromPublicKeyFailsWithInvalidValues(t *testing.T) {
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	// From https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.2
	x25519PrivateKeyBytes2 := mustHexDecode(t, "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600")

	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)

	// From https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.4
	p256SHA512PrivateKeyBytes := mustHexDecode(t, "2292bf14bb6e15b8c81a0f45b7a6e93e32d830e48cca702e0affcfb4d07e1b5c")

	for _, tc := range []struct {
		name            string
		publicKey       *hpke.PublicKey
		privateKeybytes secretdata.Bytes
	}{
		{
			name: "invalid X25519 private key bytes",
			publicKey: mustCreatePublicKey(t, x25519PublicKeyBytes, 0x123456, mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			})),
			privateKeybytes: secretdata.NewBytesFromData([]byte("invalid"), insecuresecretdataaccess.Token{}),
		},
		{
			name: "incompatible X25519 private key bytes",
			publicKey: mustCreatePublicKey(t, x25519PublicKeyBytes, 0x123456, mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantCrunchy,
			})),
			privateKeybytes: secretdata.NewBytesFromData(x25519PrivateKeyBytes2, insecuresecretdataaccess.Token{}),
		},
		{
			name: "invalid NIST private key bytes",
			publicKey: mustCreatePublicKey(t, p256SHA256PublicKeyBytes, 0x123456, mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantTink,
			})),
			privateKeybytes: secretdata.NewBytesFromData([]byte("invalid"), insecuresecretdataaccess.Token{}),
		},
		{
			name: "incompatible NIST private key bytes",
			publicKey: mustCreatePublicKey(t, p256SHA256PublicKeyBytes, 0x123456, mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantCrunchy,
			})),
			privateKeybytes: secretdata.NewBytesFromData(p256SHA512PrivateKeyBytes, insecuresecretdataaccess.Token{}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hpke.NewPrivateKeyFromPublicKey(tc.privateKeybytes, tc.publicKey)
			if err == nil {
				t.Errorf("hpke.NewPrivateKeyFromPublicKey(%v, %v) err = nil, want non-nil", tc.privateKeybytes, tc.publicKey)
			}
		})
	}
}

func TestPrivateKey_Equal_FalseIfDifferentType(t *testing.T) {
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	x25519PrivateKeyBytes := mustHexDecode(t, x25519PrivateKeyBytesHex)
	params := mustCreateParameters(t, hpke.ParametersOpts{
		KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
		KDFID:   hpke.HKDFSHA256,
		AEADID:  hpke.AES256GCM,
		Variant: hpke.VariantTink,
	})
	publicKey := mustCreatePublicKey(t, x25519PublicKeyBytes, 0x01020304, params)
	privateKey, err := hpke.NewPrivateKeyFromPublicKey(secretdata.NewBytesFromData(x25519PrivateKeyBytes, insecuresecretdataaccess.Token{}), publicKey)
	if err != nil {
		t.Fatalf("hpke.NewPrivateKeyFromPublicKey() err = %v, want nil", err)
	}
	if privateKey.Equal(&stubKey{}) {
		t.Errorf("privateKey.Equal(&stubKey{}) = true, want false")
	}
}

func doTestPrivateKeyAccessors(t *testing.T, privateKey *hpke.PrivateKey, tc *keyTestCase, wantPublicKey *hpke.PublicKey) {
	if got, want := privateKey.Parameters(), tc.params; !got.Equal(want) {
		t.Errorf("privateKey.Parameters() = %v, want %v", got, want)
	}
	if got, want := privateKey.OutputPrefix(), tc.wantOutputPrefix; !bytes.Equal(got, want) {
		t.Errorf("privateKey.OutputPrefix() = %v, want %v", got, want)
	}
	gotIDRequirement, gotRequired := privateKey.IDRequirement()
	if got, want := gotRequired, tc.params.HasIDRequirement(); got != want {
		t.Errorf("privateKey.IDRequirement() = %v, want %v", got, want)
	}
	if got, want := gotIDRequirement, tc.idRequirement; got != want {
		t.Errorf("privateKey.IDRequirement() = %v, want %v", got, want)
	}
	if got, want := privateKey.PrivateKeyBytes(), tc.privateKeyBytes; !got.Equal(want) {
		t.Errorf("privateKey.PrivateKeyBytes() = %v, want %v", got, want)
	}
	gotPublicKey, err := privateKey.PublicKey()
	if err != nil {
		t.Fatalf("privateKey.PublicKey() err = %v, want nil", err)
	}
	if got, want := gotPublicKey, wantPublicKey; !got.Equal(want) {
		t.Errorf("privateKey.PublicKey() = %v, _, want %v", got, want)
	}
}

func TestNewPrivateKeyFromPublicKey(t *testing.T) {
	testCases := mustCreateKeyTestCases(t)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pubKey, err := hpke.NewPublicKey(tc.publicKeyBytes, tc.idRequirement, tc.params)
			if err != nil {
				t.Fatalf("hpke.NewPublicKey(%v, %v, %v) err = %v, want nil", tc.publicKeyBytes, tc.idRequirement, tc.params, err)
			}
			privKey, err := hpke.NewPrivateKeyFromPublicKey(tc.privateKeyBytes, pubKey)
			if err != nil {
				t.Fatalf("hpke.NewPrivateKeyFromPublicKey(%v, %v) err = %v, want nil", tc.privateKeyBytes, pubKey, err)
			}

			doTestPrivateKeyAccessors(t, privKey, &tc, pubKey)

			otherPrivKeyFromPublicKey, err := hpke.NewPrivateKeyFromPublicKey(tc.privateKeyBytes, pubKey)
			if err != nil {
				t.Fatalf("hpke.NewPrivateKeyFromPublicKey(%v, %v) err = %v, want nil", tc.privateKeyBytes, pubKey, err)
			}
			if !otherPrivKeyFromPublicKey.Equal(privKey) {
				t.Errorf("otherPrivKeyFromPublicKey.Equal(privKey) = false, want true")
			}
			// Check equivalence with NewPrivateKey.
			otherPrivKey, err := hpke.NewPrivateKey(tc.privateKeyBytes, tc.idRequirement, tc.params)
			if err != nil {
				t.Fatalf("hpke.NewPrivateKey(%v, %v, %v) err = %v, want nil", tc.privateKeyBytes, tc.idRequirement, tc.params, err)
			}
			if !otherPrivKey.Equal(privKey) {
				t.Errorf("otherPrivKey.Equal(privKey) = false, want true")
			}
		})
	}
}

func TestNewPrivateKey(t *testing.T) {
	testCases := mustCreateKeyTestCases(t)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pubKey, err := hpke.NewPublicKey(tc.publicKeyBytes, tc.idRequirement, tc.params)
			if err != nil {
				t.Fatalf("hpke.NewPublicKey(%v, %v, %v) err = %v, want nil", tc.publicKeyBytes, tc.idRequirement, tc.params, err)
			}
			privKey, err := hpke.NewPrivateKey(tc.privateKeyBytes, tc.idRequirement, tc.params)
			if err != nil {
				t.Fatalf("hpke.NewPrivateKey(%v, %v, %v) err = %v, want nil", tc.privateKeyBytes, tc.idRequirement, tc.params, err)
			}

			doTestPrivateKeyAccessors(t, privKey, &tc, pubKey)

			otherPrivKey, err := hpke.NewPrivateKey(tc.privateKeyBytes, tc.idRequirement, tc.params)
			if err != nil {
				t.Fatalf("hpke.NewPrivateKey(%v, %v, %v) err = %v, want nil", tc.privateKeyBytes, tc.idRequirement, tc.params, err)
			}
			if !otherPrivKey.Equal(privKey) {
				t.Errorf("otherPrivKey.Equal(privKey) = false, want true")
			}
			// Check equivalence with NewPrivateKeyFromPublicKey.
			otherPrivKeyFromPublicKey, err := hpke.NewPrivateKeyFromPublicKey(tc.privateKeyBytes, pubKey)
			if err != nil {
				t.Fatalf("hpke.NewPrivateKeyFromPublicKey(%v, %v) err = %v, want nil", tc.privateKeyBytes, pubKey, err)
			}
			if !otherPrivKeyFromPublicKey.Equal(privKey) {
				t.Errorf("otherPrivKeyFromPublicKey.Equal(privKey) = false, want true")
			}
		})
	}
}

func TestPrivateKeyNotEqual(t *testing.T) {
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)
	x25519PrivateKeyBytes := mustHexDecode(t, x25519PrivateKeyBytesHex)
	// From https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.2
	x25519PublicKeyBytes2 := mustHexDecode(t, "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
	x25519PrivateKeyBytes2 := mustHexDecode(t, "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600")

	p256SHA256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)
	p256SHA256PrivateKeyBytes := mustHexDecode(t, p256SHA256PrivateKeyBytesHex)

	type keyTestCase struct {
		publicKey       *hpke.PublicKey
		privateKeyBytes secretdata.Bytes
	}

	for _, tc := range []struct {
		name string
		key1 keyTestCase
		key2 keyTestCase
	}{
		{
			name: "Different parameters",
			key1: keyTestCase{
				publicKey: mustCreatePublicKey(t, x25519PublicKeyBytes, 0x01020304, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				})),
				privateKeyBytes: secretdata.NewBytesFromData(x25519PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			},
			key2: keyTestCase{
				publicKey: mustCreatePublicKey(t, x25519PublicKeyBytes, 0x01020304, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES128GCM,
					Variant: hpke.VariantTink,
				})),
				privateKeyBytes: secretdata.NewBytesFromData(x25519PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			},
		},
		{
			name: "Different public key ID requirement",
			key1: keyTestCase{
				publicKey: mustCreatePublicKey(t, p256SHA256PublicKeyBytes, 0x01020304, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				})),
				privateKeyBytes: secretdata.NewBytesFromData(p256SHA256PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			},
			key2: keyTestCase{
				publicKey: mustCreatePublicKey(t, p256SHA256PublicKeyBytes, 0x05060708, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				})),
				privateKeyBytes: secretdata.NewBytesFromData(p256SHA256PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			},
		},
		{
			name: "Different public and private key bytes",
			key1: keyTestCase{
				publicKey: mustCreatePublicKey(t, x25519PublicKeyBytes, 0x01020304, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				})),
				privateKeyBytes: secretdata.NewBytesFromData(x25519PrivateKeyBytes, insecuresecretdataaccess.Token{}),
			},
			key2: keyTestCase{
				publicKey: mustCreatePublicKey(t, x25519PublicKeyBytes2, 0x01020304, mustCreateParameters(t, hpke.ParametersOpts{
					KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
					KDFID:   hpke.HKDFSHA256,
					AEADID:  hpke.AES256GCM,
					Variant: hpke.VariantTink,
				})),
				privateKeyBytes: secretdata.NewBytesFromData(x25519PrivateKeyBytes2, insecuresecretdataaccess.Token{}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			privateKey1, err := hpke.NewPrivateKeyFromPublicKey(tc.key1.privateKeyBytes, tc.key1.publicKey)
			if err != nil {
				t.Fatalf("hpke.NewPrivateKeyFromPublicKey(%v, %v) err = %v, want nil", tc.key1.privateKeyBytes, tc.key1.publicKey, err)
			}
			privateKey2, err := hpke.NewPrivateKeyFromPublicKey(tc.key2.privateKeyBytes, tc.key2.publicKey)
			if err != nil {
				t.Fatalf("hpke.NewPrivateKeyFromPublicKey(%v, %v) err = %v, want nil", tc.key2.privateKeyBytes, tc.key2.publicKey, err)
			}
			if privateKey1.Equal(privateKey2) {
				t.Errorf("privateKey1.Equal(privateKey2) = true, want false")
			}
		})
	}
}

func TestPrivateKeyCreator(t *testing.T) {
	params, err := hpke.NewParameters(hpke.ParametersOpts{
		KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
		KDFID:   hpke.HKDFSHA256,
		AEADID:  hpke.AES256GCM,
		Variant: hpke.VariantTink,
	})
	if err != nil {
		t.Fatalf("hpke.NewParameters() err = %v, want nil", err)
	}

	key, err := keygenregistry.CreateKey(params, 0x1234)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey(%v, 0x1234) err = %v, want nil", params, err)
	}
	hpkePrivateKey, ok := key.(*hpke.PrivateKey)
	if !ok {
		t.Fatalf("keygenregistry.CreateKey(%v, 0x1234) returned key of type %T, want %T", params, key, (*hpke.PrivateKey)(nil))
	}
	idRequirement, hasIDRequirement := hpkePrivateKey.IDRequirement()
	if !hasIDRequirement || idRequirement != 0x1234 {
		t.Errorf("hpkePrivateKey.IDRequirement() (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 123, true)
	}
	if diff := cmp.Diff(hpkePrivateKey.Parameters(), params); diff != "" {
		t.Errorf("hpkePrivateKey.Parameters() diff (-want +got):\n%s", diff)
	}

	publicKey, err := hpkePrivateKey.PublicKey()
	if err != nil {
		t.Fatalf("hpkePrivateKey.PublicKey() err = %v, want nil", err)
	}
	hpkePublicKey, ok := publicKey.(*hpke.PublicKey)
	if !ok {
		t.Fatalf("hpkePrivateKey.PublicKey() returned key of type %T, want %T", publicKey, (*hpke.PublicKey)(nil))
	}

	// Make sure we can encrypt/decrypt with the key.
	encrypter, err := hpke.NewHybridEncrypt(hpkePublicKey, internalapi.Token{})
	if err != nil {
		t.Fatalf("hpke.NewHybridEncrypt() err = %v, want nil", err)
	}
	ciphertext, err := encrypter.Encrypt([]byte("hello world"), []byte("hello world"))
	if err != nil {
		t.Fatalf("encrypter.Encrypt() err = %v, want nil", err)
	}
	decrypter, err := hpke.NewHybridDecrypt(hpkePrivateKey, internalapi.Token{})
	if err != nil {
		t.Fatalf("hpke.NewHybridDecrypt() err = %v, want nil", err)
	}
	got, err := decrypter.Decrypt(ciphertext, []byte("hello world"))
	if err != nil {
		t.Fatalf("decrypter.Decrypt() err = %v, want nil", err)
	}
	if diff := cmp.Diff(got, []byte("hello world")); diff != "" {
		t.Errorf("decrypter.Decrypt() diff (-want +got):\n%s", diff)
	}
}

func TestPrivateKeyCreator_FailsWithInvalidParameters(t *testing.T) {
	for _, tc := range []struct {
		name          string
		params        *hpke.Parameters
		idRequirement uint32
	}{
		{
			name: "invalid id requirement",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
			idRequirement: 0x1234,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := keygenregistry.CreateKey(tc.params, tc.idRequirement); err == nil {
				t.Errorf("keygenregistry.CreateKey(%v, %v) err = nil, want error", tc.params, tc.idRequirement)
			}
		})
	}
}

func TestPrivateKeyCreator_CreateMultipleDiffers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params *hpke.Parameters
	}{
		{
			name: "DHKEM_P256_HKDF_SHA256",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
		},
		{
			name: "DHKEM_P384_HKDF_SHA384",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P384_HKDF_SHA384,
				KDFID:   hpke.HKDFSHA384,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
		},
		{
			name: "DHKEM_P521_HKDF_SHA512",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_P521_HKDF_SHA512,
				KDFID:   hpke.HKDFSHA512,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
		},
		{
			name: "DHKEM_X25519_HKDF_SHA256",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.DHKEM_X25519_HKDF_SHA256,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
		},
		{
			name: "X-Wing",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.X_WING,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES128GCM,
				Variant: hpke.VariantNoPrefix,
			}),
		},
		{
			name: "ML-KEM-768",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.ML_KEM768,
				KDFID:   hpke.HKDFSHA256,
				AEADID:  hpke.AES128GCM,
				Variant: hpke.VariantNoPrefix,
			}),
		},
		{
			name: "ML-KEM-1024",
			params: mustCreateParameters(t, hpke.ParametersOpts{
				KEMID:   hpke.ML_KEM1024,
				KDFID:   hpke.HKDFSHA384,
				AEADID:  hpke.AES256GCM,
				Variant: hpke.VariantNoPrefix,
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key1, err := keygenregistry.CreateKey(tc.params, 0)
			if err != nil {
				t.Fatalf("keygenregistry.CreateKey(%v, 0) err = %v, want nil", tc.params, err)
			}
			key2, err := keygenregistry.CreateKey(tc.params, 0)
			if err != nil {
				t.Fatalf("keygenregistry.CreateKey(%v, 0) err = %v, want nil", tc.params, err)
			}
			if key1.Equal(key2) {
				t.Errorf("key1.Equal(key2) = true, want false")
			}
		})
	}
}

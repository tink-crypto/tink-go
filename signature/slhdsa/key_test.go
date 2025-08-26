// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package slhdsa_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature/slhdsa"
)

func TestNewParameters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType slhdsa.HashType
		keySize  int
		sigType  slhdsa.SignatureType
		variant  slhdsa.Variant
	}{
		{
			name:     "tink",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			variant:  slhdsa.VariantTink,
		},
		{
			name:     "no prefix",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			variant:  slhdsa.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant)
			if err != nil {
				t.Errorf("slhdsa.NewParameters(%v, %v, %v, %v) err = %v, want nil", tc.hashType, tc.keySize, tc.sigType, tc.variant, err)
			}
			if got := params.HashType(); got != tc.hashType {
				t.Errorf("params.HashType() = %v, want %v", got, tc.hashType)
			}
			if got := params.KeySize(); got != tc.keySize {
				t.Errorf("params.KeySize() = %v, want %v", got, tc.keySize)
			}
			if got := params.SignatureType(); got != tc.sigType {
				t.Errorf("params.SignatureType() = %v, want %v", got, tc.sigType)
			}
			if got := params.Variant(); got != tc.variant {
				t.Errorf("params.Variant() = %v, want %v", got, tc.variant)
			}
		})
	}
}

func TestNewParametersFails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType slhdsa.HashType
		keySize  int
		sigType  slhdsa.SignatureType
		variant  slhdsa.Variant
	}{
		{
			name:     "unknown",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			variant:  slhdsa.VariantUnknown,
		},
		{
			name:     "invalid hash type",
			hashType: slhdsa.SHAKE,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			variant:  slhdsa.VariantTink,
		},
		{
			name:     "invalid key size",
			hashType: slhdsa.SHA2,
			keySize:  128,
			sigType:  slhdsa.SmallSignature,
			variant:  slhdsa.VariantTink,
		},
		{
			name:     "invalid signature type",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.FastSigning,
			variant:  slhdsa.VariantTink,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant); err == nil {
				t.Errorf("slhdsa.NewParameters(%v, %v, %v, %v) err = nil, want error", tc.hashType, tc.keySize, tc.sigType, tc.variant)
			}
		})
	}
}

func TestParametersHasIDRequirement(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType slhdsa.HashType
		keySize  int
		sigType  slhdsa.SignatureType
		variant  slhdsa.Variant
		want     bool
	}{
		{
			name:     "tink",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			variant:  slhdsa.VariantTink,
			want:     true,
		},
		{
			name:     "no prefix",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			variant:  slhdsa.VariantNoPrefix,
			want:     false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v, %v, %v, %v) err = %v, want nil", tc.hashType, tc.keySize, tc.sigType, tc.variant, err)
			}
			if got := params.HasIDRequirement(); got != tc.want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParametersEqual(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType slhdsa.HashType
		keySize  int
		sigType  slhdsa.SignatureType
	}{
		{
			name:     "SLH-DSA_SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
		},
	} {
		t.Run(fmt.Sprintf("%s", tc.name), func(t *testing.T) {
			tinkVariant, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			noPrefixVariant, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want	 nil", slhdsa.VariantNoPrefix, err)
			}

			if !tinkVariant.Equal(tinkVariant) {
				t.Errorf("tinkVariant.Equal(tinkVariant) = false, want true")
			}
			if !noPrefixVariant.Equal(noPrefixVariant) {
				t.Errorf("noPrefixVariant.Equal(noPrefixVariant) = false, want true")
			}
			if tinkVariant.Equal(noPrefixVariant) {
				t.Errorf("tinkVariant.Equal(noPrefixVariant) = true, want false")
			}
		})
	}
}

const (
	// Copied from Tink C++ SLH-DSA signature verification test.
	privKeySHA2128sHex = "d44f6f06a73a07451096ad4bfbd240cb54b779330a65ed34ec0cd372c96fe48bf2b907c6" +
		"b73d52125c3930a195ef650baf7f68a07f4f3435408ac5ecaafaf4f3"
	pubKeySHA2128sHex = "f2b907c6b73d52125c3930a195ef650baf7f68a07f4f3435408ac5ecaafaf4f3"
	msgSHA2128sHex    = "6d657373616765"
	sigSHA2128sHex    = "677020005c0922919fb6b837c42783b93a71a10db1794c86683f5f22dd1f0b984a66f749" +
		"3cac79fc4a344ba07d1c2b7921e7b2ce50d7e5de20a47c9883059dd8e800a433d962a332" +
		"c3a884f0ae8cc14977baa4d0c9067ea9ac54c52ff9bd715ea8dc5210ff5dee5bdf00541b" +
		"b3d5a05305ba6da0920d35a596040a53f7704a430fa4eee2a21bc6d9dd942fa201cd9316" +
		"0d8e15347460bbef6ca99b0963c6050626855738d98201e8927e8543595422897954c62e" +
		"8263e09a7f97d16a4a268afb7dbe022cc468bb3ff8fdf4cc865675045a010226a67663a1" +
		"299d05913fed902eb3738cf326c45a712ac54ec462eee8bffd0624e7f40d34f24ffec7dd" +
		"00b3c73aa92e3558c003a4103c404790eef989f2dd6c98bf225e5a465a5120b40133fc97" +
		"5fbe82c42c8a15435d55a72b97b13835e4bc6d71cb336659bb6b1ed4d4ceba4e98acd61e" +
		"1180da27efc2ac6879a389b214bc8c4bf450410c786b82c0533a65ea6ce971281ba93de1" +
		"5f3983b57accb464dc9134490e88da36604f0b8bfeee10566c9a7c12cc18a42be2449cf5" +
		"237c4d4c42ec384d77a02bbfeec73b0929dd08dddde0aefc26509c2db2de6c337af131e6" +
		"1487005ab54a3af835942a79a6abaffbd51056cc83231d894d0ca89013af28e93758dd6e" +
		"913326ba459c0261df519b200b849cbd9994b55bfb8b89add46796cea6832fc9cfcda7c4" +
		"181abc2fc119fbe7a264da627a4093e922032fb09f1d87765f3fe03fdd4695b6ffac1e1e" +
		"a638141157960e539630e1b3f8e74b4ec62ed68a349a2020f08c59689e13eabaa7371fd1" +
		"98df194c985d2df93647ebd910f9ccbfc3465fed3fa015d6a890f42e1dd1359b7cd4c59a" +
		"4b0d2743f1acf733efe9f9fc349745048c0fef0e1852fd0e9f5189eae8fb04f98cc3bee0" +
		"a1574f46c4c54a700a0a669175867395a6c7bba1c0c4881db0b8688666beef55cf98c9aa" +
		"e3357f7c5c659daf36e72c2ae7dc2e757957bc45086c207aa2151eca1399f596732d25ba" +
		"17f9de45188eec6782f919daa18e2f7a37cb51a75421bf5d1b9397cad979bbef09a87c7c" +
		"57a871c3cbe0ebf36633281531b2bc9fbde43da9164101fb98204a56fea1d015a0518fd5" +
		"930020cfaf26486c8e20ae54590a2a026ed5f240f38675fbd25b27caa2af4920645bd6df" +
		"2dc49fd393adc95593cc3596c8f9b0c6183389b6bd4a1d1a5b682a41cfaac0dd4727df26" +
		"b4443bc886ed5bda5101a7b2582f59ee41aade795e21e6cb9abc4fcdc3b150c9cea6eb49" +
		"207b806b25020a369563a5ccbff289d808f005460f133dfbf4a621e9c93fc7d74edc0716" +
		"993aa727c4038b8c4855216f2d0301a22541ec1e93846f6c89f1f16dfe5b916bf16e82a5" +
		"e35a09f8865ad28d55833e9a566f7c12cb338e48c1d22c5233d2e17fee5b09eed81dfc65" +
		"5fb003f4045082b5269ce7263234bcb68225e403626249bd462f259ffaa065cf38318403" +
		"12d7993219f79e96e42e1e46801c7e809131510007b3aac2ff7c8f897d75109a26fb0d4e" +
		"e8c76a316a666f335a453ef8507a409809dfef3c4b1cf1f89ccf677a649084519dda826e" +
		"ad3d348a290bd1d39eff5f4a21487c210c37aac96e66e4bc9604ef988242a88ae0c24c7b" +
		"034cc1063f3daff93a6c3edcaed6d27fecc521155787389d0398b268e233b1803a35ffc5" +
		"9b94847acdb4685efecafa383971a9d1ff64f093db635221fbca2ddbf90b25cb8e45ce3a" +
		"474d16a9dd3018bd8b9a60287325000c0580004c9486fe4a65f0a9a6370523e1063d08f5" +
		"862ff966e8277ccf27860505944b431e372cc2f85036828e2a3b5c50456bc41deb27aec6" +
		"11b5650b202d13634eba83ed4715f9220b1c6eff1e378a6241b9f400dffd06ac588439a2" +
		"c25ee4b2796ade04d1d4bb2c616a0c6d37c95c0db4bab167f95c2e62682f17e585610562" +
		"f5db06127a1478fdf166ef1e309f1618595b2eddf045f41899697f69bc383b1ca6f25943" +
		"75f1541cc60c9be199d5ebc585daed75d8856e156c356b65d7bb253534102c790d6a14d0" +
		"556c3949f38e3102bf2388ff8afeb0ad0338fdc1e0351293bb84b2164c5922fab682b966" +
		"d7777109d9b180749604c5cadebcaa9b668ce966a93ea0945b8ea7b763c56f23b1b266c7" +
		"d7e155008d50c18d47c8d2ea11fb78e2f97018229c2d78c9815aa50b81ab39eda8e393b3" +
		"f74ca4ad466cafdccdc0cb3eecd992a6941464cdc1d8f14fcc7ed6314efe601c4340eaf9" +
		"edf0d185d5430c26d593100d3dfc0462cd5be9537d973ac4e035b19081a994a6b7041898" +
		"eda75393007013954764a90c4bcab67bccbc19e938c421fcc06f1a30e05fc138930f1746" +
		"74b9210d86ab26e8b5bf0e6adda4bfa9bce04addcf15b0005d508e59fd40b4d0b6ff7ace" +
		"35b37a88fcb7234d6857d0eed91090c9d866b601a8715fdc4aa44a2d19c98a29fe3d68a1" +
		"530b58f862f164530dcd30152d3d048ec3f8b24f17bb1616bab31075a05b120d864cdda3" +
		"071e89f5dfdf3f6050c4456b35d6f4d1a2106fb25c8bf4fc813bcd8b788b1719d0f7b836" +
		"fd65a4c9a0b0c4e64a8fcefd4e9b36093a54019e07d2f2204f4ba1077d388e9bb87ff3a2" +
		"85f7fe70f1f43054a05478485dede6c3e88b890d01709baf64cac191fc4b87f4879b51b9" +
		"75e9c21c0cd2a9288dce44fa998c5fe998748530a5e9c4bacc8d57073c6e0d3068d127f6" +
		"0e55eaae6c0cc205fd7ff17654b4150c5e728907440e96eb49ac1e3a06dc3ddc9615c66d" +
		"4d29f2267211c41d3b2e4281e6c022d5a1fd8ae20475a638ebe5ee520a4f9cb404c0df3f" +
		"ade560e9fae29d22098377e392b2f39fd273a553d881658df7c6650edaf62a4e15d2573e" +
		"18e1c2fe194173ca84b23426463fe14d235a758ab6ad0ca4f17b12801cfa9e3461640a7c" +
		"ed3ec1fd2e9a72786315e8d2da081cf93e14f67ebf7d6482d9bc0f9e4abc1e8e8529e648" +
		"0a3dabb86d927cafb3d08bb9275788230d81c2071540f1aaea0751ebbffb673949f69e6a" +
		"5fdb6f5c9d0f28b9a827bc7325517ab4b30e742f3e98cad59c48fa12b0ef9e885a03bb83" +
		"2c1efe721070cb8c177206d00f286a93f5bea0377ba86f7129dea527caae1e9f4ae9b0cd" +
		"4be6fb174019e04e9d2b0273ce44393d0867a81938625fa7d114b1f36a727614c8cee27b" +
		"25dd4b9411a4c4fc6a9b3007d682abb5f00f8ee12ec52979fe93069bab61349248b9a782" +
		"9731c29b56e87095df83d2d02ec8513886bb7573fe755df88545fd142f682ab9792b9771" +
		"e9cf4df891a28a218ee9f60f266a292834b4fecebcdb6baf1857b622a3a0a6486773b987" +
		"2dc1e4b393ed149669f4a6c30acb931b578c2e0bca6e6d85171af86529500e1d05da6c83" +
		"0ff0bf1eb90c3ccfb0c578903565a7d733466cbf85041bce8c138a8f0f3b6e55b201570d" +
		"252b57d85eb92abcf2ab59a309fb94a78f9207bfd5bf1b828e6c1781f4ef4decf2feedba" +
		"845be48415bf09bf525942be085f426fcd2ad6a2f1f4ec92b189050a1546e7fec1d061c7" +
		"38c29d00e2462f2ce72c483f5b4613ea0c82def0bc289df9e5ba9eebdb0b870a9ab71f08" +
		"c720e4883f72dfa49a05f88d002afc4e43e00e38480fb576ec07b4c014c2973eb994fb67" +
		"771b1b46d632764f7371976219da13d1ea6586fc08e5691a41ebd19da2cdcd730b8d118c" +
		"e1d8322a60262ebd2e0e03b64ef6ea93b2d76c9b7626d760b2efa8d72f00a4667741b749" +
		"c6aa706895c299d57e6822c7a7616efed153a9c3fd907119e9c7309ae428f8154f4ddec1" +
		"953f9731cc39f98982518cdb0e476d46b3873073d0297d4eb0c33df597814fe378cb11bc" +
		"b74c1737625b0d8444e13e9c29e7eab66c06c3dfd63c71fc267199e9df570306cc340d5c" +
		"31e28a6cbe4a78bb81f8f720c5f712ec19931f9df1efb445e1247f8db0e219d03d19b515" +
		"1e50fa162d346dcc39bff43e0b2b4ecb6c5e4977b485a965d4c717ed060378beda79b321" +
		"26052c537cf829a204b81a5b1d76a121d55a00e810beb36b67bb4960480cfb85465db65c" +
		"ac24368885190d59e6424a40c95edc82e9b1088c03339043a88ddb8fc071bf8a74e8c7d2" +
		"6b3576be535a66ce7bede9ce6442402472c43bbbd3306b39275118397a92ce70af9fbeb0" +
		"7ff1b7492316c1f9186ea5117ad26ec621d318786597b3d12d8426a7b98f1308eb8d911e" +
		"501f500f6ba8dd0420e3c6cd06ca9207f2841403404a1c7e1d72982558805fab2104d4b3" +
		"5506b137fa56960099a06f5d824ad0d3a545cfc3215e9b0ce7af8be1ff774357614bd95e" +
		"61a8d5c8919ef2204bf03be20415139eb8e06cffb797445441d3d77c6c98da65d694c285" +
		"cac42657000636ea9bf4c689552a6baedddcd4bc79b3f48aeb68668ae1eee796bc13fbf4" +
		"d23352d1dcf1c501105f0e9785e44ccecf271d08c4c0d5f6578995ecfdd6144398184a98" +
		"55d37e7ea4e3364a876e80da9e025d0e8b5e8e4f61470b0f37d8b8a6739eba236d606595" +
		"3f8d125555e1798e1e8ea9a7042bca0c24aba2c6d3156f99a7ee9644f6c608b07817f670" +
		"6e15f0e77b75ab72fc09789a9e86bdf83685ad0c276d85f119382d2d461cb8bb8a39a857" +
		"4bf7dc49d9b09f1a05c243f9c9b5fbc3f0f09c3169ef44df7fc1b8f7d211139ed0941d2b" +
		"9d91c6513ad67ea19abe63d9959eba1fe354b234a51f9db4c4954e25ca9e14aa4a478381" +
		"28ccefe8fc7c34034c2e3438eb95e5232af4a47191a4bee9e3c00230543382053760a782" +
		"e0ab533d07327776adad619ad4a2cff7fefdcf9b290d07807c5b23fa7a696b914e40f905" +
		"30581ecf2270e28eec1a0c485311e0f57a4807edeabe2eb7a89c4d8411d889c6164a6ff0" +
		"fc9604e410606ad9a3f6837809316d3551491278b141d22e20a2c3eaba47657e08b5e849" +
		"593332b3d1db5f6efd4ace89bd37a3b5d4049b1c06a58c0a9901bd1a9525cfd020b8dc16" +
		"dd8154473789960b47903f66f50e89d23ce637f360076b055c21ab597f45560cc2b7d48f" +
		"463a7d3120e03579371778928c41b36ccc276f52b1e4ffe7603cce185f8acb70f902b749" +
		"e500685bd3973f33ac7232e9b6e57cdbe584db93d852ad1a2654e9bea68a6425a3b21059" +
		"f4e44688de3f301bd042cc897795c83215438157831cb00dd94bb4d9cb42c31c15b6b33b" +
		"982db25c9abd89b008a44846120489b71c24bfd1794cd110799e8d3fe4296a12d35d506d" +
		"c31cfdae7a905e191cff535e12315f35100ddfa87f0004dcb0d549ac3d27e3541a1e90cb" +
		"51eb2e7bc46b98d4eaad72d11fdfebd10ee7f0c55075ab95839c5e7f7f57f142485e15a9" +
		"66e590ee4c697ab4260046731aec31e7a5011026bdaef234dd56c55ced28b18b7aa91940" +
		"ebb509e3a5ea4ba168c553f583c665a82076fd278cf3da36afa1ad3c43bf394aab561706" +
		"39ad3a885532d563e2c285eb8a716e93f04ee1329c8b14e77f8c3c49bb3857bdae9cf91a" +
		"437cc492d24ac74ceab9319459b382035e1026519a17b2c5d6b4923815889694750ed177" +
		"37f478838bd842057f3642515c41fabd0ecc07729c5bbffa788800d916d70d2662c096d4" +
		"34cf47794dbb6db5d17ba9b8f47664759cfc7394aa69219a4c4c58d90cc520dd0c7411e3" +
		"2d7ac9f614de165cbe188a19dcea6569ae8468977aecb5f75abc80f30ece39a9b0e79d70" +
		"47b189d1e00cb69a9fb2e57bca08c50e9693eab405dec5792c92a174beed639f08a85b70" +
		"11ca43a1e7854426996857fb5df6d1951e45846a9f233050d0542d968dd2bf265c3ffa47" +
		"560861fa4ac19438898fdbe6f417e7fea8ef09d6685ac2bcca20020b77baa7b56ed3515c" +
		"e0da3db93d1b101be93e12eca5265501c061d23deb9b5faab13d5f69b0897374c6596bc8" +
		"3c20ab4cf05219a5288beb48614e0bd1e47203ce2dfb56503d076ed30096e47106d755e1" +
		"b2a6ea9a5e7927cecc2373f52c17d8f99b329d4db48b1ad5122ad6604c0e8a4628f08549" +
		"d5317a0ed383aa82f86275d167f04dc5e0a74907b5975557eeababb6e32b26938a90cfbb" +
		"854e1fa0d6aafac8b00c513bed22816919251e231c9476ac4e3b4e8ea317758d18d015af" +
		"56d29c772b00c168a7c7c23e3710a8151325b8795a3ead2144445ce0b7c3e4b2f73dce68" +
		"1352f04becbdcc3800d07a822150bc96b81a90962de171c837fdd263d323f25547aff507" +
		"01f22469310ee209b41b15c0f192325ad475b0ed269ba84244f405f66c08fdaf3e230110" +
		"8914699af8e2b63c6d29093358a30039b06a0b830f263c972210fa429de1e5669ce2a652" +
		"9effd80260121d481d7fc8f111edd46af020209b2d8c668c37fb1a82645413ccf4d6d0c2" +
		"5c4542cbfb55e65c02d5c7ee631615973f2a0a32ed413a7ff07c0c6f804f3c03db1ef539" +
		"a1b151540fc32849b45696797fddf3b970f840b2233f08377783e9cecfd77c4dd2da0c7a" +
		"afb765c6ccbecbffaad01f8460c1c2a649720f8fb61693d430623603b96d98a31401c666" +
		"787df53720f81aec8eeea773dc20279c0892028f3ab7639d98c41ef082f140463dbb7ef5" +
		"33544c7fa14ad9e0501223f2f9ba544bd5f80c5cfae08876c77333cbb8746324160082fe" +
		"9ae9ba505ad16d5ebb921c6dad8cbc75b33cb3ab792266fd49a1b109a2121df8dde069a2" +
		"a51f63eb5c90fc5e7f8df11f123f1b7a7d057b8895d24f5c4471e749aa6e00ff57fb081a" +
		"6602405f1c89a48bfd8479dcd2f6910e1f7305964e0e35c081b5aafd04c8ad7fdbc8c6b3" +
		"d44099cbfcb451907726481a04109e25c8fd70a76cd5ca80cc018384a9ae6a557d645b0f" +
		"54d3e9f76b2978a326211c67a26ced1171703b576b17d8332b38c014853e0e9a3f5aa6cc" +
		"5e30d888f2b32c54f915dfdd6dfcae626c747e85f9a0f8658c11e738bd9c8c724160c79a" +
		"cd3d9ceb4e80495d6e7b48fb63f1e55f4a9e310e92fa5ba5d93580718ae678c9ded688a0" +
		"c8e75197a334d4bc8501b34cda264cb7e0a3232e2c788f218f8e3979f0f7b280ca8f85f5" +
		"9c75b1a2740911c381f93b016d8c79453cf87dedebc2f127c65426555d9e37d971d5ede6" +
		"ba1f6b97d0b8d1558be4e72545285972961e28b70efe2d7a41076ce394d6f17a0cead75d" +
		"3f5fb62b852ecb18a85698e82dfe332f80dd8492012d5f988e66a426532c36ba2365f5fe" +
		"55b92d1b8652e83e40da5201b2f75ab8cacbe61d9800df3a7282d4c4130f3cca6aa45c6f" +
		"e73732799e612d1ef694757fc163fa3dd161c894227673a7f3193be0b652c01226ef9519" +
		"f415b0d7bb823fb240077dd1217f69445262122e74c015c2c3506f8924dba9897712168c" +
		"54f604a4ef0697265f3a3e54aaf3c93ca933bad4d707cd2b4728054b12dee2ac8ec172e9" +
		"f58924cd452aa01dbee114201d719edd8d052e1284ec9522492f4415725e76994456af3b" +
		"930778d67b891c167621fe68d9257c64fd0e14ae6d7b63bf95a1d2dab75c90f50c8c0451" +
		"bde828fdee84cf966f032bf9976aa1ea96d18aeaf0aa327071e87c19cece6d537a2fac6b" +
		"b69f0ef8b733bc7fe3fdc9a26e0da75b6422416ea6bfe69d1ee921a0937b3699069d71f9" +
		"f42e9e66a1ffff14b7d86d0209a8e7bf215cd645e52b8736c433c3191af6432164a25ed6" +
		"b4c2050d2d5709b52337d061637b230efa98f4cfe81dc46c4ffa8e4b92b17689af9a2691" +
		"5540604f5614a68cf0e0f43f98e3c7d4765a7aee54770b279c21d4c4439af654cc486ce1" +
		"92b36748f4b06a64ddb6a2d84feb7b318e18d65a5fbc307c8399a62d6954bec2485d9d92" +
		"4810adf675247fa3940e1702da6ae864af97996a20679e6e52c8e18fc8ef18a32fdabc4d" +
		"826f919622928e1900a8054ea8015eae3b6538b5833011e72488616f3033a55e1eb998e4" +
		"8ac443f3efba7d8e7349c43b0ab4df18f106d8f235bed643ec051f5c524f0e0493239cb1" +
		"77e9c2d3d6ebeec99a222ed365cc54563efe18984b13bd3a6480adba03c255ae10c4c8a2" +
		"59fca9e7ea26d487279933ca1b81718f830f8d5059416e22b7f53a2e675e4591810de044" +
		"83881f6ad08c69f027723220168d870d0e41520091fad771fe2937daa9196833f49a6982" +
		"2a7c7d71dd557c5206d2d00ccd067707aa407e29739de1898bc45978599099c5e0068414" +
		"b5a559539717c4fa8eadc9638fe9065aaa0112cd08989b35a318ba5c09354f2e46f437ac" +
		"321c89a0d6ef3201ed13f681c6962d78d5f0d0774639e42febea7dc85512c1f0f278c7aa" +
		"ab29c50323a23c852c01bcd9a0f6c86c8af9d68ffc32f40ef267849f895fc8735c08f1ef" +
		"9b09a26f1724e83b5f039950a6fb8029f13ed7cfd91068f05d4abda87f698aad0beb5b14" +
		"63edca5b6320a71ed493c78f54bf4111928969e627d791fadbecf38c5e96f221eff2abaa" +
		"66494acf6bdad1c45db239541e43159c1dc4c240b1f5117823843c1cb01c92813354094f" +
		"11e7200d963226fb265d61c496ab296a27894bce9cf1b25a9ea9725ffe2a1b7b34652281" +
		"e683f5bddd34ad920736cc179476cef3eae7f5971e4954885c9586025d65bd37f3011ae4" +
		"66dc152ad67d3fd6535637eadafb5de121abbb773fa54584074dbd83f7039a7fb10b87f4" +
		"24a24bf65fc1a7aefd998ba53ceac8ca3f272f4364a2f6e0ade0369eb57d97fbed155a55" +
		"33cf03b61ff7f5933c66b57fe8bc364d9e6c96851b9464bc50f469598646f7157efe5516" +
		"95d283409b397bdf2f2402cd0a7629986d011e871c84af690738ac8fe727736bbf00aec9" +
		"736a4c846a7f76ebfbeebd7c2c1dcb5784cb569cb86c287d4ac04905061fe5754323335c" +
		"4a0a806fa8a253c1fa3c933512650be1c0c65cfe98851accfc80fd76226fe33785003c17" +
		"6790cdccf459800f5631da92d1636f17e7e0a6eb2121e45dd1091be5ed2de90eae77c6dc" +
		"e6e9bd3d1871d2cae994e7c84fed03aa0ddb99104ff4bcf725ef9554e5ea0d7f0bb91d79" +
		"38c052df93c875e6dec129bdea6e4c7192ed11f646dd3de7ca0671841cf9254003968799" +
		"56719be890eb54fa62bbc061b8416d18f47f9275b935c055e6a01dfa8b80d6b87b022371" +
		"9d52f6c02b9e18e52faf141099f1dfa84ad237743486702715a52e43ed5ce9edc7e9f3a4" +
		"801ad0391df7af438a329bf09e0c05a0af22871f14fe31d2160a84707002383d2f5c6943" +
		"a8cd430d9f6d852b79ae14a155fd8135e8fd96cb2fc0bdbc2db636eca660dd7f95b58c35" +
		"b06371858e3c424de3bb66898f107cf2c91a3ca1e5339ed0ed70801b66755161c01f6bac" +
		"92f465fe51f829bd23d2d60e5efbc976388f67e721103888eccfe06b98d61bb06725947e" +
		"6d1b40005d6841cee60a4a44b1aea78d0e29b8d9559835bd6f30b5a6709da9dad96061f3" +
		"1c459968e8738ba35285ad5cbc43f8f8a756c4575624492516e2b8d8d0e6006ed969aa7d" +
		"20ec67ccdabaec8eda981946984d77f763e3fdb67e64a9952791882b0678f2d346642654" +
		"2c79821b1b5aafbb8fde9d0a7d05655bb6c08f4426a819859844115ed8d5fea9bb2a97da" +
		"52b7f5f79a21e199ee167675a660a7c340ca598a968e3107dadfc5b96030dae6dd8c4380" +
		"c3e97f4321ce3e477099bf0f8e675b4dfa10e9aa655c8582828fb20c85fface950f79df9" +
		"0cda4820d2ea21939cad07d8aacdfe47c3e2176663815114cdf351a5184a51a29da690b8" +
		"f75010e3196fda09957e74c3dcd9b94a677bbf40392b65eee6c1fcc254fb1fbe846b665d" +
		"42b597f58528e804250bcf81735b2c5593de39da267c4309f5d1288c4674eda10ee6ba43" +
		"520368ac3ed832d3dd57b5f9c7e449b6fd631fbef0c19996527273f695afd5b42f6eeb2d" +
		"b00a3e16210a1d9322122cbff34497065f921a61ee4bff495a7dc932481e008c05f24d08" +
		"0cba5c993ffa8f842e5de3e15c0d536b2111b886d3ec307be777a5e91523278bca5ea528" +
		"64ae0861546cecaeb99db0dd3146e582bc192bd85c6dc9b8ffbffef3b490275cbbf26f4b" +
		"b8066f874d093e6f29f7cb6a9aad327fd2390f62d87758de01f60139b25fae885e26575f" +
		"25c6996332d2ab0ee19b1b11e6bd920ef10a204ac60160dbf7908eb31fc4e9ee183b9405" +
		"5ff93c5d61c65633b2613587815fdd7d7140c0169ac6c395013d1dd940ea6eaf1e03a407" +
		"af2ef43826bf9b5ba8fb5606eba499a55c25dee71fea4d90dd0487ff878da4ae12ce3bd9" +
		"ca213fa2d02d218f7fd0288ce856303dc1c25094843eec22342b8b583549a7c34fdb82b8" +
		"b304b34da42d7730e4fbbc4632178934acfe2b1914a50c1db64615463db5b5c62c898a65" +
		"cd794d6b8a21b9c0295e406a9136d7e663f6070512dd9912a17f1f02d8f1f02909503c5d" +
		"54fefee23886d23f17c030dbc16c6e5b89b5270c4de69b77fa8ed2b976c381879854590f" +
		"2a2636688d382e27d11f29ae73db88abe4275db37622a7650ca9eccb7cebc59693170796" +
		"f4297e7846d2c9605b2362c52ec6c9601bff0a13176e491fb6f35e45f03d6773a2e6581c" +
		"c436286c40501cd05e4dd25ee9ed23cf692a227b90179884a4e340156289fa4332254265" +
		"40da3c40426197b70acdf0f096cd049264c6f2273c308aae61648b7358c3ef1108114647" +
		"79e0aec392eed07d3c19a0487022965f5a588aa27bcb08af860610174210a9b6dcad1fd5" +
		"664eff817cf90e745233e303eea0233640080920febe47372eaa67b32215982d8d268389" +
		"b0fa2746c91049dd689726821d823d3afc4f9ef2e547086aa15f6ddfd8e287e517181ba9" +
		"c6b4330720201667665ac24c6c7b73779eef718035065710b4236d132e94202f3f2cfa9d" +
		"bf52c3d448f163f0c4427cf8d933bedd364f370aeec777e79743d8184d052343720867a1" +
		"4911d35c6fd86dc51a655fd23b34ab33307f50a5de8852f607fb11a7a9fcdb7997498a56" +
		"fa7fc212b26209edcb7ac03d3be52d261e2f7f8120eec51391f386badd591a9fee82e49b" +
		"375095b31048af565178c21d89e4f1017f32457e62e41013e49a68d3eec723d4dd16c7d6" +
		"e11c1d784c5706b9740f3ad6acb5e3bd2ec10eb4f1226d947605fdc85f0d703eec9cb739" +
		"d6be581b1a2acc37bd4d90aff0b2687e3b3464a48011ee0b9a1c571c02fc4efb94091dbc" +
		"e2357266713e160718d8b5ab1bacb6cb5330ff2e9dea49d11a18eb924d1c3edb7b4fff9a" +
		"6c60f23dfd1cc4c9"
)

func TestNewPublicKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType slhdsa.HashType
		keySize  int
		sigType  slhdsa.SignatureType
		privHex  string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			privHex:  privKeySHA2128sHex,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tinkParams, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			noPrefixParams, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantNoPrefix, err)
			}
			privKeyBytes, err := hex.DecodeString(tc.privHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(inst.privHex) err = %v, want nil", err)
			}
			for _, tc := range []struct {
				name          string
				params        *slhdsa.Parameters
				keyBytes      []byte
				idRequirement uint32
			}{
				{
					name:          "nil key bytes",
					params:        tinkParams,
					keyBytes:      nil,
					idRequirement: 123,
				},
				{
					name:          "invalid key bytes size",
					params:        tinkParams,
					keyBytes:      []byte("123"),
					idRequirement: 123,
				},
				{
					name:          "invalid ID requirement",
					params:        noPrefixParams,
					keyBytes:      privKeyBytes,
					idRequirement: 123,
				},
				{
					name:          "invalid params",
					params:        &slhdsa.Parameters{},
					keyBytes:      privKeyBytes,
					idRequirement: 123,
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if _, err := slhdsa.NewPublicKey(tc.keyBytes, tc.idRequirement, tc.params); err == nil {
						t.Errorf("slhdsa.NewPublicKey(%v, %v, %v) err = nil, want error", tc.keyBytes, tc.idRequirement, tc.params)
					}
				})
			}
		})
	}
}

func TestPublicKey(t *testing.T) {
	for _, tc := range []struct {
		name             string
		hashType         slhdsa.HashType
		keySize          int
		sigType          slhdsa.SignatureType
		variant          slhdsa.Variant
		pubKeyHex        string
		idRequirement    uint32
		wantOutputPrefix []byte
	}{
		{
			name:             "tink",
			hashType:         slhdsa.SHA2,
			keySize:          64,
			sigType:          slhdsa.SmallSignature,
			variant:          slhdsa.VariantTink,
			pubKeyHex:        pubKeySHA2128sHex,
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:             "no prefix",
			hashType:         slhdsa.SHA2,
			keySize:          64,
			sigType:          slhdsa.SmallSignature,
			variant:          slhdsa.VariantNoPrefix,
			pubKeyHex:        pubKeySHA2128sHex,
			idRequirement:    0,
			wantOutputPrefix: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyBytes, err := hex.DecodeString(tc.pubKeyHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
			}
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			pubKey, err := slhdsa.NewPublicKey(keyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, tc.idRequirement, params, err)
			}
			if got := pubKey.OutputPrefix(); !bytes.Equal(got, tc.wantOutputPrefix) {
				t.Errorf("params.OutputPrefix() = %v, want %v", got, tc.wantOutputPrefix)
			}
			gotIDRequrement, gotRequired := pubKey.IDRequirement()
			if got, want := gotRequired, params.HasIDRequirement(); got != want {
				t.Errorf("params.IDRequirement() = %v, want %v", got, want)
			}
			if got, want := gotIDRequrement, tc.idRequirement; got != want {
				t.Errorf("params.IDRequirement() = %v, want %v", got, want)
			}

			otherPubKey, err := slhdsa.NewPublicKey(keyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, tc.idRequirement, params, err)
			}
			if !otherPubKey.Equal(pubKey) {
				t.Errorf("otherPubKey.Equal(pubKey) = false, want true")
			}
		})
	}
}

func TestPublicKeyEqualSelf(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:      "SLH-DSA-SHA2-128s",
			hashType:  slhdsa.SHA2,
			keySize:   64,
			sigType:   slhdsa.SmallSignature,
			pubKeyHex: pubKeySHA2128sHex,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			keyBytes, err := hex.DecodeString(tc.pubKeyHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
			}
			pubKey, err := slhdsa.NewPublicKey(keyBytes, 123, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, 123, params, err)
			}
			if !pubKey.Equal(pubKey) {
				t.Errorf("pubKey.Equal(pubKey) = false, want true")
			}
		})
	}
}

type stubKey struct{}

var _ key.Key = (*stubKey)(nil)

func (k *stubKey) Parameters() key.Parameters    { return nil }
func (k *stubKey) Equal(other key.Key) bool      { return true }
func (k *stubKey) IDRequirement() (uint32, bool) { return 123, true }

func TestPublicKeyEqual_FalseIfDifferentType(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:      "SLH-DSA-SHA2-128s",
			hashType:  slhdsa.SHA2,
			keySize:   64,
			sigType:   slhdsa.SmallSignature,
			pubKeyHex: pubKeySHA2128sHex,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			keyBytes, err := hex.DecodeString(tc.pubKeyHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
			}
			pubKey, err := slhdsa.NewPublicKey(keyBytes, 123, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, 123, params, err)
			}
			if pubKey.Equal(&stubKey{}) {
				t.Errorf("pubKey.Equal(&stubKey{}) = true, want false")
			}
		})
	}
}

type TestPublicKeyParams struct {
	keyHex         string
	changeKeyBytes bool
	idRequirement  uint32
	hashType       slhdsa.HashType
	keySize        int
	sigType        slhdsa.SignatureType
	variant        slhdsa.Variant
}

func TestPublicKeyEqualFalse(t *testing.T) {
	for _, tc := range []struct {
		name      string
		firstKey  *TestPublicKeyParams
		secondKey *TestPublicKeyParams
	}{
		{
			name: "different ID requirement",
			firstKey: &TestPublicKeyParams{
				keyHex:        pubKeySHA2128sHex,
				idRequirement: 123,
				hashType:      slhdsa.SHA2,
				keySize:       64,
				sigType:       slhdsa.SmallSignature,
				variant:       slhdsa.VariantTink,
			},
			secondKey: &TestPublicKeyParams{
				keyHex:        pubKeySHA2128sHex,
				idRequirement: 456,
				hashType:      slhdsa.SHA2,
				keySize:       64,
				sigType:       slhdsa.SmallSignature,
				variant:       slhdsa.VariantTink,
			},
		},
		{
			name: "different key bytes",
			firstKey: &TestPublicKeyParams{
				keyHex:        pubKeySHA2128sHex,
				idRequirement: 123,
				hashType:      slhdsa.SHA2,
				keySize:       64,
				sigType:       slhdsa.SmallSignature,
				variant:       slhdsa.VariantTink,
			},
			secondKey: &TestPublicKeyParams{
				keyHex:         pubKeySHA2128sHex,
				changeKeyBytes: true,
				idRequirement:  123,
				hashType:       slhdsa.SHA2,
				keySize:        64,
				sigType:        slhdsa.SmallSignature,
				variant:        slhdsa.VariantTink,
			},
		},
		{
			name: "different variant",
			firstKey: &TestPublicKeyParams{
				keyHex:        pubKeySHA2128sHex,
				idRequirement: 0,
				hashType:      slhdsa.SHA2,
				keySize:       64,
				sigType:       slhdsa.SmallSignature,
				variant:       slhdsa.VariantTink,
			},
			secondKey: &TestPublicKeyParams{
				keyHex:        pubKeySHA2128sHex,
				idRequirement: 0,
				hashType:      slhdsa.SHA2,
				keySize:       64,
				sigType:       slhdsa.SmallSignature,
				variant:       slhdsa.VariantNoPrefix,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			firstKeyBytes, err := hex.DecodeString(tc.firstKey.keyHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(tc.firstKey.keyHex) err = %v, want nil", err)
			}
			if tc.firstKey.changeKeyBytes {
				firstKeyBytes[0] = 0x99
			}
			secondKeyBytes, err := hex.DecodeString(tc.secondKey.keyHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(tc.secondKey.keyHex) err = %v, want nil", err)
			}
			if tc.secondKey.changeKeyBytes {
				secondKeyBytes[0] = 0x99
			}
			firstParams, err := slhdsa.NewParameters(tc.firstKey.hashType, tc.firstKey.keySize, tc.firstKey.sigType, tc.firstKey.variant)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", tc.firstKey.variant, err)
			}
			firstPubKey, err := slhdsa.NewPublicKey(firstKeyBytes, tc.firstKey.idRequirement, firstParams)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", firstKeyBytes, tc.firstKey.idRequirement, firstParams, err)
			}
			secondParams, err := slhdsa.NewParameters(tc.secondKey.hashType, tc.secondKey.keySize, tc.secondKey.sigType, tc.secondKey.variant)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", tc.secondKey.variant, err)
			}
			secondPubKey, err := slhdsa.NewPublicKey(secondKeyBytes, tc.secondKey.idRequirement, secondParams)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", secondKeyBytes, tc.secondKey.idRequirement, secondParams, err)
			}
			if firstPubKey.Equal(secondPubKey) {
				t.Errorf("firstPubKey.Equal(secondPubKey) = true, want false")
			}
		})
	}
}

func TestPublicKeyKeyBytes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType slhdsa.HashType
		keySize  int
		sigType  slhdsa.SignatureType
		keyHex   string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
			keyHex:   pubKeySHA2128sHex,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			keyBytes, err := hex.DecodeString(tc.keyHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(tc.keyHex) err = %v, want nil", err)
			}
			pubKey, err := slhdsa.NewPublicKey(keyBytes, 123, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, 123, params, err)
			}
			gotPubKeyBytes := pubKey.KeyBytes()
			if !bytes.Equal(gotPubKeyBytes, keyBytes) {
				t.Errorf("bytes.Equal(gotPubKeyBytes, keyBytes) = false, want true")
			}
			// Make sure a copy is made when creating the public key.
			keyBytes[0] = 0x99
			if bytes.Equal(pubKey.KeyBytes(), keyBytes) {
				t.Errorf("bytes.Equal(pubKey.KeyBytes(), keyBytes) = true, want false")
			}
			// Make sure no changes are made to the internal state of the public key.
			gotPubKeyBytes[1] = 0x99
			if bytes.Equal(pubKey.KeyBytes(), gotPubKeyBytes) {
				t.Errorf("bytes.Equal((pubKey.KeyBytes(), gotPubKeyBytes) = true, want false")
			}
		})
	}
}

var testCases = []struct {
	name             string
	hashType         slhdsa.HashType
	keySize          int
	sigType          slhdsa.SignatureType
	variant          slhdsa.Variant
	privKeyBytesHex  string
	pubKeyBytesHex   string
	idRequirement    uint32
	wantOutputPrefix []byte
}{
	{
		name:             "tink",
		hashType:         slhdsa.SHA2,
		keySize:          64,
		sigType:          slhdsa.SmallSignature,
		variant:          slhdsa.VariantTink,
		privKeyBytesHex:  privKeySHA2128sHex,
		pubKeyBytesHex:   pubKeySHA2128sHex,
		idRequirement:    uint32(0x01020304),
		wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
	},
	{
		name:             "no prefix",
		hashType:         slhdsa.SHA2,
		keySize:          64,
		sigType:          slhdsa.SmallSignature,
		variant:          slhdsa.VariantNoPrefix,
		privKeyBytesHex:  privKeySHA2128sHex,
		pubKeyBytesHex:   pubKeySHA2128sHex,
		idRequirement:    0,
		wantOutputPrefix: nil,
	},
}

func TestPrivateKeyNewPrivateKeyWithPublicKey(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			pubKeyBytes, privKeyBytes := getTestKeyPair(t, tc.hashType, tc.keySize, tc.sigType)
			pubKey, err := slhdsa.NewPublicKey(pubKeyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", pubKeyBytes, tc.idRequirement, params, err)
			}
			secretKey := secretdata.NewBytesFromData(privKeyBytes, insecuresecretdataaccess.Token{})
			privKey, err := slhdsa.NewPrivateKeyWithPublicKey(secretKey, pubKey)
			if err != nil {
				t.Fatalf("slhdsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v, want nil", secretKey, pubKey, err)
			}

			// Test IDRequirement.
			gotIDRequrement, gotRequired := privKey.IDRequirement()
			if got, want := gotRequired, params.HasIDRequirement(); got != want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, want)
			}
			if got, want := gotIDRequrement, tc.idRequirement; got != want {
				t.Errorf("params.IDRequirement() = %v, want %v", got, want)
			}

			// Test OutputPrefix.
			if got := privKey.OutputPrefix(); !bytes.Equal(got, tc.wantOutputPrefix) {
				t.Errorf("params.OutputPrefix() = %v, want %v", got, tc.wantOutputPrefix)
			}

			// Test Equal.
			otherPubKey, err := slhdsa.NewPublicKey(pubKeyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", pubKeyBytes, tc.idRequirement, params, err)
			}
			otherPrivKey, err := slhdsa.NewPrivateKeyWithPublicKey(secretKey, otherPubKey)
			if err != nil {
				t.Fatalf("slhdsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v, want nil", secretKey, pubKey, err)
			}
			if !otherPrivKey.Equal(privKey) {
				t.Errorf("otherPrivKey.Equal(privKey) = false, want true")
			}

			// Test PublicKey.
			got, err := privKey.PublicKey()
			if err != nil {
				t.Fatalf("privKey.PublicKey() err = %v, want nil", err)
			}
			if !got.Equal(pubKey) {
				t.Errorf("privKey.PublicKey().Equal(pubKey) = false, want true")
			}

			// Test Parameters.
			if got := privKey.Parameters(); !got.Equal(params) {
				t.Errorf("privKey.Parameters().Equal(&params) = false, want true")
			}
		})
	}
}

func TestPrivateKeyNewPrivateKey(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tc.variant)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			pubKeyBytes, privKeyBytes := getTestKeyPair(t, tc.hashType, tc.keySize, tc.sigType)
			secretKey := secretdata.NewBytesFromData(privKeyBytes, insecuresecretdataaccess.Token{})
			privKey, err := slhdsa.NewPrivateKey(secretKey, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", secretKey, tc.idRequirement, params, err)
			}

			// Test IDRequirement.
			gotIDRequrement, gotRequired := privKey.IDRequirement()
			if got, want := gotRequired, params.HasIDRequirement(); got != want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, want)
			}
			if got, want := gotIDRequrement, tc.idRequirement; got != want {
				t.Errorf("params.IDRequirement() = %v, want %v", got, want)
			}

			// Test OutputPrefix.
			if got := privKey.OutputPrefix(); !bytes.Equal(got, tc.wantOutputPrefix) {
				t.Errorf("params.OutputPrefix() = %v, want %v", got, tc.wantOutputPrefix)
			}

			// Test Equal.
			otherPrivKey, err := slhdsa.NewPrivateKey(secretKey, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", secretKey, tc.idRequirement, params, err)
			}
			if !otherPrivKey.Equal(privKey) {
				t.Errorf("otherPrivKey.Equal(privKey) = false, want true")
			}

			// Test PublicKey.
			want, err := slhdsa.NewPublicKey(pubKeyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", pubKeyBytes, tc.idRequirement, params, err)
			}
			got, err := privKey.PublicKey()
			if err != nil {
				t.Fatalf("privKey.PublicKey() err = %v, want nil", err)
			}
			if !got.Equal(want) {
				t.Errorf("privKey.PublicKey().Equal(want) = false, want true")
			}

			// Test Parameters.
			if got := privKey.Parameters(); !got.Equal(params) {
				t.Errorf("privKey.Parameters().Equal(&params) = false, want true")
			}
		})
	}
}

func TestNewPrivateKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paramsTink, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			paramsNoPrefix, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantNoPrefix, err)
			}
			for _, tc := range []struct {
				name         string
				params       *slhdsa.Parameters
				idRequrement uint32
				privKeyBytes secretdata.Bytes
			}{
				{
					name:         "nil private key bytes",
					params:       paramsTink,
					idRequrement: 123,
					privKeyBytes: secretdata.NewBytesFromData(nil, insecuresecretdataaccess.Token{}),
				},
				{
					name:         "invalid private key bytes size",
					params:       paramsTink,
					idRequrement: 123,
					privKeyBytes: secretdata.NewBytesFromData([]byte("123"), insecuresecretdataaccess.Token{}),
				},
				{
					name:         "empty params",
					params:       &slhdsa.Parameters{},
					idRequrement: 123,
					privKeyBytes: secretdata.NewBytesFromData([]byte("12345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
				},
				{
					name:         "invalid ID requiremet",
					idRequrement: 123,
					params:       paramsNoPrefix,
					privKeyBytes: secretdata.NewBytesFromData([]byte("12345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if _, err := slhdsa.NewPrivateKey(tc.privKeyBytes, tc.idRequrement, tc.params); err == nil {
						t.Errorf("slhdsa.NewPrivateKey(%v, %v, %v) err = nil, want error", tc.privKeyBytes, tc.idRequrement, tc.params)
					}
				})
			}
		})
	}
}

func TestNewPrivateKeyWithPublicKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			pubKeyBytes, privKeyBytes := getTestKeyPair(t, tc.hashType, tc.keySize, tc.sigType)
			pubKey, err := slhdsa.NewPublicKey(pubKeyBytes, 123, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", pubKeyBytes, 123, params, err)
			}
			for _, tc := range []struct {
				name            string
				params          *slhdsa.Parameters
				pubKey          *slhdsa.PublicKey
				privateKeyBytes secretdata.Bytes
			}{
				{
					name:            "nil private key bytes",
					pubKey:          pubKey,
					privateKeyBytes: secretdata.NewBytesFromData(nil, insecuresecretdataaccess.Token{}),
				},
				{
					name:            "invalid private key bytes size",
					pubKey:          pubKey,
					privateKeyBytes: secretdata.NewBytesFromData([]byte("123"), insecuresecretdataaccess.Token{}),
				},
				{
					name:            "empty public key",
					pubKey:          &slhdsa.PublicKey{},
					privateKeyBytes: secretdata.NewBytesFromData(privKeyBytes, insecuresecretdataaccess.Token{}),
				},
				{
					name:            "nil public key",
					pubKey:          nil,
					privateKeyBytes: secretdata.NewBytesFromData(privKeyBytes, insecuresecretdataaccess.Token{}),
				},
				{
					name:            "invalid public key",
					pubKey:          pubKey,
					privateKeyBytes: secretdata.NewBytesFromData([]byte("12345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if _, err := slhdsa.NewPrivateKeyWithPublicKey(tc.privateKeyBytes, tc.pubKey); err == nil {
						t.Errorf("slhdsa.NewPrivateKeyWithPublicKey(%v, %v) err = nil, want error", tc.privateKeyBytes, tc.pubKey)
					}
				})
			}
		})
	}
}

func TestPrivateKeyEqualSelf(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			pubKeyBytes, privKeyBytes := getTestKeyPair(t, tc.hashType, tc.keySize, tc.sigType)
			pubKey, err := slhdsa.NewPublicKey(pubKeyBytes, 123, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v", pubKeyBytes, 123, params, err)
			}
			secretKey := secretdata.NewBytesFromData(privKeyBytes, insecuresecretdataaccess.Token{})
			privKey, err := slhdsa.NewPrivateKeyWithPublicKey(secretKey, pubKey)
			if err != nil {
				t.Fatalf("slhdsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v", secretKey, pubKey, err)
			}
			if !privKey.Equal(privKey) {
				t.Errorf("privKey.Equal(privKey) = false, want true")
			}
		})
	}
}

func TestPrivateKeyEqual_FalseIfDifferentType(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			pubKeyBytes, privKeyBytes := getTestKeyPair(t, tc.hashType, tc.keySize, tc.sigType)
			pubKey, err := slhdsa.NewPublicKey(pubKeyBytes, 123, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v", pubKeyBytes, 123, params, err)
			}
			secretKey := secretdata.NewBytesFromData(privKeyBytes, insecuresecretdataaccess.Token{})
			privKey, err := slhdsa.NewPrivateKeyWithPublicKey(secretKey, pubKey)
			if err != nil {
				t.Fatalf("slhdsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v", secretKey, pubKey, err)
			}
			if privKey.Equal(&stubKey{}) {
				t.Errorf("privKey.Equal(&stubKey{}) = true, want false")
			}
		})
	}
}

func TestPrivateKeyEqualFalse(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paramsTink, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			paramsNoPrefix, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantNoPrefix, err)
			}
			for _, tc := range []struct {
				name           string
				privKeyBytes1  secretdata.Bytes
				params1        *slhdsa.Parameters
				idRequirement1 uint32
				privKeyBytes2  secretdata.Bytes
				params2        *slhdsa.Parameters
				idRequirement2 uint32
			}{
				{
					name:           "different private key bytes",
					privKeyBytes1:  secretdata.NewBytesFromData([]byte("1234567812345678123456781234567812345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params1:        paramsTink,
					idRequirement1: 123,
					privKeyBytes2:  secretdata.NewBytesFromData([]byte("1234567812345678123456781234567812345678123456781234567812345679"), insecuresecretdataaccess.Token{}),
					params2:        paramsTink,
					idRequirement2: 123,
				},
				{
					name:           "different ID requirement",
					privKeyBytes1:  secretdata.NewBytesFromData([]byte("1234567812345678123456781234567812345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params1:        paramsTink,
					idRequirement1: 123,
					privKeyBytes2:  secretdata.NewBytesFromData([]byte("1234567812345678123456781234567812345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params2:        paramsTink,
					idRequirement2: 456,
				},
				{
					name:           "different params",
					privKeyBytes1:  secretdata.NewBytesFromData([]byte("1234567812345678123456781234567812345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params1:        paramsTink,
					idRequirement1: 0,
					privKeyBytes2:  secretdata.NewBytesFromData([]byte("1234567812345678123456781234567812345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params2:        paramsNoPrefix,
					idRequirement2: 0,
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					firstPrivKey, err := slhdsa.NewPrivateKey(tc.privKeyBytes1, tc.idRequirement1, tc.params1)
					if err != nil {
						t.Fatalf("slhdsa.NewPrivateKey(%v, %v, %v) err = %v", tc.privKeyBytes1, tc.idRequirement1, tc.params1, err)
					}
					secondPrivKey, err := slhdsa.NewPrivateKey(tc.privKeyBytes2, tc.idRequirement2, tc.params2)
					if err != nil {
						t.Fatalf("slhdsa.NewPrivateKey(%v, %v, %v) err = %v", tc.privKeyBytes2, tc.idRequirement2, tc.params2, err)
					}
					if firstPrivKey.Equal(secondPrivKey) {
						t.Errorf("firstPrivKey.Equal(secondPrivKey) = true, want false")
					}
				})
			}
		})
	}
}

func TestPrivateKeyKeyBytes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hashType  slhdsa.HashType
		keySize   int
		sigType   slhdsa.SignatureType
		pubKeyHex string
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsa.SHA2,
			keySize:  64,
			sigType:  slhdsa.SmallSignature,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pubKeyBytes, privKeyBytes := getTestKeyPair(t, tc.hashType, tc.keySize, tc.sigType)
			params, err := slhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, slhdsa.VariantTink)
			if err != nil {
				t.Fatalf("slhdsa.NewParameters(%v) err = %v, want nil", slhdsa.VariantTink, err)
			}
			pubKey, err := slhdsa.NewPublicKey([]byte(pubKeyBytes), 123, params)
			if err != nil {
				t.Fatalf("slhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", []byte(pubKeyBytes), 123, params, err)
			}
			secretKey := secretdata.NewBytesFromData([]byte(privKeyBytes), insecuresecretdataaccess.Token{})
			privKey, err := slhdsa.NewPrivateKeyWithPublicKey(secretKey, pubKey)
			if err != nil {
				t.Fatalf("slhdsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v, want nil", secretKey, pubKey, err)
			}
			if got, want := privKey.PrivateKeyBytes().Data(insecuresecretdataaccess.Token{}), []byte(privKeyBytes); !bytes.Equal(got, want) {
				t.Errorf("bytes.Equal(got, want) = false, want true")
			}
		})
	}
}

func getTestKeyPair(t *testing.T, hashType slhdsa.HashType, keySize int, sigType slhdsa.SignatureType) ([]byte, []byte) {
	t.Helper()
	if hashType == slhdsa.SHA2 && keySize == 64 && sigType == slhdsa.SmallSignature {
		pubKeyBytes, err := hex.DecodeString(pubKeySHA2128sHex)
		if err != nil {
			t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
		}
		privKeyBytes, err := hex.DecodeString(privKeySHA2128sHex)
		if err != nil {
			t.Fatalf("hex.DecodeString(privKeyHex) err = %v, want nil", err)
		}
		return pubKeyBytes, privKeyBytes
	}
	t.Fatalf("unsupported hashType: %v, keySize: %v, sigType: %v", hashType, keySize, sigType)
	return nil, nil
}

func TestKeyCreator(t *testing.T) {
	params, err := slhdsa.NewParameters(slhdsa.SHA2, 64, slhdsa.SmallSignature, slhdsa.VariantTink)
	if err != nil {
		t.Fatalf("slhdsa.NewParameters() err = %v, want nil", err)
	}

	key, err := keygenregistry.CreateKey(params, 0x1234)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey(%v, 0x1234) err = %v, want nil", params, err)
	}
	slhdsaPrivateKey, ok := key.(*slhdsa.PrivateKey)
	if !ok {
		t.Fatalf("keygenregistry.CreateKey(%v, 0x1234) returned key of type %T, want %T", params, key, (*slhdsa.PrivateKey)(nil))
	}
	idRequirement, hasIDRequirement := slhdsaPrivateKey.IDRequirement()
	if !hasIDRequirement || idRequirement != 0x1234 {
		t.Errorf("slhdsaPrivateKey.IDRequirement() (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 123, true)
	}
	if diff := cmp.Diff(slhdsaPrivateKey.Parameters(), params); diff != "" {
		t.Errorf("slhdsaPrivateKey.Parameters() diff (-want +got):\n%s", diff)
	}
}

func TestPrivateKeyCreator_Fails(t *testing.T) {
	paramsNoPrefix, err := slhdsa.NewParameters(slhdsa.SHA2, 64, slhdsa.SmallSignature, slhdsa.VariantNoPrefix)
	if err != nil {
		t.Fatalf("slhdsa.NewParameters() err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name          string
		params        *slhdsa.Parameters
		idRequirement uint32
	}{
		{
			name:          "invalid id requirement",
			params:        paramsNoPrefix,
			idRequirement: 0x1234,
		},
		{
			name:          "invalid parameters",
			params:        &slhdsa.Parameters{},
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

// Copyright 2026 Google LLC
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

package hpke

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

func mustHexDecodeString(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): err %q", s, err)
	}
	return b
}

type mlKEMTestVector struct {
	name                string
	kemID               KEMID
	recipientPrivKeyHex string
	recipientPubKeyHex  string
	ciphertextHex       string
	sharedSecretHex     string
}

func mlKEMTestVectors(t *testing.T) []mlKEMTestVector {
	t.Helper()
	const (
		// Test vector from https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/mlkem_768_test.json.
		recipientPrivKeyMLKEM768Hex = "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f"
		recipientPubKeyMLKEM768Hex  = "a8e651a1e685f22478a8954f007bc7711b930772c78f092e82878e3e937f367967532913a8d53dfdf4bfb1f8846746596705cf345142b972a3f16325c40c2952a37b25897e5ef35fbaeb73a4acbeb6a0b89942ceb195531cfc0a07993954483e6cbc87c06aa74ff0cac5207e535b260aa98d1198c07da605c4d11020f6c9f7bb68bb3456c73a01b710bc99d17739a51716aa01660c8b628b2f5602ba65f07ea993336e896e83f2c5731bbf03460c5b6c8afecb748ee391e98934a2c57d4d069f50d88b30d6966f38c37bc649b82634ce7722645ccd625063364646d6d699db57b45eb67465e16de4d406a818b9eae1ca916a2594489708a43cea88b02a4c03d09b44815c97101caf5048bbcb247ae2366cdc254ba22129f45b3b0eb399ca91a303402830ec01db7b2ca480cf350409b216094b7b0c3ae33ce10a9124e89651ab901ea253c8415bd7825f02bb229369af972028f22875ea55af16d3bc69f70c2ee8b75f28b47dd391f989ade314729c331fa04c1917b278c3eb602868512821adc825c64577ce1e63b1d9644a612948a3483c7f1b9a258000e30196944a403627609c76c7ea6b5de01764d24379117b9ea29848dc555c454bceae1ba5cc72c74ab96b9c91b910d26b88b25639d4778ae26c7c6151a19c6cd7938454372465e4c5ec29245acb3db5379de3dabfa629a7c04a8353a8530c95acb732bb4bb81932bb2ca7a848cd366801444abe23c83b366a87d6a3cf360924c002bae90af65c48060b3752f2badf1ab2722072554a5059753594e6a702761fc97684c8c4a7540a6b07fbc9de87c974aa8809d928c7f4cbbf8045aea5bc667825fd05a521f1a4bf539210c7113bc37b3e58b0cbfc53c841cbb0371de2e511b989cb7c70c023366d78f9c37ef047f8720be1c759a8d96b93f65a94114ffaf60d9a81795e995c71152a4691a5a602a9e1f3599e37c768c7bc108994c0669f3adc957d46b4b6256968e290d7892ea85464ee7a750f39c5e3152c2dfc56d8b0c924ba8a959a68096547f66423c838982a5794b9e1533771331a9a656c28828beb9126a60e95e8c5d906832c7710705576b1fb9507269ddaf8c95ce9719b2ca8dd112be10bcc9f4a37bd1b1eeeb33ecda76ae9f69a5d4b2923a86957671d619335be1c4c2c77ce87c41f98a8cc466460fa300aaf5b301f0a1d09c88e65da4d8ee64f68c02189bbb3584baff716c85db654048a004333489393a07427cd3e217e6a345f6c2c2b13c27b337271c0b27b2dbaa00d237600b5b594e8cf2dd625ea76cf0ed899122c9796b4b0187004258049a477cd11d68c49b9a0e7b00bce8cac7864cbb375140084744c93062694ca795c4f40e7acc9c5a1884072d8c38dafb501ee4184dd5a819ec24ec1651261f962b17a7215aa4a748c15836c389137678204838d7195a85b4f98a1b574c4cd7909cd1f833effd1485543229d3748d9b5cd6c17b9b3b84aef8bce13e683733659c79542d615782a71cdeee792bab51bdc4bbfe8308e663144ede8491830ad98b4634f64aba8b9c042272653920f380c1a17ca87ced7aac41c82888793181a6f76e197b7b90ef90943bb3844912911d8551e5466c5767ab0bc61a1a3f736162ec098a900b12dd8fabbfb3fe8cb1dc4e8315f2af0d32f0017ae136e19f028"
		ciphertextMLKEM768Hex       = "c8391085b8d3ea9794212541b2914f08964d33521d3f67ad66096ebfb1f706424b49558f755b5625bae236f2e0079601c766f7d960808f7e2bb0c7a5e066ed346de628f8c57eebabbb0c22d911548463693ef3ce52a53f7ff415f00e657ae1c5a48fa5ec6e4be5cf462daffc84d2f6d5ff55dc9bbe8bb0d725ec64fd4cd4bd8dba0a844e8b5ce4b6a28934d7f7a050991fe185b506b451dabfad52d52cb2114ca7d9a5cf986c8fdc1bc10ec0c1869e50c03c55a76192a1049aca636ba9020bdaa8d0f58c763b0b89845ca06d4c4ddc21433e16b9c62e44871fdbc05ba218af871fdd7dcfa464e60faa5265264ce1391bd9a8c5faa7626d5f159b9805b975710a3503a0b858a11c6a647cc0e19ac88b1be9056c95b4d2087d0951d1d2f4992491117e6347794ba54571ec49bba71af3413d38a30bf5872248d1f6d07c86baf782e73d2637f043d341a00921857d8b21ddf3e1d6310036ed27af49e5de1b900fe4de79808ff29f9570859612b15adc01fbb265b305b1e3a12ae419da5b74261fa284c101da3d8dca8b2e4521aca571ef44a058e844ff32b16d5aaea05f7f3af8e2ab16222e347662eddfb891d0ecc2a55c5638f9dde92d9a3d544a5f901ac501acd1ea6a010201fcb10ad702c425a94bdf5890d500a2a147eee1d1fcba8c3abe7c2dfe70f346f033d816a0b2791b4f0b2d956d9ee5971715399a5688302495e2e07c1c8c01527184bcd0c208bc159f2e13318c0bb3dd24a6a7fc849f83385ed4dba07fe1d7bd5640cc9ed5ccfdd68763cb0d0edf61b292177fc1d2d3c11dd0495056bcb12558aebcfddef9feb4aebc57afd9023c65cfe65a24e33f1b00111e92e63e011eaf0b212cf95743cd07f5189ece1f205b7f6fcb2e6b1961b5404cebe47c8cd13b8599d5b49e6d87eeda36e9b8fc4c00635896aa2b75896e336d1b612ee13db811e1f07e61748d920f4865f3f11741399dc6162c91ca168a02329dff821d58198712dd558abb099b3a0baf9da1b730b2aa73bcf58d74f357b06f7211c804b6c8af16ff3509fad1d35b14bfdced7db8a6a25c48e5956480724daa057cd660b67ee3e472574182679d485838a6476eac02141075c812af7967ba7c9185cc2abd2a4545b80f3d3104d58d654a57792dcfabbe9c0715e8de2ef81ef404c8168fd7a43efab3d448e686a088efd26a26159948926723d7eccc39e3c1b719cf8becb7be7e964f22cd8cb1b7e25e800ea97d60a64cc0bbd9cb407a3ab9f88f5e29169eeafd4e0322fde6590ae093ce8feeae98b622caa7556ff426c9e7a404ce69355830a7a67767a76c7d9a97b84bfcf50a02f75c235d2f9c671138049ffc7c8055926c03eb3fb87f9695185a42eca9a41655873d30a6b3bf428b246223484a8ff61ee3eeafff10e99c2c13a76284d063e56ab711a35a85b5383df81da23490f66e8ea3fcba067f5530c6541c2b8f74717c35023e7b9b3956c3ee2ff84ba03ccf4b4b5321b9240895481bc6d63c1693c1847852f8e97f50a133532ac3ee1e52d464"
		sharedSecretMLKEM768Hex     = "e7184a0975ee3470878d2d159ec83129c8aec253d4ee17b4810311d198cd0368"
		// Test vector from https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/mlkem_1024_test.json.
		recipientPrivKeyMLKEM1024Hex = "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f"
		recipientPubKeyMLKEM1024Hex  = "537911957c125148a87f41589cb222d0d19229e2cb55e1a044791e7ca61192a46460c3183d2bcd6de08a5e7651603acc349ca16cba18abb23a3e8c330d7421598a6278ec7ebfabca0ef488b2290554753499c0452e453815309955b8150fa1a1e393386dc12fdb27b38c6745f2944016ec457f39b18d604a07a1abe07bc844050ffa8a06fa154a49d88fac775452d6a7c0e589bfb5c370c2c4b6201dda80c9ab2076ecc08b44522fda3326f033806dd2693f319739f40c4f42b24aca7098fb8ff5f9ac20292d02b56ac746801acccc84863dee32878497b69438bf991776286650482c8d9d9587bc6a55b85c4d7fa74d02656b421c9e23e03a48d4b74425c26e4a20dd9562a4da0793f3a352ccc0f18217d868c7f5002abe768b1fc73f05744e7cc28f10344062c10e08eccced3c1f7d392c01d979dd718d8398374665a16a9870585c39d5589a50e133389c9b9a276c024260d9fc7711c81b6337b57da3c376d0cd74e14c73727b276656b9d8a4eb71896ff589d4b893e7110f3bb948ece291dd86c0b7468a678c746980c12aa6b95e2b0cbe4331bb24a33a270153aa472c47312382ca365c5f35259d025746fc6595fe636c767510a69c1e8a176b7949958f2697399497a2fc7364a12c8198295239c826cb5082086077282ed628651fc04c639b438522a9de309b14b086d6e923c551623bd72a733cb0dabc54a9416a99e72c9fda1cb3fb9ba06b8adb2422d68cadc553c98202a17656478ac044ef3456378abce9991e0141ba79094fa8f77a300805d2d32ffc62bf0ca4554c330c2bb7042db35102f68b1a0062583865381c74dd913af70b26cf0923d0c4cb971692222552a8f4b788b4afd1341a9df415cf203900f5ccf7f65988949a75580d049639853100854b21f4018003502bb1ba95f556a5d67c7eb52410eba288a6d0635ca8a4f6d696d0a020c826938d34943c3808c79cc007768533216bc1b29da6c812eff3340baa8d2e65344f09bd47894f5a3a4118715b3c5020679327f9189f7e10856b238bb9b0ab4ca85abf4b21f5c76bccd71850b22e045928276a0f2e951db0707c6a116dc19113fa762dc5f20bd5d2ab5be71744dc9cbdb51ea757963aac56a90a0d8023bed1f5cae8a64da047279b353a096a835b0b2b023b6aa048989233079aeb467e522fa27a5822921e5c551b4f537536e46f3a6a97e72c3b063104e09a040598940d872f6d871f5ef9b4355073b54769e45454e6a0819599408621ab4413b35507b0df578ce2d511d52058d5749df38b29d6cc58870caf92f69a75161406e71c5ff92451a77522b8b2967a2d58a49a81661aa65ac09b08c9fe45abc3851f99c730c45003aca2bf0f8424a19b7408a537d541c16f5682bfe3a7faea564f1298611a7f5f60922ba19de73b1917f1853273555199a649318b50773345c997460856972acb43fc81ab6321b1c33c2bb5098bd489d696a0f70679c1213873d08bdad42844927216047205633212310ee9a06cb10016c805503c341a36d87e56072eabe23731e34af7e2328f85cdb370ccaf00515b64c9c54bc837578447aacfaed5969aa351e7da4efa7b115c4c51f4a699779850295ca72d781ad41bc680532b89e710e2189eb3c50817ba255c7474c95ca9110cc43b8ba8e682c7fb7b0fdc265c0483a65ca4514ee4b832aac5800c3b08e74f563951c1fbb210353efa1aa866856bc1e034733b0485dab1d020c6bf765ff60b3b801984a90c2fe970bf1de97004a6cf44b4984ab58258b4af71221cd17530a700c32959c9436344b5316f09ccca7029a230d639dcb022d8ba79ba91cd6ab12ae1579c50c7bb10e30301a65cae3101d40c7ba927bb553148d1647024d4a06c8166d0b0b81269b7d5f4b34fb022f69152f514004a7c685368552343bb60360fbb9945edf446d345bdcaa7455c74ba0a551e184620fef97688773d50b6433ca7a7ac5cb6b7f671a15376e5a6747a623fa7bc6630373f5b1b512690a661377870a60a7a189683f9b0cf0466e1f750762631c4ab09f505c42dd28633569472735442851e321616d4009810777b6bd46fa7224461a5cc27405dfbac0d39b002cab33433f2a86eb8ce91c134a6386f860a1994eb4b6875a46d195581d173854b53d2293df3e9a822756cd8f212b325ca29b4f9f8cfbadf2e41869abfbad10738ad04cc752bc20c394746850e0c4847db"
		ciphertextMLKEM1024Hex       = "c9bead6b0c1114389bd4761c73ab9095b5809daac9f659bb564af226173052a4a3e7f2e5fd47d2b02aaeb5189e06b9f4ae98b619cb63efbdf3989a94b36e8ea0d700633b950a0ae2a78ed92e85c85c70e13e626fb263fac9681521c3ab22fdab29173c9616a2b037083ff7b2e019b5bcde068fac257ef8f12798411693c1bdcc65420997a513a8a69502620be8e4ce7362e412a76cf51c1f2433f1ab64ce0e5d2f56d7c9ade994d0e35d0aeef3ac515b482437664d8c1d25e5a5507cf80f970d3ea7226aacdc457cbf88a0560aa35bb2c5c455867e2159910a35810befe3aa10eb04d8d57147cb8f66d2b070bac43d1f1ffdd57a9399951f64965727bcb9f66ad42309dafc799c1c540af1af93eff68a86d61f5115db662dee7ac9a362677762b6a164a0fa0a4d859e4b8c8dbdb4e183f5e6808fc52229650caf7cf3e16de3d895d148c35448ab8c2753c9831b24bd4921497eaa192565cabfd83c0c68dfe7d392abf5e5e6f84bb9f5af4b7118c0b558105f9c10c9b6d70682e1de6e0689d7106a6374bd34aed7229e6cb356f2ea65e680ce7b1e2c3704e116a38542826e8a001141baf2e34de37a03040986d4c0cd5d57f0701ce930986fd9525b58e2e59f45b8dd04c0f35b0f47970cc67079618eb9e6d91e9b0f8c6d2e165cf448a2c1ebf71b6537e0f375185dfafef698b6239bb35580b315bcb5ed408c357f192def89bc1b75cdd6aae8b5faf0c3e13803f6bdfa76fb407fcbda790c329b3ee42fd3d3b03bd5003f0bc432f7ba39631112452dfd12140433ff8980eb6a526ba85ef99477378b4dc76635a5cd5040e43b8c1fe4ee5e158e423bfc0c893c1d5613bed08da719c9073184eeb36fd357380fb1873d8cbd36e2255e985b1b76819743a6584a9b3a580996c9c2eed9bbbfff78a6204b5e5eeae5f4efd2660078b37f0754ab5da862e666b145b5f23f3d0977799929dfa2aedda53d152eda1d0d0e4ea43f6ed889bb965eefe0a7c685bb36770eaa874242c0e229cf6ce56defa5aeae64d0c40dda8aa26eaeb31458f070a3bc72e1619ee9b5f642291c56df5b7e43db6c802fc74f4f3f9b5c0d355c3aae520aa31229d12f3e7cc5d48e691191a36b283765f4133f0ff1fe2f01c6648b2798a74eb5d842a248f524a7e7f8974211297b44f0dd19f386e86be6ba782de77fde887226f37a1c77bc5eddeee5bf46b67fb7478d559865f262caa84d64a8ce59e4df0818e14861526acd3483600f3dae7959d35d8181ca6a81ce791be00752da7759446a2cfbe00b8248b93491debd520220b755416d2fc6b7c8af2ff75e5bcbb8e7537380a5721c77484957a69271d8bafce0f166735ff869232de5d381afbf0e44d69172b79a35191949de09703b94222b13c385c6081e6d2ede1e57fe184ef8f60196b9a3a7b7eff7497191ca8741b5a01e79cb69a61142e6f5d080fbb3e566f79e146f75c8a1097860841b4747df604dba954e4a8d9e0dccc1f609d05cf8d31219ecd60c312de684552f09227cb829291c645732c5f5d4d711639f42a23080aa34fe1420f219bd6bcf4e3b29b9d02293b2da81383e0a51d2bb186c7b0a211a0cd63acbfc0210401e985d436b3803d5601c24136afd1562522e45b457cb439178be4a87cce40346d34ae0f3c39103c8a3ebc9c86c8db8fc5561eb0f3a143d4e9fe93a5cba6f6fcae5650d3f43d2668a5956c922893b816647ded0afc052a6c3d9d01a3d3af0f1ba807ff10491e131dc15e165cfd0650a1f2c313d7956141edcc61cb90e9e7abf2fe35fc9dc1bde88939fa11f7bbe3eb4d8ffa643b074d74f45113586e9bb12060003d71941f2da098dc0e96cad3255cf328ea2d3308c1f4585e89c613c426b7e798e1ec4e98fe6c71e7491f5eca0cd05115861bd160e3fe73a58a026ba538e0e256b92f1d7a2497570594856860ffd06b601ac575592f4ac612b5de7866042123ebc60c55768e3a7600a3260551f2bea22bbf6b6c8246e80f9125c4bb9db354dd64ae695c15f5071f4abb9639207cac7331b310f69a05f54b995de529a023f033b055db95287a14ba30a7cc526bb724c417fba290636a996f286e3e9e939e4fe1c398b5c6599959d0b4445a327ec469a1653cfaea7552cecec085ccaa68938ae4ac3c424f7e480439ebd2c992b5f6f95ec244b657dbdeaa9ae110aaf4d68bf4e27410d43ceef3e88e9c717dd44c9ee"
		sharedSecretMLKEM1024Hex     = "489dd1e9c2be4af3482bdb35bb26ce760e6e414da6ecbe489985748a825f1cd6"
	)
	return []mlKEMTestVector{
		{
			name:                "ML-KEM-768",
			kemID:               MLKEM768,
			recipientPrivKeyHex: recipientPrivKeyMLKEM768Hex,
			recipientPubKeyHex:  recipientPubKeyMLKEM768Hex,
			ciphertextHex:       ciphertextMLKEM768Hex,
			sharedSecretHex:     sharedSecretMLKEM768Hex,
		},
		{
			name:                "ML-KEM-1024",
			kemID:               MLKEM1024,
			recipientPrivKeyHex: recipientPrivKeyMLKEM1024Hex,
			recipientPubKeyHex:  recipientPubKeyMLKEM1024Hex,
			ciphertextHex:       ciphertextMLKEM1024Hex,
			sharedSecretHex:     sharedSecretMLKEM1024Hex,
		},
	}
}

func TestMLKEMRoundtrip(t *testing.T) {
	for _, vec := range mlKEMTestVectors(t) {
		t.Run(vec.name, func(t *testing.T) {
			recipientPrivKey := mustHexDecodeString(t, vec.recipientPrivKeyHex)
			recipientPubKey := mustHexDecodeString(t, vec.recipientPubKeyHex)

			kem, err := newKEM(vec.kemID)
			if err != nil {
				t.Fatal(err)
			}

			secret, enc, err := kem.encapsulate(recipientPubKey)
			if err != nil {
				t.Errorf("encapsulate: got err %q, want success", err)
			}

			otherSecret, err := kem.decapsulate(enc, recipientPrivKey)
			if err != nil {
				t.Errorf("decapsulate: got err %q, want success", err)
			}
			if !bytes.Equal(secret, otherSecret) {
				t.Errorf("decapsulate: got shared secret %v, want %v", otherSecret, secret)
			}
		})
	}
}

func TestMLKEMDecapsulateWorks(t *testing.T) {
	for _, vec := range mlKEMTestVectors(t) {
		t.Run(vec.name, func(t *testing.T) {
			recipientPrivKey := mustHexDecodeString(t, vec.recipientPrivKeyHex)
			ciphertext := mustHexDecodeString(t, vec.ciphertextHex)
			sharedSecret := mustHexDecodeString(t, vec.sharedSecretHex)

			kem, err := newKEM(vec.kemID)
			if err != nil {
				t.Fatal(err)
			}

			secret, err := kem.decapsulate(ciphertext, recipientPrivKey)
			if err != nil {
				t.Errorf("decapsulate: got err %q, want success", err)
			}
			if !bytes.Equal(secret, sharedSecret) {
				t.Errorf("decapsulate: got shared secret %v, want %v", secret, sharedSecret)
			}
		})
	}
}

func TestMLKEMEncapsulateBadRecipientPubKey(t *testing.T) {
	for _, vec := range mlKEMTestVectors(t) {
		t.Run(vec.name, func(t *testing.T) {
			recipientPubKey := mustHexDecodeString(t, vec.recipientPubKeyHex)

			kem, err := newKEM(vec.kemID)
			if err != nil {
				t.Fatal(err)
			}

			badRecipientPubKey := append(recipientPubKey, []byte("hello")...)
			if _, _, err := kem.encapsulate(badRecipientPubKey); err == nil {
				t.Error("encapsulate: got success, want err")
			}
		})
	}
}

// TestMLKEMDecapsulateEncapsulatedKeyPrefixesLargerSlice checks--if the
// encapsulated key is part of a larger slice, as in HPKE Encrypt
// https://github.com/tink-crypto/tink-go/blob/d25153b336507a5cc37555d3c1ed36ba41cb3f30/hybrid/internal/hpke/encrypt.go#L58
// --that decapsulate does not modify the larger slice.
func TestMLKEMDecapsulateEncapsulatedKeyPrefixesLargerSlice(t *testing.T) {
	for _, vec := range mlKEMTestVectors(t) {
		t.Run(vec.name, func(t *testing.T) {
			recipientPrivKey := mustHexDecodeString(t, vec.recipientPrivKeyHex)
			recipientPubKey := mustHexDecodeString(t, vec.recipientPubKeyHex)

			kem, err := newKEM(vec.kemID)
			if err != nil {
				t.Fatal(err)
			}

			secret, encapsulatedKey, err := kem.encapsulate(recipientPubKey)
			if err != nil {
				t.Errorf("encapsulate: got err %q, want success", err)
			}

			largerSlice := make([]byte, 3*len(encapsulatedKey))
			suffix := largerSlice[len(encapsulatedKey):]
			zeroedSlice := make([]byte, len(suffix))
			if !bytes.Equal(suffix, zeroedSlice) {
				t.Errorf("suffix: got %x, want %x", suffix, zeroedSlice)
			}

			copy(largerSlice, encapsulatedKey)
			if !bytes.Equal(suffix, zeroedSlice) {
				t.Errorf("suffix: got %x, want %x", suffix, zeroedSlice)
			}

			encapsulatedKeySlice := largerSlice[:len(encapsulatedKey)]
			otherSecret, err := kem.decapsulate(encapsulatedKeySlice, recipientPrivKey)
			if err != nil {
				t.Errorf("decapsulate: got err %q, want success", err)
			}
			if !bytes.Equal(suffix, zeroedSlice) {
				t.Errorf("suffix: got %x, want %x", suffix, zeroedSlice)
			}
			if !bytes.Equal(secret, otherSecret) {
				t.Errorf("decapsulate: got shared secret %v, want %v", otherSecret, secret)
			}
		})
	}
}

func TestMLKEMDecapsulateBadEncapsulatedKey(t *testing.T) {
	for _, vec := range mlKEMTestVectors(t) {
		t.Run(vec.name, func(t *testing.T) {
			recipientPrivKey := mustHexDecodeString(t, vec.recipientPrivKeyHex)
			recipientPubKey := mustHexDecodeString(t, vec.recipientPubKeyHex)

			kem, err := newKEM(vec.kemID)
			if err != nil {
				t.Fatal(err)
			}

			_, encapsulatedKey, err := kem.encapsulate(recipientPubKey)
			if err != nil {
				t.Errorf("encapsulate: got err %q, want success", err)
			}

			badEncapsulatedKey := append(encapsulatedKey, []byte("hello")...)
			if _, err := kem.decapsulate(badEncapsulatedKey, recipientPrivKey); err == nil {
				t.Error("decapsulate: got success, want err")
			}
		})
	}
}

func TestMLKEMDecapsulateBadRecipientPrivKey(t *testing.T) {
	for _, vec := range mlKEMTestVectors(t) {
		t.Run(vec.name, func(t *testing.T) {
			recipientPrivKey := mustHexDecodeString(t, vec.recipientPrivKeyHex)
			recipientPubKey := mustHexDecodeString(t, vec.recipientPubKeyHex)

			kem, err := newKEM(vec.kemID)
			if err != nil {
				t.Fatal(err)
			}

			_, encapsulatedKey, err := kem.encapsulate(recipientPubKey)
			if err != nil {
				t.Errorf("encapsulate: got err %q, want success", err)
			}

			badRecipientPrivKey := append(recipientPrivKey, []byte("hello")...)
			if _, err := kem.decapsulate(encapsulatedKey, badRecipientPrivKey); err == nil {
				t.Error("decapsulate: got success, want err")
			}
		})
	}
}

func TestMLKEMEncapsulatedKeyLength(t *testing.T) {
	for _, vec := range mlKEMTestVectors(t) {
		t.Run(vec.name, func(t *testing.T) {
			kem, err := newKEM(vec.kemID)
			if err != nil {
				t.Fatal(err)
			}

			if kem.encapsulatedKeyLength() != kemLengths[vec.kemID].nEnc {
				t.Errorf("encapsulatedKeyLength: got %d, want %d", kem.encapsulatedKeyLength(), kemLengths[vec.kemID].nEnc)
			}
		})
	}
}

func TestNewMLKEM_InvalidIDs(t *testing.T) {
	if _, err := newMLKEM(UnknownKEMID); err == nil {
		t.Errorf("newPrimitives() err = nil, want error")
	}
}

type mlKEMHPKETestVector struct {
	name        string
	kemID       KEMID
	kdfID       KDFID
	aeadID      AEADID
	privateKey  []byte
	contextInfo []byte
	ciphertext  []byte
	key         []byte
	baseNonce   []byte
	ptEnc       []byte
	aadEnc      []byte
	ctEnc       []byte
}

func mlKEMHPKEVectors(t *testing.T) []mlKEMHPKETestVector {
	t.Helper()
	const (
		// Test vector from https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html.
		privateKeyMLKEM768Hex  = "e3408aae322a3628a4d641c2690d4eb212fd66f369782f2dd22fa293476c69957716be20e83920cd26a7710110a34ac3d5da7d90efdc9759812f5cf1a47e85bf"
		contextInfoMLKEM768Hex = "34663634363532303666366532303631323034373732363536333639363136653230353537323665"
		ciphertextMLKEM768Hex  = "f4c758bd517040c97d327a0d30de9770055583ac2fb90a91a6ec7cca4b464abbd78722db29b985607aea1bb4a79fc76fb784c4d10828e9bfd21495c3e94596c4b626051f30c7028a29c716a2568997392b30179cfbe136fb06b741504dd8901a7291446a692c804859171245d12aa53e0f58b6643a3ba8490180161340f24dfbeb0ab865445ceaa235236ee0db44c119bfe942c7f83d381d7d65172008de0d684de2e87f21394a66bfcf88918832f299469f32fca0e7d5efac51d34b6a788c54922b3b4b7e8325f6306cf545380169773ebdc03fa06ce25aa1c71d307c08bef2016affdd6c293f3cbb0cdb92021692a8ebaef6b74cd6a2bb468da79cc9d08a0494bb88bb2ba0c88d4a3ee2af38762cd6c297c6b36ee18816546b375718876efa557ec600e7c4c6e44aaa3a1372c677dc638dc9742d90319ffc27ee99149c5c8a8185ecf600fdd8be897efea52bfbdc4ef53fff7301ee49a7a352b4890e31c2f44b459b9f7df4623b0be87f1cb9212de1beb19687f3fca6d13ca7f924c0471cf3d9b284e13db8e25e2fd88095ae020100cd9ad5aa5355b8aa90d31657355f80160b3e1e12820908b3a85d321be6d68bebfc7335738b7122de60f4acbb924d3a610749577e8c09574ac0160a3a2f37f9f8af0082082673347db7f2ec20f9d05e96e483411b4c2b18cc49a01ec65ae3a077ba18a7074e5bd14ce97b773687a2cc89b18d9f442d30eebd4925d1591aeba4a04c1a69a7cc6cf34e2581300a27b2bbe9c2fec61ed1b63e50f8704c2737de13f4a9e53e021c5a314d13951293c0a74cc4f098a458885fee8dcf879ee8fe91ebd2a2ca1ffaa9efd84a042b32e195165ae187d66b27e3cde4334bff1eced50910c3ea026ae049df54ab30791f129caa89180c1b6939f8017ef980de3900bbb32e9bc2e1bc53595c438137c62afa349961772d12694fea979f0f4e70c8176b750eb9002483815984b6747d8d4f301eb0b76987d407b2261adecf580160d3185f49aecace7e82701a2eb70d20c43de1be39c1a26e4b5433e213abb748ed5e6fa088c5843c725336c650fbd73f2ee3f8800e9c07948bedec99f75673545425ab826dfe8a0636f422035bb56ef90b5dfab3592232a0b9a84b1bdd78b610a9c3a89ab3dddeaceae9bc5b5d89c930ca20039b65acceb1dba527b58fd6517a21ba90cfb38a2cec950c3f3b490fa4458fe5ccdf79fbd88ae0a84b02cf980aacd4107c29bff7ac8c2fb9e8c131144d968a8b9f4c5bc75420f6cba590682170f2931c99b41895d68ea474f74829fda255f80c7d4ae7b2b0dbd002684f01aa5a2bb17003817d29f27697778404bb9d07fc46eedea487f50490e9beaaa2be101b0d03ae9612e7574022c49166e1e0ce14187df4c75a134f12f60f74d41645584017404b3da7c7e2dec2eca554fb90eb5c958db7e6f5f19cacd27de4651c52358bb7be407261ae4f16559c9617cbcdea92133114b35c376e174165d56082b0e6e2ea347f4e26b904375da1248a863766d95b2c5a2de36b47"
		keyMLKEM768Hex         = "00fc412edb7a5adc4a2994869d1016ef"
		baseNonceMLKEM768Hex   = "2a2bd95954150f73d200005e"
		ptEncMLKEM768Hex       = "34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739"
		aadEncMLKEM768Hex      = "436f756e742d30"
		ctEncMLKEM768Hex       = "4793c6f4dc5824a0039d8faf2d84d359fd6cf423eaeee578bbb7830068ba34b576a6e3f4ba03c5c2c62f2b869224a1c5acf96083cd13bdc3623a47bde544171a72aa684b12a562196785"
		// Test vector from https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html.
		privateKeyMLKEM1024Hex  = "c58f733ea1245a7a54723c30dbf0837acdd7e93c188692523b53b132b993a25af933368a76bbcbf1212e1d34d7128e32c387dc9b04a7ceb0e2b40e1e5769c57d"
		contextInfoMLKEM1024Hex = "34663634363532303666366532303631323034373732363536333639363136653230353537323665"
		ciphertextMLKEM1024Hex  = "f4a53a8db87e065bc2929f5d4e827ef6f6aed7c8f457e19dd8d0c1930e3e1bd2ae6183590d45a037d13f5fa7ff1d1d7ec9873d625fec2727c0a940a66fe5bd6501946f3bfb8f027da703e82ea1d86ac8089d7f6e359e9ac6ec95661be7958489d48e930e9eb9e77e842adc9774525dafbbb6675727cea9501aeb53a33fe08bdaa43418486d3391add4a6cb72bd6865f616e3b9ae4339871e6662f03500e05c0ed883fc3ab9ed8940a7a48037f37b8701dc2daa42469b88086732bca4b7ecfe412b5217defa3b0db1df8b7b003938535cfaf72e55ae08fb76687a5268dfc1e3b2d827bb66f2d09a689b69b5d06cc51aeffd76479fce38e952af5fc0ed1e0195929ba7d1172d509d26b133ec3f415273de4c8acc302435ea4afbfa0cb3e1b669d0e968f3326da174b10de6e29adcb4970036dd17567b376ad97e0a94d3fe7cbff0daaa3ea698ce12ba7fdede4c51f88502dddcc5a62a146253464c8f60ecffbf4c1469435c18c3380cb226931804497b9e73f8a0ced189770b626239531b709f9fc9b299b1f3dd403cdebda088104adac23ede52b4d225b5140f34e3f7da50b8a671807be7c0c408b1b7e665609bb2bf0680d942d33f99fa24d8f9c9d41ac6d056a5d59de974c0e16dd89e2c9794dc4f2a23f12d4d1dcdcd799ea56a185c0453348016a4bf05c5daeb71aa8a911eab43d787a81656a4f9a36fac5304ef8949077636b96536dfced3e005d8c30d053f06bc30bdf97251d842e1a4a1713521bdc43ae1d0af798c33d383e36e1049f7040ca35dcc25537b93411959103e0be8a3c16b68c499e8f7ed2f18372e6a7d605e5efdaa79d06a78e9e8c1fb47afe30eaf6f1fafad31cf88b39e502b3ac5b183ad3e5fdf90306a8840bc45d44f3ef933482a2a3cb2ac5e5adba06585fe04b5f8260bc0139b7d9892acb3326748aef0d7337122830e39cee915149ce3e2da5281cd7917930274e74ca46a5078019411dcf662ea4c6fc1647b62653eecbe6114b2b8c7c6dc4b6f210ec380d093c2674da248029895e2ce8481094ae40a56eb0107e5213556b5af4d1f45fc1d1417d58844d7a116c308c1c794e3f76efafffc372719aca595f34a6a87eae2211e0d4ba6d6217528bbbd09675105c2358d48d71711bfd64f42f66179ba845266709e0dbeb2f8f71febc684bf1217e0176406b2eac9ec257c5ab4e1711ba866420da0874895eec278bbed2aa7546a798d13510bb49929455dcc27791a381d086ef37872d1ec7b3a621bf989667c6804be0dcf1f1d7806cb1e32db6bd6701089b119b745b7d15b8b4d0d421e1cfbd1adaee71586a2d2a6e289cec185b3ce1e139cb9272bfd145918a0e7768ece9169197106a3487cab68ebc99f49919d6906953dacfb7ab020045c36db21315004ae7b9632ef1310b657b35e6f6312329274eea7858c9aca3a3f93eea9e065e9d248b1b5476da95708ee65f1e8b3a7a03d95188f87c504626793b8a4b87e49bc1da085dac71342b351496e63e00650b1f9751cec64a60f6b7920b9f9eaec00b5788bc77e9a2861501c528be11c5d98f6c4e1d8dd3f809456a8963e7511da4438bd0eb8621c210d522a60deb8e0d9c00b7d354e16d7af2969d64174493f0205444cee5bfcf21ef34e09c93c7941506e77329723e203c4473c9ed861fdf4a20d96235f5615cdd9f5b6013bef71fd37b464677f1a802919115f5231602798710ef33495bbb16a0de68d3c0dfd2e1c4833789912ecd7cf41af474f76eb22ef670176ae9e5418eda91be4853de9c212a14636fc7f804612707981a4097f746d137ff7af79aaf73b9d79b5c1243ec5ca02fbfc00c12b02bd59d28217c1181f7388332a1362272182d23aa6059a7493586581a5df3452bd414bcc84599bf740de19a745f40953f87f156b568ba4039e4ecc15e11b9f21f6acc6cffb1da164c0a40323043fc126dec090ecb9054ca3ac1a245291925b531f6b08d8ea60becb8edbdd2d4ac4b3a6fd5282335737b5c7fea581e2842f7b3b56a694e0b2e909507690f2c452d6ec020fb309d12ec0f75117c8cfb10c8a3c3614321beafcf0459d523ee0ceb7e730e3b5d2b1b509e7e5310c07f9dd4eb5250e550ae084613791b87c107c4c875c6ae44a30eece84d4ba8d45754c7b5c63ba3193bc0c013c1619c2b82710fd958a92f99c549a3be20fdb7ce3c2f07dba9b917e81190589c8a0fe95a3"
		keyMLKEM1024Hex         = "57928282570ac8e002ebc79908293d65faabdb3ef58149edb33083cc2f38a55b"
		baseNonceMLKEM1024Hex   = "107259b6ac73abb151fb98a8"
		ptEncMLKEM1024Hex       = "34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739"
		aadEncMLKEM1024Hex      = "436f756e742d30"
		ctEncMLKEM1024Hex       = "433d24cb45dba60451bfcdd3fcc9033a55cbcf128f6068a09cc617dee516d02bd1b15d8bb9f8acc788b29086566124414183c07dfe160d135213dc21b34e7320a19e54d979b2ba3f2d66"
	)
	return []mlKEMHPKETestVector{
		{
			name:        "ML-KEM-768",
			kemID:       MLKEM768,
			kdfID:       HKDFSHA256,
			aeadID:      AES128GCM,
			privateKey:  mustHexDecodeString(t, privateKeyMLKEM768Hex),
			contextInfo: mustHexDecodeString(t, contextInfoMLKEM768Hex),
			ciphertext:  mustHexDecodeString(t, ciphertextMLKEM768Hex),
			key:         mustHexDecodeString(t, keyMLKEM768Hex),
			baseNonce:   mustHexDecodeString(t, baseNonceMLKEM768Hex),
			ptEnc:       mustHexDecodeString(t, ptEncMLKEM768Hex),
			aadEnc:      mustHexDecodeString(t, aadEncMLKEM768Hex),
			ctEnc:       mustHexDecodeString(t, ctEncMLKEM768Hex),
		},
		{
			name:        "ML-KEM-1024",
			kemID:       MLKEM1024,
			kdfID:       HKDFSHA384,
			aeadID:      AES256GCM,
			privateKey:  mustHexDecodeString(t, privateKeyMLKEM1024Hex),
			contextInfo: mustHexDecodeString(t, contextInfoMLKEM1024Hex),
			ciphertext:  mustHexDecodeString(t, ciphertextMLKEM1024Hex),
			key:         mustHexDecodeString(t, keyMLKEM1024Hex),
			baseNonce:   mustHexDecodeString(t, baseNonceMLKEM1024Hex),
			ptEnc:       mustHexDecodeString(t, ptEncMLKEM1024Hex),
			aadEnc:      mustHexDecodeString(t, aadEncMLKEM1024Hex),
			ctEnc:       mustHexDecodeString(t, ctEncMLKEM1024Hex),
		},
	}
}

func TestMLKEMHPKEVectors(t *testing.T) {
	for _, vec := range mlKEMHPKEVectors(t) {
		t.Run(vec.name, func(t *testing.T) {
			kem, kdf, aead, err := newPrimitives(vec.kemID, vec.kdfID, vec.aeadID)
			if err != nil {
				t.Fatal(err)
			}

			privateKeySecret := secretdata.NewBytesFromData(vec.privateKey, insecuresecretdataaccess.Token{})
			ctx, err := newRecipientContext(vec.ciphertext, privateKeySecret, kem, kdf, aead, vec.contextInfo)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(vec.key, ctx.key) {
				t.Errorf("newRecipientContext(): got key %x, want %x", ctx.key, vec.key)
			}
			if !bytes.Equal(vec.baseNonce, ctx.baseNonce) {
				t.Errorf("newRecipientContext(): got baseNonce %x, want %x", ctx.baseNonce, vec.baseNonce)
			}

			otherPtEnc, err := ctx.open(vec.ctEnc, vec.aadEnc)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(vec.ptEnc, otherPtEnc) {
				t.Errorf("open(): got plaintext %x, want %x", otherPtEnc, vec.ptEnc)
			}
		})
	}
}

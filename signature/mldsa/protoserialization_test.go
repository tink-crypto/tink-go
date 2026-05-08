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

package mldsa

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	mldsapb "github.com/tink-crypto/tink-go/v2/proto/ml_dsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	// Keys copied from Tink C++ ML-DSA proto serialization tests.
	privKeyHex = "84d1e8cb37e37dc5a172706588fd367a85e9b10669a791bff7a1d77c0661e379"
	pubKeyHex  = "51a09ab1023acc98a397a0a019307fd3a3f43a8d3064197725e7fdc06d262dc92895483e" +
		"81254addd9e72bfedd5e3d17497e079be5bd5d162838e3eabd6bc10c3e274d8bfaeaac99" +
		"d1206fc20ecdb84d8ef3b3dfca8557a2218325b0de00733f7dbce7f255e50959e845d72b" +
		"1ffe277c87de88bc75e239352f513830e74e3999428358c884d5578aee9be53bc54ae891" +
		"91c758f58f43a0d03e8211270288022e01538159b071c4328882a9726c17263079ec1d98" +
		"19d97fd39ba770ccf283cda1e2ff20f095e74479556483f5e9af8d98f206d0825c964f21" +
		"5e18ccfcee6a1419b31c8d8e26e7b54fb6a87b488b8cb54e91177a431268e73f2417a3dc" +
		"81140fca7c69c9c20b93faba91fc42e67fd017682f5589c64cd0c3d5b5a503d7fcfbe347" +
		"46932cb0ccde62fdb42a6d3c8f3d493eed6625c25755b8b970b8dc6deb159930be575f23" +
		"7fadfe3fd1af05b6bd4297979fc3af0d4e0503030c21e78b141aa24029cfd9807893a82f" +
		"b33b8a91d6a8a94c67c7d380ef6a573c73be6ed605498440e23e2151ed87819b069992f2" +
		"f7d2b24073efebdf51d5a1e67e16f837a12b3139d4e4f7a7d5c9214da83731e08a906118" +
		"ee63e822da91f9ef9570538a78aa95649e5f829dc3095fbbaf31607b07d25ef7665adbde" +
		"4fd4ac1ddb70cbd69e80564c7a72c6e58a1a429e4aeed2bdf7177d0e057f2ccaa2acf8ae" +
		"ceee7fc20e609e0d6760abdbf4b5fea64e67b5620df677266b3cec53b8470e92fbbe02b1" +
		"969b8ffa07d2191b6402102c18ed75b441c446a36ccb7be6b39693770ecf32067208ee06" +
		"24ca7f6f5e702cdacaec9590a70c9a251ec977fa1fa9f8e5fe806de8acbfeb57310a721e" +
		"c31aa1e903bdfb220c1e7021f89c47c0698e9edf8c6c6ff20df554855058baa83f9631bd" +
		"31105ccbd953be038f6d23280bdd0e8506ba37da4463b2dc4a66015723ee4dfc44a9abab" +
		"0f19f0597e7a76848e65aa5abd00d65f96704f5e3f8a1ccc112f23d2821d0244d72eb952" +
		"d39ce0968c694e6e1640e76d20847fc5e2fd94574e7fa0047b4e60088d6f511224b92f56" +
		"a30103db1771f2dd36d9d30cf937f80a04dbe3234dd3c716ccca8cd141f92ace71fa5290" +
		"0e7c73874ce2e891b35081e7a4cabbdd61b3944931b5ec67744648d5a89daba3bcff0beb" +
		"e759817dc009e5780fbd45553b5d5e562fd94a41e00cf0c4578468871ddec77a9f7cb301" +
		"91dad5760974983e31488a24a412a44e885a8386fc16831b25c17edfb140ffc0112bd9ae" +
		"decd3976655fafc681210efe44425341fd3ee458309ae350c0b96dbc50914e4712687a9d" +
		"ffcfb435ab0597d5607934d4ea711ebc8feda87d8c14bebef69c7eaaa8c7742d0cdb295b" +
		"d25795b7737b5d30503ef5e3dfc37973aebfc1935cc8d195c9f374cdba78d0fe871ad6cc" +
		"fb9001ad35f9917ace444d6d448ab2b7357d61d78741d6e43b77cf6b8674d927af1aa426" +
		"f668d0cf0ba0fd889362eb652f73b1d1be0dc6f86f0f4d4207473da9263829a3197f894e" +
		"68130f1e02b2f8cbfcf24af5bb78be40e0f21220c93b53ba4a373429a8be89cfa03a24ac" +
		"9cedacc0c378adf9e1f0107908254f7bb61afc81ca53f2d7c76972b8dea425f04bca595d" +
		"a60ddffa49d00f70eeb8af13e35887bdc760beeda66baecf93a465375774ac50b2462d73" +
		"2e6736c3de8733760fb583514ea32b74e097c8052fa089490b47170d2ece6ba39aca9cef" +
		"939e582ab792679e82e3b9d8593193b2aa8ff11d4806da28bda27429a5c5a9d264986eec" +
		"1cffafac707070a648096beff100c5890a7280eb71890f225c44025f17a51bc72b329f4c" +
		"b7f1cae3b2561fc525e340cb8b86b545de4335aa45d9468e4b6e9c5b459eb0abc1c79523" +
		"29e7b19e5ad83722d2dec2233b308b55a3c8af2dfd3f21accb28112dd05297cc934e963c" +
		"c08fad897c32e223742052ac50f993b8de5d7966a32ab5a2107fbe0da9c09ebbd9c66b86" +
		"e4286977976dd7539d34f7960bc94d7ccff98825dabdf51af3aed87f8653e71a5f19a635" +
		"c54ef00d8e097d91e686d144fd6e9840d72c6c87d4acf497696f3ac91a94ddc6f88bd11d" +
		"8c6a1bc209118ccabf565b82a3b6226440fd3b2eb9825128428c142ff7955d2c9c902a2c" +
		"936db386b1c390440e32d1939256804b5c032368751a11bfa8be1742c4c44e32edc6ab2b" +
		"00c519831c8e8ebcd0de15d0d752a3dc4b1845d5bfcf7b958aefa415241c05edcbb07a0c" +
		"7dffdb7780576e4dd5ef564437a880567f07f6d0606aab2e8e71de453fdeb9469fa3fa79" +
		"bc32218c01f6f7394969706b950afdd7afbcea0e0266ea4d5da76a96cd9970b014a8f35b" +
		"fb30b255c938bc72c57cfe177932243a92b7e013847bafee10bc262dd77ffdd0d979c57c" +
		"31a00a3cbcbff215212cdf407d45c9290ca894fa7f8b0792a8103d045ba9007e23823fe3" +
		"efe264664b644fd92d7227d085494eb29acd1a619d1c7a6ee0ec0e083459d1986be6c426" +
		"c57004298701825768b95477a9c279be47869b11d1568423c39e789862d15d3014239ec6" +
		"15a1aa39e92e6a1c062fee26582675576b88a1fe4bed76e15d9f5fe4cf36b549220bb32d" +
		"dc64400c6e0d99e39e47d9feca3f39d418c88e48b950b7fab7a36c7301e42c97e49d0a99" +
		"812eaa10c3bb60e2e15e987d4009cf9468e28de331ba4d66103ef9b644d89a72300cc1e4" +
		"012617a8bd4a4f958451da83bb8a64b2f09a8d5ac898693db9c36a92ab0530042d41111d" +
		"5c1df76e8722a7cf"
	privKeyHex44 = "dddaccfaa05b0332b3fd7269c7d42de6cbe370735431f735346ccb6be7ad3174"
	pubKeyHex44  = "6e17b61b6c7881ab6d39ee703ab4ab4888d2134e54bb0195bfd0573c03d60bb8445" +
		"f3a2045029da4fef83f7c55869c46d73dd641bc81baf1e713cdeec5116f24338a565c4a54d9d7acf" +
		"4413ea505e00f294e48b1c7f9a391d2f070a6a741f12c0ed605a3e9ac6bcb5b5819703b17dcd331f" +
		"08d987d50e2aa0df091c1a182ddd5ffd19a2b9ef27a5355d962229aa9451397569917e3325b44a7f" +
		"040f6fbea8e69dbcf42d2d0b7af204368ebed1ba6be5ecb503a8d8bd3325dcc8dbf07b64ea9884b1" +
		"14f394cc17dcf4f80c58c1dced81a3f8ef8f201605e5f3306d436e9697a68a2b62a3fc5478e7113a" +
		"070f5aa69385a8076d522652d6926b114838cb2e5578edba7488c1cfeabe41fdcf477aecf74755d1" +
		"a67384c896e22a22f1106e0a1684838642afb76c3ebee45f48139fcef99afc885b2a51b519a3d598" +
		"04b6a1a6a7077edd82705d1551bf12a215ef7053b57d2789f532ef1d5736ab088629cc09f536030c" +
		"db4b89b2bdf547b874913cc5d62fcf98f1e537e4252315a3768710972a14066f12cc01548bd9de6a" +
		"59425b161d1441d3f6c2abafef11e8f35756d27a7754004e449a95eb698dc66463bfe3b3f8ca47e7" +
		"340e10b69b42b105b39d9dced186d09595e9d65ce6227c039c8c6c6f9e45d17d5a2834b073e4b7cf" +
		"0f1ce12a9453da2ba3ebb5bc0ffac14243af76517ad7d6fbd319c54391334e97d899b04bc91a31ad" +
		"ad7cc7a056b5987fbc818075966814776aefca64381b1d3c5d01e933dc354f63bb79d9aafec70927" +
		"972cbf9252b96e2b02770b6c4956021a6e1552ac0258d4245e1f9de76e523377d87d57ba7d8f442a" +
		"b52b86f180040d47b8620feeaed7d543b0f38af35127013e5e8a32813f3eb7182ab3b154734b48ff" +
		"d31fda285873312b59713b59d1bdce3147237b9ccbdd0a9e1394f02c3636b4739d00f2251572d455" +
		"d8ffb45d43270e42c132f96e99cfac1186e4bb27cd0510536d742f7394259207f332a2df9a7740be" +
		"bf66c03bbe5380c0c2daa1c736c4b0c938ed12884464d6f069d9cff3e3e8cc93fea8f5e2c707e53d" +
		"24f2d2a69623a23a456447aad4bbeab468949c8006facd119c0c3ce6f4166495b5d10395d6c55adf" +
		"87a08c379110e0811899eb97fb6168633a487db9ffa3a3dcf6bad9870493731acc4d4ba3280c197d" +
		"7ce2f550294349ff8d5ba196ac50f45f9c6a62fcaede31f9068a90830e89f50cd5b11adc90cefc3a" +
		"33a96e03400346e595866fad098b5e001a3cf7579b45da72aae543c7cfb4a78aded527aa266b98f4" +
		"ce11038bb50698d02407c4a698bf502d4222c912d90462a4cea4abf2b4434fa0f72687dcad38e432" +
		"92b843da6273cdf2da4f430253b99bdd39b2913416ff13c366387db72738061d3269c4c3bb5518ea" +
		"53da32112d0681f750772cc517b48263e44348a2575c745eb1fa43c44a3c19ae2e2b373c6d048849" +
		"df1b9f09ea59167b07d8611e96d7d297a55ae13ec4f82c825d661607b39b5f820b9be55e5f0b28e2" +
		"8b064f8faf5117eb462588e91003c0fed30d313fc4ef996f7598946714e2849580510c1496c91821" +
		"bf16c7329c6cba46a013e40e2a5c0f9e8cd3e6830641ce8013212aa7bea6e9073c138bec6b781445" +
		"8cc16b78b8a84fcee22c18b73976b11b22749bab5852411de427b0abbce118a0f204289ad0983bce" +
		"87f99dea31e7172774ad3827c85165bf68aee7a983558aaa2792ddbc95bc748d4af646991ceda2b0" +
		"95c0f35bcc0e45e8608f71cfc69fc01170b6f9c7c83adda58d3efcc340a67d54ca9f0099f999cce4" +
		"2947499253bf798b5207c03f3c44c41da57f06ba761e029e1c768f2d77034552e2ae2a67fc956"
)


func mustCreateKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

func TestParsePublicKeyFails(t *testing.T) {
	keyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
	}
	protoPublicKey := mldsapb.MlDsaPublicKey{
		KeyValue: keyBytes,
		Version:  publicKeyProtoVersion,
		Params: &mldsapb.MlDsaParams{
			MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
		},
	}
	serializedProtoPublicKey, err := proto.Marshal(&protoPublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPublicKey) err = %v, want nil", err)
	}
	protoPublicKeyWithWrongPrivateKeyVersion := mldsapb.MlDsaPublicKey{
		KeyValue: keyBytes,
		Version:  publicKeyProtoVersion + 1,
		Params: &mldsapb.MlDsaParams{
			MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
		},
	}
	serializedProtoPublicKeyWithWrongVersion, err := proto.Marshal(&protoPublicKeyWithWrongPrivateKeyVersion)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPublicKeyWithWrongPrivateKeyVersion) err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name:             "key data is nil",
			keySerialization: mustCreateKeySerialization(t, nil, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong type URL",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "invalid_type_url",
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong key material type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKeyWithWrongVersion,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &publicKeyParser{}
			if _, err = p.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want non-nil", tc.keySerialization)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	keyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
	}
	protoPublicKey := mldsapb.MlDsaPublicKey{
		KeyValue: keyBytes,
		Version:  publicKeyProtoVersion,
		Params: &mldsapb.MlDsaParams{
			MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
		},
	}
	serializedProtoPublicKey, err := proto.Marshal(&protoPublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPublicKey) err = %v, want nil", err)
	}

	keyBytes44, err := hex.DecodeString(pubKeyHex44)
	if err != nil {
		t.Fatalf("hex.DecodeString(pubKeyHex44) err = %v, want nil", err)
	}
	protoPublicKey44 := mldsapb.MlDsaPublicKey{
		KeyValue: keyBytes44,
		Version:  publicKeyProtoVersion,
		Params: &mldsapb.MlDsaParams{
			MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_44,
		},
	}
	serializedProtoPublicKey44, err := proto.Marshal(&protoPublicKey44)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPublicKey44) err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
		wantVariant      Variant
		wantInstance     Instance
		protoKey         *mldsapb.MlDsaPublicKey
	}{
		{
			name: "ML-DSA-65 key with TINK output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
			wantVariant:  VariantTink,
			wantInstance: MLDSA65,
			protoKey:     &protoPublicKey,
		},
		{
			name: "ML-DSA-65 key with RAW output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			wantVariant:  VariantNoPrefix,
			wantInstance: MLDSA65,
			protoKey:     &protoPublicKey,
		},
		{
			name: "ML-DSA-44 key with TINK output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey44,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
			wantVariant:  VariantTink,
			wantInstance: MLDSA44,
			protoKey:     &protoPublicKey44,
		},
		{
			name: "ML-DSA-44 key with RAW output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey44,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			wantVariant:  VariantNoPrefix,
			wantInstance: MLDSA44,
			protoKey:     &protoPublicKey44,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &publicKeyParser{}
			gotKey, err := p.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("p.ParseKey(%v) err = %v, want nil", tc.keySerialization, err)
			}
			wantParams, err := NewParameters(tc.wantInstance, tc.wantVariant)
			if err != nil {
				t.Fatalf("NewParameters(%v, %v) err = %v, want nil", tc.wantInstance, tc.wantVariant, err)
			}
			idRequirement, _ := tc.keySerialization.IDRequirement()
			wantKey, err := NewPublicKey(tc.protoKey.GetKeyValue(), idRequirement, wantParams)
			if err != nil {
				t.Fatalf("NewPublicKey(%v, %v, %v) err = %v, want nil", tc.protoKey.GetKeyValue(), idRequirement, wantParams, err)
			}
			if !gotKey.Equal(wantKey) {
				t.Errorf("%v.Equal(%v) = false, want true", gotKey, wantKey)
			}
			// Test serialization returns back tc.keySerialization.
			s := publicKeySerializer{}
			keySerialization, err := s.SerializeKey(gotKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(gotKey) err = %v, want nil", err)
			}
			if got, want := keySerialization, tc.keySerialization; !got.Equal(want) {
				t.Errorf("s.SerializeKey(gotKey) = %v, want %v", got, want)
			}
		})
	}
}

type testParams struct{}

func (p *testParams) HasIDRequirement() bool { return true }

func (p *testParams) Equal(params key.Parameters) bool { return true }

type testKey struct{}

func (k *testKey) Parameters() key.Parameters { return &testParams{} }

func (k *testKey) Equal(other key.Key) bool { return true }

func (k *testKey) IDRequirement() (uint32, bool) { return 123, true }

func TestSerializePublicKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name      string
		publicKey key.Key
	}{
		{
			name:      "nil public key",
			publicKey: nil,
		},
		{
			name:      "invalid public key",
			publicKey: &PublicKey{},
		},
		{
			name:      "incorrect key type",
			publicKey: &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &publicKeySerializer{}
			if _, err := s.SerializeKey(tc.publicKey); err == nil {
				t.Errorf("s.SerializeKey(%v) err = nil, want non-nil", tc.publicKey)
			}
		})
	}
}

func mustCreatePublicKey(t *testing.T, instance Instance, keyBytes []byte, idRequirement uint32, variant Variant) *PublicKey {
	t.Helper()
	params, err := NewParameters(instance, variant)
	if err != nil {
		t.Fatalf("NewParameters(%v, %v) err = %v, want nil", instance, variant, err)
	}
	pubKey, err := NewPublicKey(keyBytes, idRequirement, params)
	if err != nil {
		t.Fatalf("NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, idRequirement, params, err)
	}
	return pubKey
}

func TestSerializePublicKey(t *testing.T) {
	keyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
	}
	protoPublicKey := mldsapb.MlDsaPublicKey{
		KeyValue: keyBytes,
		Version:  publicKeyProtoVersion,
		Params: &mldsapb.MlDsaParams{
			MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
		},
	}
	serializedProtoPublicKey, err := proto.Marshal(&protoPublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPublicKey) err = %v, want nil", err)
	}

	keyBytes44, err := hex.DecodeString(pubKeyHex44)
	if err != nil {
		t.Fatalf("hex.DecodeString(pubKeyHex44) err = %v, want nil", err)
	}
	protoPublicKey44 := mldsapb.MlDsaPublicKey{
		KeyValue: keyBytes44,
		Version:  publicKeyProtoVersion,
		Params: &mldsapb.MlDsaParams{
			MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_44,
		},
	}
	serializedProtoPublicKey44, err := proto.Marshal(&protoPublicKey44)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPublicKey44) err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name      string
		publicKey key.Key
		want      *protoserialization.KeySerialization
	}{
		{
			name:      "ML-DSA-65 Public key with TINK output prefix type",
			publicKey: mustCreatePublicKey(t, MLDSA65, keyBytes, 12345, VariantTink),
			want: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name:      "ML-DSA-65 Public key with RAW output prefix type",
			publicKey: mustCreatePublicKey(t, MLDSA65, keyBytes, 0, VariantNoPrefix),
			want: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name:      "ML-DSA-44 Public key with TINK output prefix type",
			publicKey: mustCreatePublicKey(t, MLDSA44, keyBytes44, 12345, VariantTink),
			want: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey44,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name:      "ML-DSA-44 Public key with RAW output prefix type",
			publicKey: mustCreatePublicKey(t, MLDSA44, keyBytes44, 0, VariantNoPrefix),
			want: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey44,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &publicKeySerializer{}
			got, err := s.SerializeKey(tc.publicKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(%v) err = nil, want non-nil", tc.publicKey)
			}
			if !got.Equal(tc.want) {
				t.Errorf("s.SerializeKey(%v) = %v, want %v", tc.publicKey, got, tc.want)
			}
		})
	}
}

func getTestKeyPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
	}
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(privKeyHex) err = %v, want nil", err)
	}
	return pubKeyBytes, privKeyBytes
}

func TestParsePrivateKeyFails(t *testing.T) {
	pubKeyBytes, privKeyBytes := getTestKeyPair(t)

	protoPrivateKey := &mldsapb.MlDsaPrivateKey{
		KeyValue: privKeyBytes,
		PublicKey: &mldsapb.MlDsaPublicKey{
			KeyValue: pubKeyBytes,
			Version:  publicKeyProtoVersion,
			Params: &mldsapb.MlDsaParams{
				MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
			},
		},
		Version: publicKeyProtoVersion,
	}
	serializedProtoPrivateKey, err := proto.Marshal(protoPrivateKey)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPrivateKey, err)
	}

	protoPublicKeyWithWrongPrivateKeyVersion := &mldsapb.MlDsaPrivateKey{
		KeyValue: privKeyBytes,
		PublicKey: &mldsapb.MlDsaPublicKey{
			KeyValue: pubKeyBytes,
			Version:  publicKeyProtoVersion,
			Params: &mldsapb.MlDsaParams{
				MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
			},
		},
		Version: privateKeyProtoVersion + 1,
	}
	serializedProtoPrivateKeyWithWrongPrivateKeyVersion, err := proto.Marshal(protoPublicKeyWithWrongPrivateKeyVersion)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPublicKeyWithWrongPrivateKeyVersion, err)
	}
	protoPrivateKeyWithWrongPublicKeyVersion := &mldsapb.MlDsaPrivateKey{
		KeyValue: privKeyBytes,
		PublicKey: &mldsapb.MlDsaPublicKey{
			KeyValue: pubKeyBytes,
			Version:  publicKeyProtoVersion + 1,
			Params: &mldsapb.MlDsaParams{
				MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
			},
		},
		Version: privateKeyProtoVersion,
	}
	serializedProtoPrivateKeyWithWrongPublicKeyVersion, err := proto.Marshal(protoPrivateKeyWithWrongPublicKeyVersion)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPrivateKeyWithWrongPublicKeyVersion, err)
	}

	otherPubKeyBytes := bytes.Clone(pubKeyBytes)
	otherPubKeyBytes[0] = 0x99
	protoPrivateKeyWithWrongPublicKeyBytes := &mldsapb.MlDsaPrivateKey{
		KeyValue: privKeyBytes,
		PublicKey: &mldsapb.MlDsaPublicKey{
			KeyValue: otherPubKeyBytes,
			Version:  publicKeyProtoVersion,
			Params: &mldsapb.MlDsaParams{
				MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
			},
		},
		Version: privateKeyProtoVersion,
	}
	serializedProtoPrivateKeyWithWrongPublicKeyBytes, err := proto.Marshal(protoPrivateKeyWithWrongPublicKeyBytes)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPrivateKeyWithWrongPublicKeyBytes, err)
	}

	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name:             "key data is nil",
			keySerialization: mustCreateKeySerialization(t, nil, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong type URL",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "invalid_type_url",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_UNKNOWN_PREFIX, 12345),
		},
		{
			name: "wrong private key material type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong private key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				Value:           serializedProtoPrivateKeyWithWrongPrivateKeyVersion,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong public key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				Value:           serializedProtoPrivateKeyWithWrongPublicKeyVersion,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong public key bytes",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				Value:           serializedProtoPrivateKeyWithWrongPublicKeyBytes,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &privateKeyParser{}
			if _, err = p.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want non-nil", tc.keySerialization)
			}
		})
	}
}

func TestParsePrivateKey(t *testing.T) {
	pubKeyBytes, privKeyBytes := getTestKeyPair(t)

	protoPrivateKey := mldsapb.MlDsaPrivateKey{
		KeyValue: privKeyBytes,
		PublicKey: &mldsapb.MlDsaPublicKey{
			KeyValue: pubKeyBytes,
			Version:  publicKeyProtoVersion,
			Params: &mldsapb.MlDsaParams{
				MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
			},
		},
		Version: publicKeyProtoVersion,
	}
	serializedProtoPrivateKey, err := proto.Marshal(&protoPrivateKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPrivateKey) err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
		wantVariant      Variant
	}{
		{
			name: "key with TINK output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
			wantVariant: VariantTink,
		},
		{
			name: "key with RAW output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_RAW, 0),
			wantVariant: VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &privateKeyParser{}
			gotKey, err := p.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("p.ParseKey(%v) err = %v, want non-nil", tc.keySerialization, err)
			}
			wantParams, err := NewParameters(MLDSA65, tc.wantVariant)
			if err != nil {
				t.Fatalf("NewParameters(%v) err = %v, want nil", tc.wantVariant, err)
			}
			idRequirement, _ := tc.keySerialization.IDRequirement()
			privateKeyBytes := secretdata.NewBytesFromData(protoPrivateKey.GetKeyValue(), insecuresecretdataaccess.Token{})
			wantKey, err := NewPrivateKey(privateKeyBytes, idRequirement, wantParams)
			if err != nil {
				t.Fatalf("NewPrivateKey(%v, %v, %v) err = %v, want nil", privateKeyBytes, idRequirement, wantParams, err)
			}
			if !gotKey.Equal(wantKey) {
				t.Errorf("%v.Equal(%v) = false, want true", gotKey, wantKey)
			}
			// Test serialization returns back tc.keySerialization.
			s := privateKeySerializer{}
			keySerialization, err := s.SerializeKey(gotKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(gotKey) err = %v, want nil", err)
			}
			if got, want := keySerialization, tc.keySerialization; !got.Equal(want) {
				t.Errorf("s.SerializeKey(gotKey) = %v, want %v", got, want)
			}
		})
	}
}

func TestSerializePrivateKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name       string
		privateKey key.Key
	}{
		{
			name:       "nil private key",
			privateKey: nil,
		},
		{
			name:       "invlid private key",
			privateKey: &PrivateKey{},
		},
		{
			name:       "incorrect key type",
			privateKey: &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &privateKeySerializer{}
			if _, err := s.SerializeKey(tc.privateKey); err == nil {
				t.Errorf("s.SerializeKey(%v) err = nil, want non-nil", tc.privateKey)
			}
		})
	}
}

func mustCreatePrivateKey(t *testing.T, instance Instance, keyBytes secretdata.Bytes, idRequirement uint32, variant Variant) *PrivateKey {
	t.Helper()
	params, err := NewParameters(instance, variant)
	if err != nil {
		t.Fatalf("NewParameters(%v, %v) err = %v, want nil", instance, variant, err)
	}
	pubKey, err := NewPrivateKey(keyBytes, idRequirement, params)
	if err != nil {
		t.Fatalf("NewPrivateKey(%v, %v, %v) err = %v, want nil", keyBytes, idRequirement, params, err)
	}
	return pubKey
}

func TestSerializePrivateKey(t *testing.T) {
	pubKeyBytes, privKeyBytes := getTestKeyPair(t)

	protoPrivateKey := mldsapb.MlDsaPrivateKey{
		KeyValue: privKeyBytes,
		PublicKey: &mldsapb.MlDsaPublicKey{
			KeyValue: pubKeyBytes,
			Version:  publicKeyProtoVersion,
			Params: &mldsapb.MlDsaParams{
				MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
			},
		},
		Version: publicKeyProtoVersion,
	}
	serializedProtoPrivateKey, err := proto.Marshal(&protoPrivateKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPrivateKey) err = %v, want nil", err)
	}
	privateKeyBytes := secretdata.NewBytesFromData(privKeyBytes, insecuresecretdataaccess.Token{})

	pubKeyBytes44, err := hex.DecodeString(pubKeyHex44)
	if err != nil {
		t.Fatalf("hex.DecodeString(pubKeyHex44) err = %v, want nil", err)
	}
	privKeyBytes44, err := hex.DecodeString(privKeyHex44)
	if err != nil {
		t.Fatalf("hex.DecodeString(privKeyHex44) err = %v, want nil", err)
	}
	protoPrivateKey44 := mldsapb.MlDsaPrivateKey{
		KeyValue: privKeyBytes44,
		PublicKey: &mldsapb.MlDsaPublicKey{
			KeyValue: pubKeyBytes44,
			Version:  publicKeyProtoVersion,
			Params: &mldsapb.MlDsaParams{
				MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_44,
			},
		},
		Version: publicKeyProtoVersion,
	}
	serializedProtoPrivateKey44, err := proto.Marshal(&protoPrivateKey44)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPrivateKey44) err = %v, want nil", err)
	}
	privateKeyBytes44 := secretdata.NewBytesFromData(privKeyBytes44, insecuresecretdataaccess.Token{})

	for _, tc := range []struct {
		name       string
		privateKey *PrivateKey
		want       *protoserialization.KeySerialization
	}{
		{
			name:       "ML-DSA-65 Private key with TINK output prefix type",
			privateKey: mustCreatePrivateKey(t, MLDSA65, privateKeyBytes, 12345, VariantTink),
			want: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name:       "ML-DSA-65 Private key with RAW output prefix type",
			privateKey: mustCreatePrivateKey(t, MLDSA65, privateKeyBytes, 0, VariantNoPrefix),
			want: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
		{
			name:       "ML-DSA-44 Private key with TINK output prefix type",
			privateKey: mustCreatePrivateKey(t, MLDSA44, privateKeyBytes44, 12345, VariantTink),
			want: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				Value:           serializedProtoPrivateKey44,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name:       "ML-DSA-44 Private key with RAW output prefix type",
			privateKey: mustCreatePrivateKey(t, MLDSA44, privateKeyBytes44, 0, VariantNoPrefix),
			want: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				Value:           serializedProtoPrivateKey44,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &privateKeySerializer{}
			got, err := s.SerializeKey(tc.privateKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(%v) err = nil, want non-nil", tc.privateKey)
			}
			if !got.Equal(tc.want) {
				t.Errorf("s.SerializeKey(%v) = %v, want %v", tc.privateKey, got, tc.want)
			}
		})
	}
}

func TestSerializeParametersFailsWithWrongParameters(t *testing.T) {
	for _, tc := range []struct {
		name       string
		parameters key.Parameters
	}{
		{
			name:       "empty parameters",
			parameters: &Parameters{},
		},
		{
			name:       "nil",
			parameters: nil,
		},
		{
			name:       "wrong type",
			parameters: &testParams{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializer := &parametersSerializer{}
			if _, err := serializer.Serialize(tc.parameters); err == nil {
				t.Errorf("serializer.Serialize(%v) err = nil, want error", tc.parameters)
			}
		})
	}
}

func TestSerializeParameters(t *testing.T) {
	format65 := &mldsapb.MlDsaKeyFormat{
		Version: 0,
		Params: &mldsapb.MlDsaParams{
			MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
		},
	}
	serializedFormat65, err := proto.Marshal(format65)
	if err != nil {
		t.Fatalf("proto.Marshal(format65) err = %v, want nil", err)
	}

	format44 := &mldsapb.MlDsaKeyFormat{
		Version: 0,
		Params: &mldsapb.MlDsaParams{
			MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_44,
		},
	}
	serializedFormat44, err := proto.Marshal(format44)
	if err != nil {
		t.Fatalf("proto.Marshal(format44) err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name       string
		parameters key.Parameters
		want       *tinkpb.KeyTemplate
	}{
		{
			name: "ML-DSA-65 parameters with TINK variant",
			parameters: &Parameters{
				instance: MLDSA65,
				variant:  VariantTink,
			},
			want: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value:            serializedFormat65,
			},
		},
		{
			name: "ML-DSA-65 parameters with NO_PREFIX variant",
			parameters: &Parameters{
				instance: MLDSA65,
				variant:  VariantNoPrefix,
			},
			want: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				Value:            serializedFormat65,
			},
		},
		{
			name: "ML-DSA-44 parameters with TINK variant",
			parameters: &Parameters{
				instance: MLDSA44,
				variant:  VariantTink,
			},
			want: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value:            serializedFormat44,
			},
		},
		{
			name: "ML-DSA-44 parameters with NO_PREFIX variant",
			parameters: &Parameters{
				instance: MLDSA44,
				variant:  VariantNoPrefix,
			},
			want: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				Value:            serializedFormat44,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeParameters(tc.parameters)
			if err != nil {
				t.Fatalf("protoserialization.SerializeParameters(%v) err = %v, want nil", tc.parameters, err)
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeParameters(%v) returned unexpected diff (-want +got):\n%s", tc.parameters, diff)
			}
		})
	}
}

func TestParseParameters(t *testing.T) {
	format65 := &mldsapb.MlDsaKeyFormat{
		Version: 0,
		Params: &mldsapb.MlDsaParams{
			MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
		},
	}
	serializedFormat65, err := proto.Marshal(format65)
	if err != nil {
		t.Fatalf("proto.Marshal(format65) err = %v, want nil", err)
	}

	format44 := &mldsapb.MlDsaKeyFormat{
		Version: 0,
		Params: &mldsapb.MlDsaParams{
			MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_44,
		},
	}
	serializedFormat44, err := proto.Marshal(format44)
	if err != nil {
		t.Fatalf("proto.Marshal(format44) err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name     string
		want     key.Parameters
		template *tinkpb.KeyTemplate
	}{
		{
			name: "ML-DSA-65 parameters with TINK variant",
			want: &Parameters{
				instance: MLDSA65,
				variant:  VariantTink,
			},
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value:            serializedFormat65,
			},
		},
		{
			name: "ML-DSA-65 parameters with NO_PREFIX variant",
			want: &Parameters{
				instance: MLDSA65,
				variant:  VariantNoPrefix,
			},
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				Value:            serializedFormat65,
			},
		},
		{
			name: "ML-DSA-44 parameters with TINK variant",
			want: &Parameters{
				instance: MLDSA44,
				variant:  VariantTink,
			},
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value:            serializedFormat44,
			},
		},
		{
			name: "ML-DSA-44 parameters with NO_PREFIX variant",
			want: &Parameters{
				instance: MLDSA44,
				variant:  VariantNoPrefix,
			},
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				Value:            serializedFormat44,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseParameters(tc.template)
			if err != nil {
				t.Fatalf("protoserialization.ParseParameters(%v) err = %v, want nil", tc.template, err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("protoserialization.ParseParameters(%v) returned unexpected diff (-want +got):\n%s", tc.template, diff)
			}
		})
	}
}

func mustMarshal(t *testing.T, format proto.Message) []byte {
	t.Helper()
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("proto.Marshal(format) err = %v, want nil", err)
	}
	return serializedFormat
}

func TestParseParametersFails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name: "invalid output prefix type",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
				Value: mustMarshal(t, &mldsapb.MlDsaKeyFormat{
					Version: 0,
					Params: &mldsapb.MlDsaParams{
						MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
					},
				}),
			},
		},
		{
			name: "invalid version",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshal(t, &mldsapb.MlDsaKeyFormat{
					Version: 1,
					Params: &mldsapb.MlDsaParams{
						MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
					},
				}),
			},
		},
		{
			name: "invalid value",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value:            []byte("invalid_value"),
			},
		},
		{
			name: "invalid instance",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshal(t, &mldsapb.MlDsaKeyFormat{
					Version: 0,
					Params: &mldsapb.MlDsaParams{
						MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_UNKNOWN_INSTANCE,
					},
				}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseParameters(tc.template); err == nil {
				t.Errorf("protoserialization.ParseParameters(%v) err = nil, want error", tc.template)
			}
		})
	}
}

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

package mldsa_test

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
	"github.com/tink-crypto/tink-go/v2/signature/mldsa"
)

func TestNewParameters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance mldsa.Instance
		variant  mldsa.Variant
	}{
		{
			name:     "tink",
			instance: mldsa.MLDSA65,
			variant:  mldsa.VariantTink,
		},
		{
			name:     "no prefix",
			instance: mldsa.MLDSA65,
			variant:  mldsa.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := mldsa.NewParameters(tc.instance, tc.variant)
			if err != nil {
				t.Errorf("mldsa.NewParameters(%v, %v) err = %v, want nil", tc.instance, tc.variant, err)
			}
			if got := params.Variant(); got != tc.variant {
				t.Errorf("params.Variant() = %v, want %v", got, tc.variant)
			}
		})
	}
	for _, inst := range []mldsa.Instance{
		mldsa.MLDSA65,
	} {
		t.Run("unknown", func(t *testing.T) {
			if _, err := mldsa.NewParameters(inst, mldsa.VariantUnknown); err == nil {
				t.Errorf("mldsa.NewParameters(%v, %v) err = nil, want error", inst, mldsa.VariantUnknown)
			}
		})
	}
}

func TestParametersHasIDRequirement(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance mldsa.Instance
		variant  mldsa.Variant
		want     bool
	}{
		{
			name:     "tink",
			instance: mldsa.MLDSA65,
			variant:  mldsa.VariantTink,
			want:     true,
		},
		{
			name:     "no prefix",
			instance: mldsa.MLDSA65,
			variant:  mldsa.VariantNoPrefix,
			want:     false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := mldsa.NewParameters(tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v, %v) err = %v, want nil", tc.instance, tc.variant, err)
			}
			if got := params.HasIDRequirement(); got != tc.want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParametersEqual(t *testing.T) {
	for _, inst := range []mldsa.Instance{
		mldsa.MLDSA65,
	} {
		t.Run(fmt.Sprintf("%s", inst), func(t *testing.T) {
			tinkVariant, err := mldsa.NewParameters(inst, mldsa.VariantTink)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", mldsa.VariantTink, err)
			}
			noPrefixVariant, err := mldsa.NewParameters(inst, mldsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want	 nil", mldsa.VariantNoPrefix, err)
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
	// Copied from Tink C++ ML-DSA signature verification test.
	privKey65Hex = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D"
	pubKey65Hex  = "1483236FC9F943D98417809E95405384530ED83E151E8465D34E4638F1F8D7058D62E19A" +
		"B806490883A823176D4DC8A3C10C9960D0E948A9F7B62CA8E118DE5D7A05BB18E8018B6C" +
		"ACB4FE7885490599939D90D004BD480B116F5D6627B6C4C1B2A1496CC3525EF9F19953EC" +
		"63CDD6EBDB21D65B27C644194916AAD07CC559B08CFC1282D25D7276C9E5062E0B1C4CF1" +
		"11C0A9DCC49BF40F5ED3C27CB4E78E39C1F068736A788E2ED4A02E9EF23EACE802CD295B" +
		"6EB97D533091B3293D9BAD2938DFDECF2C4F9F6387B38A7FD22738A010B85949688650B6" +
		"F063B6BC6350A1E84C869FB3BBCDC4BF6C0D0674D7C07F7AE78E4BBB302B6DB8488B5F91" +
		"64E5E264682E45E71B58FC19ADF5EA892439EB352AFDDB63D22177AEF17261909E3F87BC" +
		"C7E1B1A58CD5DE8F8A886A12D7137CE5BFBD2C53ECEBFD1B9F2298583D767E0DB5178B95" +
		"2F4D069D66FDEDCA1FBDCF8720AAAA5313C0500ECF95B9B70E7E3D58DD2B57433D3A0637" +
		"DF36E964B21F44F791B3AF9074D6DBC9A2FC041D9E22D5E387C4081E6D4CCE6AB11FC8B4" +
		"F2C718EB2A19924E3F17EA1F44D0084B5D5296A97A3624E4E1F6CA05229F2888557AAB57" +
		"7FD72F8DC328F0E4F45DD13A191920F671ACE3BC29DC3195E951D0F5EEAA095A3D5F20E4" +
		"E4EA1AC157261C1C514AEB6940E63053AD68383F14E923602E6B241E9813246B47F009DB" +
		"446FBF61246BAD7ED386647D020A854CCA39ECAE5FA6D667CB6D433F02BC2FAB9F37096F" +
		"3C127741EC02A46C81022E070AE1DF54623DF44C5C744EDD0D3BC66581B8E1348E75B5C5" +
		"2D0E41BC71EDAD5B12DDA2280724B7D704BFF2AF04505F65AE496DA86701D36BC9AFB0B1" +
		"99442A9C5C743D97880E89C8CCB34C51890602627924316E79D4415CC1C2ED490A7A6EBB" +
		"4B507181CFF18BB53A6B8F816C15A2EA8667CE59EDBE8F42376001E31981310CA403E083" +
		"28AA97828DC3A86C260819BC8DF72A3E29657CA65B7763A54067958CCD6FD73DF789B306" +
		"A37185C8117F0C86CF9D1C48D102ECA8343F41F86F6084E2E72E6952357D7DC076A02A7C" +
		"EF64724AE634E35712E291A24704D2939717246371B42C11A672FE8FD31DA83FC3D5DE65" +
		"0FB2136A13A0D6229A115EA3758E3AD0810A99944275FA8FECFD2BF1D130B40473F4ABF8" +
		"86485A1E36290DB437B331DB303539F98D298183509D934F1A747AF29BC36BD7CA79E5D4" +
		"0D098EBFE61F400620B5B1AFB81327342AADEC634F1A77DAE793D55A252D391AD155A615" +
		"0AB049CBA0270F07936AC21575BE6FAD53A0DC23F462E377F2C882391BAC1C17C11D18A6" +
		"77C3EFFACC4C6A920596F8654BB4955750BCBC18744375656F0B594D825872BB161A1B7F" +
		"DFE7D01E7A19E02F41AB9D02D1FED47161716172B8D68DB04E57C74053DAC785E9245BCC" +
		"8DCA48C736457EDEB8A075C1C42254E87110CBE4A909421AE6AECECE5D65834739BE6CAC" +
		"51D1023CA25C322B7B3461EC65168CCCF483A2668FB4527BCB312564C4097224DBC38AB3" +
		"97C3A7FD693B29992B9A773C43C0E9E94479F1762C91C367D9A079B13FDC38BD74F209E4" +
		"D543ABF8C9B14CED015599DFAE94723361ACBF6C1C0434DC0EFAF22C61057775F17F36D7" +
		"6FD75D6BFCE7DCE922DCD7585AA33CAE7A6916C4E4AC5F86E4753F8CC798C20205C8C476" +
		"56FBAD7799B6A53DAE5DCB74CDB677FFFA66CBF2873A219413714578D6DA3B61AA29C494" +
		"C2F084BE1FA1C1CC40D1E4A424A4CEC73E455062B6E28C333839570D6FC6C08402A8D39F" +
		"145B97C3AACC6F24702E80F66F5D2FA1530CFF2A07486B3D38D8C9994EE633C2E527AF49" +
		"FBE26F634C6663CF95520E04A76F33E8876826B88887C4FE8FDEB1C50F55C7E7FBC2A507" +
		"7FA029DB53B7CD8FA3576BBC219AE7D7B21518FD94FA187D39D63187BF9F2BF2592F1A7A" +
		"35628137D82E50477FF3406DABFE558A3FD30D4E72D1F523EBF51DF6C7BFD9C85325897A" +
		"7949113F30C9570F3A9FBAF73658430C3B2AFA43BF9D37D5410B5E416C5CF375CF9ADDCE" +
		"CF560E7D636C2D58B89D3E5A446201990EFFC467FFBA1009EE90D0F46BD2D7018AE92CAB" +
		"ECF62130BD7B4A077AF31882A713C73572387533EA249C9A18F0599C06EE216CFC60F749" +
		"8B2A75F3F8143D90A4ABF8651DEFAD600FD332AB09E3D8FAEFA2EC9152EAF6F2BE6B7862" +
		"9022C0231849BE4C13FA08B827EC301150FA380663F737418C8BF0700F4327F58C2256F8" +
		"BA8B61176DFD1ACE6A81C19033E3D678A9CB234F85A5B6372EAF1A1883F5ACED3ADF58B7" +
		"FABFE44D986DBEDA351EA9DE5A841CD523336F986AB8FBBECF1F52B1E87DBB3AC457A743" +
		"FAE899A5BB3D10EAFC4D0808B7FA98C8068093CAE7A0BC2074BAA701273734C28E97CD11" +
		"02FFBCEBB83EBB17C9200BE6DBE58BC87C522E4D24254204FD2EC52C60C1225649C3DEE1" +
		"7012C1CC0D5CDA0B2F0FC4F27274E04ACEDE68BACE92E294B589BE45D74C5377AFEAC718" +
		"2F4B702B5A50B49F1B32BD476483957C664676A819FE6851F07768DA82261C75D53F8F04" +
		"A64291A56E008B11AE09EE73923257EC195020D958F7B6D43ABA268978CB33B150A9C0DE" +
		"CAFBB36291257512CC7F2CB0B5564A0F81EF4686838CDBFE10475520E6EF69047CCA864E" +
		"50C86E9D91FC4EAE741D4BE8AD7B12952B76C3429548169C370A7A5E2DB3FC809B993095" +
		"2EF5AF9CDCCAF74FC13D0DB8D55862858E47E4C6F66FDA9DA423B884DB6ED79D012587F7" +
		"57F0BD974680AD8E"
	msg65Hex = "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8"
	sig65Hex = "BD0D51DB2F225AC6D3DA8F0C2439B0BCDA26EFF7EFA67CFD3C2B98EFA08477A74088DC63" +
		"8126865E493697B6FE360FF9C55B304D15A7474C983C3D8A4E1AB28FF9925CC9073AD986" +
		"D4B53C28B4CC909DC36B9334CC4510AFFDEA9548620923ED2158224AC5CA8FEF19228DBB" +
		"BF12956F5422176E8A474AFBE6EC6551F1FFDE71E86C48B39BE6CA540DBD78B985E89A2F" +
		"7576325E79DCF801585D30DCB3F971C827F4489745D450DF7AE34496C42C7A8778AAC7FD" +
		"DB9740CD3F07A8AFAD1C1471FB9591BBCF37BEAEA10C465ADB4BD7303ED6CA41AD4848CE" +
		"8A5659F7E3D4894AB0E79A0E7206C9FE278AC9CF1F6A3DA6B9FA8E03AFEEE717739CBFEB" +
		"5C26EF3B1C9130C8DD46F9C8E8149DA9B0FE5AA8FD03600F87824A6F2EE8BBCA0EF6D8C3" +
		"8EC526E982100BB8A8974EA91129BF827FE4CCA13D7203D38AC51B2A14025948E5AC0F71" +
		"394EB804C885521EE65EEA303CE30D0FA9626A914F36246A8F55EB2D866B215FC191CB73" +
		"4CC6B4724C8C1562F81E3678D39097871249B86833C6981FF45CEC71339E1C6F38ED1D04" +
		"B6C70C21642D268B5E058F8095101C2339EE5619280F2553308DBCFEF74537DD02722E42" +
		"608FFCA2E8EA8B8A2FECF46948C952D003071792845A07DBCFCC483B594CA9E0A6966449" +
		"8835DA427761E19F9FDF29E5319AA0FBAA7150DE0B1F951D9CC0E1B62DFB0857DB7C2129" +
		"A896D65DCE0ECD3A87FABCC2A4A6FA5811CF6312DC9E3ABFD5ACC116A8A25F45AD3736FD" +
		"B541276732DCD997B1B687BDAC9827A4582B8D3F0877595830E2079DCE9104E1FCFEFD0F" +
		"8225BA9739C30CA7671A05688B55BCA1F9ED968E6F3F2831E3D54E596707BF63FD6AA809" +
		"FE410EC38A17E3F8DE2E050A9E6B81CC386CC229041A7BE15FFC912FC4066A4D2D7FB98A" +
		"F7022840E593C4E599D0309F37B65B85F10541683300779FA41124B19D4032CF8D7AF572" +
		"6D3A08331D7A712DA910903C0A381F616CE5B1085F779486172EA4D7B127692557DD156B" +
		"63B0E445ED8888E446397542E50C9BFE7B728E31388F7743D0F51151D4B4CB7642431ED0" +
		"BAEAE264F4B2D9BAC2D5618338EE092228A251A4F99D4F95D263CAE16FB9A45A51D45BEF" +
		"0F6CAD30547AB4BAA1C6F28E6FF35B195D938514F58FC2B47BEB8C895D213F11035E5FAE" +
		"F85C917D7AA551FDF8D316CC4DE5A159CD4F39E3C118673984147C82BB41089CF0D9B671" +
		"2E899A99CBA5DE33BF33E2C0DA03745031A48A37F7E6A7288790839461F2C58BB5ED9347" +
		"7834B572DCE2DD00DD31B866C2387076037053872D8CF8EB57AE81FDD84823DC69FE0A33" +
		"F599846620AB74E86912759E245332EECFEFAAB9726F8A59256200BE72BC47DC3E0A4E28" +
		"868842935D216334191F32E0630920D8DB05EE62813218A1E1FC5DE96719D08A00FE7D50" +
		"72C8D51B3ED0AB0F9D5B45BBC2D5DD2CC7E6ECCB080D617565119C4B2A4E408A0B18EC96" +
		"9DCDB2BB7D8DE2EEEF3A76A0A5E437C6681AE7A00D54868E0F51EE39616AA29FEB7ABF4A" +
		"3E17865003B781497BA572EDE6EA7A9479FD15C295B79C0384D4D8451043C6F67F2E10D8" +
		"442F0C4E72684D6576FD41BC3756B1A8834082144760C7F609B3665C03F001073CCFEC1E" +
		"B18FB9A61D82A8462D0A86FF80520053C55F2D79502F95EEE9B50F1B95179BEAB6EB1ADC" +
		"4F582A9CA12C31E6F165E064AA9F289DD2A5E12F45E71C98CBC87DBF218926250D1A78DF" +
		"D2B46B1DB4844AC63C5A6960F67A6BF0B270337E629AC04BA47883E52C33246863EB9F54" +
		"BF2DFA5905F057490FE14F993D81EAC50E0D16DD0EB2098D0D1170FBF30892A7BFB45F6C" +
		"6B7E349865CF4313D1572CA41A06C0D5561B0704AF4BCD4CBFF4045C5F76A9A760751F7B" +
		"1432F8049CC9C0496F3E80026E2078CDC7BF54132C84200A4C27B23AAF69E97B25D8CBAD" +
		"A6F5C82748D73F8CEE44980B909EB0C11EB49FCEA972552BF5BE540DD9467EC81D709905" +
		"62DC558C00CFF68DB80F3D2BBE61D7E154A2D5A4166E86546D8A82886E1CFA28CE2D8BF5" +
		"7D67D9B6CE32D451F9B2B4D73474C299C64FDD8D2AE15EAFC3F88179B8B364FE16B51E7B" +
		"6C4DB47D796E159546BD409DD72879234578875C7940E057FB9508DDD9754D130F5CC3E3" +
		"2D82104DBCE1BA883FBC0C9AB9072A1A2771B0EA1152682D182D537EEEABE3F79C531A26" +
		"E236AEF6479D5A7817D00723D0183E4A1A671C3285BAE7793D7FF982A6B90F7D38E40F76" +
		"3EDC401F2BD0618D3E305257CFADD3CCFED8DD3FD03CDBB533976FA353ABE73503EF8360" +
		"964C2CA78888B4E67B0EEA68D35E64A840D136A7F0CA41CBBC52543BE45CA846F0213EEA" +
		"90D932AB3A6902795B0B4FAC28C838224309E94782FA315BFBB9A535F3763FA9C3C95FFA" +
		"3FFDA9C486678F7905A3637605A6929F234B9B04BDC729E14581888848930DF0D77FB1DB" +
		"65D75F292E0EC78FFF3352ECF99D87E0B6FFC78F5B9CB423FCCE606D74D35D115A418EEE" +
		"AE012026691B82D5B0262A1DD137ABF192683173A5615A3298A2224280C405EEE6094ADD" +
		"0E1ACEE74204BC0F8170221621A71743084A072FDF03293D8FD7778E8E3282DC49A1A950" +
		"404CE827C281E1F57E9DFA1F1156726DFCA3560F5C909987D6D79E831166155D5AAEE8F1" +
		"ED382863195ED48EA6924D7A119EA99756434092F08E217804EB4943E56A42CC7AC5CDFA" +
		"7CACE562FAC86AAF3BB5C3CF6F6DC35036B388E9EC8BE2272C2D6CA425FF23E6EF787833" +
		"2042B120246271B93F87C463434921D0BF6A105A2C7E473B3C5E4BC5828403C130005B2E" +
		"EDB7C161010A7A782AF3EA91700A7610DDA532DAC61DCA768B51541D2F6213B9C5047CA2" +
		"AC0E1DDA275EFB58359B5AE203706BBCB1B2DB3ED8896C3721B51865A6F9B4B8949FAB4F" +
		"3301AE7CBDC540F0B04FD6E27BE48748DA228DAE22353DA7CA1C464E70FB78960491279E" +
		"827128BEF241C764061A5AD103EE62B26AE08066C5F20B807883C8E8A3144B7968F23262" +
		"7440154FED536DCC09DC9E33BB7BCDAED850F0435E1B9D943F79640BA06F21F99A1D8999" +
		"7BC5529D1E69095DE36958B8F186C12007DAF19115B0F971DFACB126280E1C4B956C458F" +
		"9AD2EDF2226A696685A3DEACE620DBAD643B4B2E31911F53BBCC1E712B83DE8687D4956E" +
		"BE1A30CF4D7E86DBE8B6E28DD6AF59BF6E83E25D9B67458ABE922181C4BFA5E5D047A779" +
		"9D8F117411DA633096CE2ABF19C5317C545835B06A54759497605A0265A0396C4F069F7A" +
		"AF9E677140679A265893780B0F4ACA2E48010346CDA16356E6D69F48FBD6E9763E1EAF57" +
		"6008BD2EDCCA2DF8808989D801F687EFC97EBD1C0FAA8555664BDD49E39B38565480D7DE" +
		"0BB51E1CC5341DBF12DA73B5AA7DF954B5569272A7A3EA3AD45D8F65F718007A0C35AE3C" +
		"7206E14AE7033E4DCE999F232BBB488AEFF090A1D160B10847B134FA82867114C4EFB7CC" +
		"83DF601108E61457F7242FB159B0840D7711C0C50DEDBDDF346BFBA7C7EFCA4068B35B93" +
		"FF81054115AE59DE3C55BBA020AD66893B88AE491F8F6BD45BDB0D506D15E050B26BDD02" +
		"42F0EEC3092830E3F35D59A4B94B7A41A993F44DF9199EE6B084681D554AFD3970DD410E" +
		"748F4A95F3F5A3B2827F1C587B563FF7F0D7C47AF3B9F72B8AD6A46C2CB178929F80C185" +
		"2AD8247769BD4FEE274A0A07B20137CA67674E91779D9C6424F06E78A8BAC807C31CBB46" +
		"77E9CC7D8755997BD19DBF053F1EB7DD6DC3875E667088B0501FDDBAB90C6A4C215E28B1" +
		"7DB87B0F4423C6108813AC993F69CD20953E0C6B85E308F20F1855F5993FB269159F2EE5" +
		"D87316A0B744CD6530BFAF581C7FBAFD20689B702BDD4F907CD9D5ED768FAB06CD625B17" +
		"1D7159112E2446F8B6B2FD3B89F43D6C42B5120CFC98AE2762D241C41D32DFF80F714711" +
		"9FBA9900689E1919EAD74C77F27C046B513FE143884A439F1E8399CF97C7E83F3BA585C5" +
		"A0117251EFB5AFF33974D5B0FDBD61B62CA5692983643788AC31010E70E6909BE8757F6B" +
		"D2E721BAC6790F8DCA7D1AFCDA291F1DA1669E8906F4880E0E1BDC2608A0DF671BA401C1" +
		"78A53AA6E1B2D6C90D2769E4230B60E9FF10EE38A1532090B3D5076D1D320697F4AC06FC" +
		"8574136373FDF90D6872190E26F5311BAF686A95F47EF7A31F8A6AAF0196D3CCED25D5A5" +
		"49FE618D02F3C531FECF1C6770BE5B43FFC299519B7AA701BED350A09AF45B9268D8D5D8" +
		"1E8B962303C1F8E4BF15F5DE14A85312EB1C9511DF3E687CA14081754A2958324B4E5BAC" +
		"035C91240F01D7719DAAE546ED56885F1F393DF95690C20618AAE3229C6488AF7820C3E8" +
		"B421957CCF4F31A5173B7282FB972F7981AE53F73F2AE5747B608FB05F01888E80C1C6CA" +
		"031D52E573FBCDF986471D038EE3C6E0814E24E8DF75BDBAE63F2909B47D9401107439A6" +
		"B022C897763194687110D50779A9ACA6231B04D587A87CAADE5E4E91B7BCF43B2E469F52" +
		"DBF19AB1D180F477D5DF2E45ED2609638E22E4F5143BB0E733F16AD183153C8460E9D0A8" +
		"21C9AE4AD7DB358B18E91A9022A26283F553D722F4D37B3B9EA7E5F684A1395C72EAF261" +
		"50960A318B8901630E1A657479A2B1F7181A1C215678F3626BB7E2FD0F36498497A20F2D" +
		"3C467E803F697DA800000000000000000000000000000000000000080F141A2024"
)

func TestNewPublicKeyFails(t *testing.T) {
	for _, tc := range []struct {
		inst    mldsa.Instance
		privHex string
	}{
		{
			mldsa.MLDSA65,
			privKey65Hex,
		},
	} {
		t.Run(fmt.Sprintf("%s", tc.inst), func(t *testing.T) {
			tinkParams, err := mldsa.NewParameters(tc.inst, mldsa.VariantTink)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", mldsa.VariantTink, err)
			}
			noPrefixParams, err := mldsa.NewParameters(tc.inst, mldsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", mldsa.VariantNoPrefix, err)
			}
			privKeyBytes, err := hex.DecodeString(tc.privHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(inst.privHex) err = %v, want nil", err)
			}
			for _, tc := range []struct {
				name          string
				params        *mldsa.Parameters
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
					params:        &mldsa.Parameters{},
					keyBytes:      privKeyBytes,
					idRequirement: 123,
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if _, err := mldsa.NewPublicKey(tc.keyBytes, tc.idRequirement, tc.params); err == nil {
						t.Errorf("mldsa.NewPublicKey(%v, %v, %v) err = nil, want error", tc.keyBytes, tc.idRequirement, tc.params)
					}
				})
			}
		})
	}
}

func TestPublicKey(t *testing.T) {
	for _, tc := range []struct {
		name             string
		instance         mldsa.Instance
		variant          mldsa.Variant
		keyHex           string
		idRequirement    uint32
		wantOutputPrefix []byte
	}{
		{
			name:             "tink",
			instance:         mldsa.MLDSA65,
			variant:          mldsa.VariantTink,
			keyHex:           pubKey65Hex,
			idRequirement:    uint32(0x01020304),
			wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:             "no prefix",
			instance:         mldsa.MLDSA65,
			variant:          mldsa.VariantNoPrefix,
			keyHex:           pubKey65Hex,
			idRequirement:    0,
			wantOutputPrefix: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyBytes, err := hex.DecodeString(tc.keyHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
			}
			params, err := mldsa.NewParameters(tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			pubKey, err := mldsa.NewPublicKey(keyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("mldsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, tc.idRequirement, params, err)
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

			otherPubKey, err := mldsa.NewPublicKey(keyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("mldsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, tc.idRequirement, params, err)
			}
			if !otherPubKey.Equal(pubKey) {
				t.Errorf("otherPubKey.Equal(pubKey) = false, want true")
			}
		})
	}
}

func TestPublicKeyEqualSelf(t *testing.T) {
	for _, inst := range []mldsa.Instance{
		mldsa.MLDSA65,
	} {
		t.Run(fmt.Sprintf("%s", inst), func(t *testing.T) {
			params, err := mldsa.NewParameters(inst, mldsa.VariantTink)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", mldsa.VariantTink, err)
			}
			keyBytes, err := hex.DecodeString(pubKey65Hex)
			if err != nil {
				t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
			}
			pubKey, err := mldsa.NewPublicKey(keyBytes, 123, params)
			if err != nil {
				t.Fatalf("mldsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, 123, params, err)
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
	for _, inst := range []mldsa.Instance{
		mldsa.MLDSA65,
	} {
		t.Run(fmt.Sprintf("%s", inst), func(t *testing.T) {
			params, err := mldsa.NewParameters(inst, mldsa.VariantTink)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", mldsa.VariantTink, err)
			}
			keyBytes, err := hex.DecodeString(pubKey65Hex)
			if err != nil {
				t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
			}
			pubKey, err := mldsa.NewPublicKey(keyBytes, 123, params)
			if err != nil {
				t.Fatalf("mldsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, 123, params, err)
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
	instance       mldsa.Instance
	variant        mldsa.Variant
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
				keyHex:        pubKey65Hex,
				idRequirement: 123,
				instance:      mldsa.MLDSA65,
				variant:       mldsa.VariantTink,
			},
			secondKey: &TestPublicKeyParams{
				keyHex:        pubKey65Hex,
				idRequirement: 456,
				instance:      mldsa.MLDSA65,
				variant:       mldsa.VariantTink,
			},
		},
		{
			name: "different key bytes",
			firstKey: &TestPublicKeyParams{
				keyHex:        pubKey65Hex,
				idRequirement: 123,
				instance:      mldsa.MLDSA65,
				variant:       mldsa.VariantTink,
			},
			secondKey: &TestPublicKeyParams{
				keyHex:         pubKey65Hex,
				changeKeyBytes: true,
				idRequirement:  123,
				instance:       mldsa.MLDSA65,
				variant:        mldsa.VariantTink,
			},
		},
		{
			name: "different variant",
			firstKey: &TestPublicKeyParams{
				keyHex:        pubKey65Hex,
				idRequirement: 0,
				instance:      mldsa.MLDSA65,
				variant:       mldsa.VariantTink,
			},
			secondKey: &TestPublicKeyParams{
				keyHex:        pubKey65Hex,
				idRequirement: 0,
				instance:      mldsa.MLDSA65,
				variant:       mldsa.VariantNoPrefix,
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
			firstParams, err := mldsa.NewParameters(tc.firstKey.instance, tc.firstKey.variant)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", tc.firstKey.variant, err)
			}
			firstPubKey, err := mldsa.NewPublicKey(firstKeyBytes, tc.firstKey.idRequirement, firstParams)
			if err != nil {
				t.Fatalf("mldsa.NewPublicKey(%v, %v, %v) err = %v, want nil", firstKeyBytes, tc.firstKey.idRequirement, firstParams, err)
			}
			secondParams, err := mldsa.NewParameters(tc.secondKey.instance, tc.secondKey.variant)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", tc.secondKey.variant, err)
			}
			secondPubKey, err := mldsa.NewPublicKey(secondKeyBytes, tc.secondKey.idRequirement, secondParams)
			if err != nil {
				t.Fatalf("mldsa.NewPublicKey(%v, %v, %v) err = %v, want nil", secondKeyBytes, tc.secondKey.idRequirement, secondParams, err)
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
		instance mldsa.Instance
		keyHex   string
	}{
		{
			name:     "MLDSA65",
			instance: mldsa.MLDSA65,
			keyHex:   pubKey65Hex,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := mldsa.NewParameters(tc.instance, mldsa.VariantTink)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", mldsa.VariantTink, err)
			}
			keyBytes, err := hex.DecodeString(tc.keyHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(tc.keyHex) err = %v, want nil", err)
			}
			pubKey, err := mldsa.NewPublicKey(keyBytes, 123, params)
			if err != nil {
				t.Fatalf("mldsa.NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, 123, params, err)
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
	instance         mldsa.Instance
	variant          mldsa.Variant
	privKeyBytesHex  string
	pubKeyBytesHex   string
	idRequirement    uint32
	wantOutputPrefix []byte
}{
	{
		name:             "tink",
		instance:         mldsa.MLDSA65,
		variant:          mldsa.VariantTink,
		privKeyBytesHex:  privKey65Hex,
		pubKeyBytesHex:   pubKey65Hex,
		idRequirement:    uint32(0x01020304),
		wantOutputPrefix: []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
	},
	{
		name:             "no prefix",
		instance:         mldsa.MLDSA65,
		variant:          mldsa.VariantNoPrefix,
		privKeyBytesHex:  privKey65Hex,
		pubKeyBytesHex:   pubKey65Hex,
		idRequirement:    0,
		wantOutputPrefix: nil,
	},
}

func TestPrivateKeyNewPrivateKeyWithPublicKey(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params, err := mldsa.NewParameters(tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			pubKeyBytes, privKeyBytes := getTestKeyPair(t, tc.instance)
			pubKey, err := mldsa.NewPublicKey(pubKeyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("mldsa.NewPublicKey(%v, %v, %v) err = %v, want nil", pubKeyBytes, tc.idRequirement, params, err)
			}
			secretSeed := secretdata.NewBytesFromData(privKeyBytes, insecuresecretdataaccess.Token{})
			privKey, err := mldsa.NewPrivateKeyWithPublicKey(secretSeed, pubKey)
			if err != nil {
				t.Fatalf("mldsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v, want nil", secretSeed, pubKey, err)
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
			otherPubKey, err := mldsa.NewPublicKey(pubKeyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("mldsa.NewPublicKey(%v, %v, %v) err = %v, want nil", pubKeyBytes, tc.idRequirement, params, err)
			}
			otherPrivKey, err := mldsa.NewPrivateKeyWithPublicKey(secretSeed, otherPubKey)
			if err != nil {
				t.Fatalf("mldsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v, want nil", secretSeed, pubKey, err)
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
			params, err := mldsa.NewParameters(tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			pubKeyBytes, privKeyBytes := getTestKeyPair(t, tc.instance)
			secretSeed := secretdata.NewBytesFromData(privKeyBytes, insecuresecretdataaccess.Token{})
			privKey, err := mldsa.NewPrivateKey(secretSeed, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("mldsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", secretSeed, tc.idRequirement, params, err)
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
			otherPrivKey, err := mldsa.NewPrivateKey(secretSeed, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("mldsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", secretSeed, tc.idRequirement, params, err)
			}
			if !otherPrivKey.Equal(privKey) {
				t.Errorf("otherPrivKey.Equal(privKey) = false, want true")
			}

			// Test PublicKey.
			want, err := mldsa.NewPublicKey(pubKeyBytes, tc.idRequirement, params)
			if err != nil {
				t.Fatalf("mldsa.NewPublicKey(%v, %v, %v) err = %v, want nil", pubKeyBytes, tc.idRequirement, params, err)
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
	for _, inst := range []mldsa.Instance{
		mldsa.MLDSA65,
	} {
		t.Run(fmt.Sprintf("%s", inst), func(t *testing.T) {
			paramsTink, err := mldsa.NewParameters(inst, mldsa.VariantTink)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", mldsa.VariantTink, err)
			}
			paramsNoPrefix, err := mldsa.NewParameters(inst, mldsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", mldsa.VariantNoPrefix, err)
			}
			for _, tc := range []struct {
				name         string
				params       *mldsa.Parameters
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
					params:       &mldsa.Parameters{},
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
					if _, err := mldsa.NewPrivateKey(tc.privKeyBytes, tc.idRequrement, tc.params); err == nil {
						t.Errorf("ed25519.NewPrivateKey(%v, %v, %v) err = nil, want error", tc.privKeyBytes, tc.idRequrement, tc.params)
					}
				})
			}
		})
	}
}

func TestNewPrivateKeyWithPublicKeyFails(t *testing.T) {
	for _, inst := range []mldsa.Instance{
		mldsa.MLDSA65,
	} {
		t.Run(fmt.Sprintf("%s", inst), func(t *testing.T) {
			params, err := mldsa.NewParameters(inst, mldsa.VariantTink)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", mldsa.VariantTink, err)
			}
			pubKeyBytes, privKeyBytes := getTestKeyPair(t, inst)
			pubKey, err := mldsa.NewPublicKey(pubKeyBytes, 123, params)
			if err != nil {
				t.Fatalf("mldsa.NewPublicKey(%v, %v, %v) err = %v, want nil", pubKeyBytes, 123, params, err)
			}
			for _, tc := range []struct {
				name            string
				instance        mldsa.Instance
				pubKey          *mldsa.PublicKey
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
					pubKey:          &mldsa.PublicKey{},
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
					if _, err := mldsa.NewPrivateKeyWithPublicKey(tc.privateKeyBytes, tc.pubKey); err == nil {
						t.Errorf("mldsa.NewPrivateKeyWithPublicKey(%v, %v) err = nil, want error", tc.privateKeyBytes, tc.pubKey)
					}
				})
			}
		})
	}
}

func TestPrivateKeyEqualSelf(t *testing.T) {
	for _, inst := range []mldsa.Instance{
		mldsa.MLDSA65,
	} {
		t.Run(fmt.Sprintf("%s", inst), func(t *testing.T) {
			params, err := mldsa.NewParameters(inst, mldsa.VariantTink)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", mldsa.VariantTink, err)
			}
			pubKeyBytes, privKeyBytes := getTestKeyPair(t, inst)
			pubKey, err := mldsa.NewPublicKey(pubKeyBytes, 123, params)
			if err != nil {
				t.Fatalf("mldsa.NewPublicKey(%v, %v, %v) err = %v", pubKeyBytes, 123, params, err)
			}
			secretSeed := secretdata.NewBytesFromData(privKeyBytes, insecuresecretdataaccess.Token{})
			privKey, err := mldsa.NewPrivateKeyWithPublicKey(secretSeed, pubKey)
			if err != nil {
				t.Fatalf("mldsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v", secretSeed, pubKey, err)
			}
			if !privKey.Equal(privKey) {
				t.Errorf("privKey.Equal(privKey) = false, want true")
			}
		})
	}
}

func TestPrivateKeyEqual_FalseIfDifferentType(t *testing.T) {
	for _, inst := range []mldsa.Instance{
		mldsa.MLDSA65,
	} {
		t.Run(fmt.Sprintf("%s", inst), func(t *testing.T) {
			params, err := mldsa.NewParameters(inst, mldsa.VariantTink)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", mldsa.VariantTink, err)
			}
			pubKeyBytes, privKeyBytes := getTestKeyPair(t, inst)
			pubKey, err := mldsa.NewPublicKey(pubKeyBytes, 123, params)
			if err != nil {
				t.Fatalf("mldsa.NewPublicKey(%v, %v, %v) err = %v", pubKeyBytes, 123, params, err)
			}
			secretSeed := secretdata.NewBytesFromData(privKeyBytes, insecuresecretdataaccess.Token{})
			privKey, err := mldsa.NewPrivateKeyWithPublicKey(secretSeed, pubKey)
			if err != nil {
				t.Fatalf("mldsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v", secretSeed, pubKey, err)
			}
			if privKey.Equal(&stubKey{}) {
				t.Errorf("privKey.Equal(&stubKey{}) = true, want false")
			}
		})
	}
}

func TestPrivateKeyEqualFalse(t *testing.T) {
	for _, inst := range []mldsa.Instance{
		mldsa.MLDSA65,
	} {
		t.Run(fmt.Sprintf("%s", inst), func(t *testing.T) {
			paramsTink, err := mldsa.NewParameters(inst, mldsa.VariantTink)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", mldsa.VariantTink, err)
			}
			paramsNoPrefix, err := mldsa.NewParameters(inst, mldsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", mldsa.VariantNoPrefix, err)
			}
			for _, tc := range []struct {
				name           string
				privKeyBytes1  secretdata.Bytes
				params1        *mldsa.Parameters
				idRequirement1 uint32
				privKeyBytes2  secretdata.Bytes
				params2        *mldsa.Parameters
				idRequirement2 uint32
			}{
				{
					name:           "different private key bytes",
					privKeyBytes1:  secretdata.NewBytesFromData([]byte("12345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params1:        paramsTink,
					idRequirement1: 123,
					privKeyBytes2:  secretdata.NewBytesFromData([]byte("12345678123456781234567812345679"), insecuresecretdataaccess.Token{}),
					params2:        paramsTink,
					idRequirement2: 123,
				},
				{
					name:           "different ID requirement",
					privKeyBytes1:  secretdata.NewBytesFromData([]byte("12345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params1:        paramsTink,
					idRequirement1: 123,
					privKeyBytes2:  secretdata.NewBytesFromData([]byte("12345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params2:        paramsTink,
					idRequirement2: 456,
				},
				{
					name:           "different params",
					privKeyBytes1:  secretdata.NewBytesFromData([]byte("12345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params1:        paramsTink,
					idRequirement1: 0,
					privKeyBytes2:  secretdata.NewBytesFromData([]byte("12345678123456781234567812345678"), insecuresecretdataaccess.Token{}),
					params2:        paramsNoPrefix,
					idRequirement2: 0,
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					firstPrivKey, err := mldsa.NewPrivateKey(tc.privKeyBytes1, tc.idRequirement1, tc.params1)
					if err != nil {
						t.Fatalf("mldsa.NewPrivateKey(%v, %v, %v) err = %v", tc.privKeyBytes1, tc.idRequirement1, tc.params1, err)
					}
					secondPrivKey, err := mldsa.NewPrivateKey(tc.privKeyBytes2, tc.idRequirement2, tc.params2)
					if err != nil {
						t.Fatalf("mldsa.NewPrivateKey(%v, %v, %v) err = %v", tc.privKeyBytes2, tc.idRequirement2, tc.params2, err)
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
	for _, inst := range []mldsa.Instance{
		mldsa.MLDSA65,
	} {
		t.Run(fmt.Sprintf("%s", inst), func(t *testing.T) {
			pubKeyBytes, privKeyBytes := getTestKeyPair(t, inst)
			params, err := mldsa.NewParameters(inst, mldsa.VariantTink)
			if err != nil {
				t.Fatalf("mldsa.NewParameters(%v) err = %v, want nil", mldsa.VariantTink, err)
			}
			pubKey, err := mldsa.NewPublicKey([]byte(pubKeyBytes), 123, params)
			if err != nil {
				t.Fatalf("mldsa.NewPublicKey(%v, %v, %v) err = %v, want nil", []byte(pubKeyBytes), 123, params, err)
			}
			secretSeed := secretdata.NewBytesFromData([]byte(privKeyBytes), insecuresecretdataaccess.Token{})
			privKey, err := mldsa.NewPrivateKeyWithPublicKey(secretSeed, pubKey)
			if err != nil {
				t.Fatalf("mldsa.NewPrivateKeyWithPublicKey(%v, %v) err = %v, want nil", secretSeed, pubKey, err)
			}
			if got, want := privKey.PrivateKeyBytes().Data(insecuresecretdataaccess.Token{}), []byte(privKeyBytes); !bytes.Equal(got, want) {
				t.Errorf("bytes.Equal(got, want) = false, want true")
			}
		})
	}
}

func getTestKeyPair(t *testing.T, instance mldsa.Instance) ([]byte, []byte) {
	t.Helper()
	switch instance {
	case mldsa.MLDSA65:
		pubKeyBytes, err := hex.DecodeString(pubKey65Hex)
		if err != nil {
			t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
		}
		privKeyBytes, err := hex.DecodeString(privKey65Hex)
		if err != nil {
			t.Fatalf("hex.DecodeString(privKeyHex) err = %v, want nil", err)
		}
		return pubKeyBytes, privKeyBytes
	default:
		t.Fatalf("unsupported instance: %v", instance)
	}
	return nil, nil
}

func TestKeyCreator(t *testing.T) {
	params, err := mldsa.NewParameters(mldsa.MLDSA65, mldsa.VariantTink)
	if err != nil {
		t.Fatalf("mldsa.NewParameters() err = %v, want nil", err)
	}

	key, err := keygenregistry.CreateKey(params, 0x1234)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey(%v, 0x1234) err = %v, want nil", params, err)
	}
	mldsaPrivateKey, ok := key.(*mldsa.PrivateKey)
	if !ok {
		t.Fatalf("keygenregistry.CreateKey(%v, 0x1234) returned key of type %T, want %T", params, key, (*mldsa.PrivateKey)(nil))
	}
	idRequirement, hasIDRequirement := mldsaPrivateKey.IDRequirement()
	if !hasIDRequirement || idRequirement != 0x1234 {
		t.Errorf("mldsaPrivateKey.IDRequirement() (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 123, true)
	}
	if diff := cmp.Diff(mldsaPrivateKey.Parameters(), params); diff != "" {
		t.Errorf("mldsaPrivateKey.Parameters() diff (-want +got):\n%s", diff)
	}
}

func TestPrivateKeyCreator_Fails(t *testing.T) {
	paramsNoPrefix, err := mldsa.NewParameters(mldsa.MLDSA65, mldsa.VariantNoPrefix)
	if err != nil {
		t.Fatalf("mldsa.NewParameters() err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name          string
		params        *mldsa.Parameters
		idRequirement uint32
	}{
		{
			name:          "invalid id requirement",
			params:        paramsNoPrefix,
			idRequirement: 0x1234,
		},
		{
			name:          "invalid parameters",
			params:        &mldsa.Parameters{},
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

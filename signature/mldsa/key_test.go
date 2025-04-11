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

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
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

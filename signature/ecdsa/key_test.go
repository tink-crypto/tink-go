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

package ecdsa_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature/ecdsa"
)

func TestNewParametersInvalidValues(t *testing.T) {
	testCases := []struct {
		name      string
		curveType ecdsa.CurveType
		hashType  ecdsa.HashType
		encoding  ecdsa.SignatureEncoding
		variant   ecdsa.Variant
	}{
		{
			name:      "unkown curve type",
			curveType: ecdsa.UnknownCurveType,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "unkown encoding",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.UnknownSignatureEncoding,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "unkown variant",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantUnknown,
		},
		{
			name:      "unkown hash type",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.UnknownHashType,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "invalid curve type value (negative)",
			curveType: -1,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "invalid encoding value (negative)",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  -1,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "invalid variant value (negative)",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   -1,
		},
		{
			name:      "invalid hash type value (negative)",
			curveType: ecdsa.NistP256,
			hashType:  -1,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "invalid curve type value (too large)",
			curveType: 10,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "invalid encoding value (too large)",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  10,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "invalid variant value (too large)",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   10,
		},
		{
			name:      "invalid hash type value (too large)",
			curveType: ecdsa.NistP256,
			hashType:  10,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "NistP256 with SHA384",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA384,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "NistP256 with SHA512",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA512,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "NistP384 with SHA256",
			curveType: ecdsa.NistP384,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "NistP521 with SHA256",
			curveType: ecdsa.NistP521,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "NistP521 with SHA384",
			curveType: ecdsa.NistP521,
			hashType:  ecdsa.SHA384,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ecdsa.NewParameters(tc.curveType, tc.hashType, tc.encoding, tc.variant); err == nil {
				t.Errorf("ecdsa.NewParameters(%v, %v, %v, %v) = nil, want error", tc.curveType, tc.hashType, tc.encoding, tc.variant)
			}
		})
	}
}

func TestNewParameters(t *testing.T) {
	testCases := []struct {
		name      string
		curveType ecdsa.CurveType
		hashType  ecdsa.HashType
		encoding  ecdsa.SignatureEncoding
	}{
		{
			name:      "NistP256 with SHA256 and DER encoding",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
		},
		{
			name:      "NistP384 with SHA384 and DER encoding",
			curveType: ecdsa.NistP384,
			hashType:  ecdsa.SHA384,
			encoding:  ecdsa.DER,
		},
		{
			name:      "NistP384 with SHA384 and DER encoding",
			curveType: ecdsa.NistP384,
			hashType:  ecdsa.SHA384,
			encoding:  ecdsa.DER,
		},
		{
			name:      "NistP384 with SHA512 and DER encoding",
			curveType: ecdsa.NistP384,
			hashType:  ecdsa.SHA512,
			encoding:  ecdsa.DER,
		},
		{
			name:      "NistP521 with SHA512 and DER encoding",
			curveType: ecdsa.NistP521,
			hashType:  ecdsa.SHA512,
			encoding:  ecdsa.DER,
		},
		{
			name:      "NistP256 with SHA256 and IEEEP1363 encoding",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.IEEEP1363,
		},
		{
			name:      "NistP384 with SHA384 and IEEEP1363 encoding",
			curveType: ecdsa.NistP384,
			hashType:  ecdsa.SHA384,
			encoding:  ecdsa.IEEEP1363,
		},
		{
			name:      "NistP384 with SHA384 and IEEEP1363 encoding",
			curveType: ecdsa.NistP384,
			hashType:  ecdsa.SHA384,
			encoding:  ecdsa.IEEEP1363,
		},
		{
			name:      "NistP384 with SHA512 and IEEEP1363 encoding",
			curveType: ecdsa.NistP384,
			hashType:  ecdsa.SHA512,
			encoding:  ecdsa.IEEEP1363,
		},
		{
			name:      "NistP521 with SHA512 and IEEEP1363 encoding",
			curveType: ecdsa.NistP521,
			hashType:  ecdsa.SHA512,
			encoding:  ecdsa.IEEEP1363,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params, err := ecdsa.NewParameters(tc.curveType, tc.hashType, tc.encoding, ecdsa.VariantTink)
			if err != nil {
				t.Fatalf("ecdsa.NewParameters(%v, %v, %v, %v) = %v, want nil", tc.curveType, tc.hashType, tc.encoding, ecdsa.VariantTink, err)
			}
			if got, want := params.CurveType(), tc.curveType; got != want {
				t.Errorf("params.CurveType() = %v, want %v", got, want)
			}
			if got, want := params.HashType(), tc.hashType; got != want {
				t.Errorf("params.HashType() = %v, want %v", got, want)
			}
			if got, want := params.SignatureEncoding(), tc.encoding; got != want {
				t.Errorf("params.SignatureEncoding() = %v, want %v", got, want)
			}
			if got, want := params.Variant(), ecdsa.VariantTink; got != want {
				t.Errorf("params.Variant() = %v, want %v", got, want)
			}
			if got, want := params.HasIDRequirement(), true; got != want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, want)
			}
			other, err := ecdsa.NewParameters(tc.curveType, tc.hashType, tc.encoding, ecdsa.VariantTink)
			if err != nil {
				t.Fatalf("ecdsa.NewParameters(%v, %v, %v, %v) = %v, want nil", tc.curveType, tc.hashType, tc.encoding, ecdsa.VariantTink, err)
			}
			if !params.Equals(other) {
				t.Errorf("params.Equals(other) = false, want true")
			}
		})
	}
}

const (
	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.5
	pubKeyXP256Hex      = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
	pubKeyYP256Hex      = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
	privKeyValueP256Hex = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
	// Encoded as an uncompressed octet string as per [SEC 1 v2.0, Section 2.3.3]
	//
	// [SEC 1 v2.0, Section 2.3.3]: https://www.secg.org/sec1-v2.pdf#page=17.08
	pubKeyUncompressedP256Hex        = "04" + pubKeyXP256Hex + pubKeyYP256Hex
	pubKeyUncompressedP256InvalidHex = "04" + pubKeyXP256Hex + "08c8049879c6278b227334847415851500000000000000000000000000000000"

	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.6
	pubKeyXP384Hex            = "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13"
	pubKeyYP384Hex            = "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720"
	privKeyValueP384Hex       = "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5"
	pubKeyUncompressedP384Hex = "04" + pubKeyXP384Hex + pubKeyYP384Hex

	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.7
	pubKeyXP521Hex            = "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4"
	pubKeyYP521Hex            = "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5"
	privKeyValueP521Hex       = "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"
	pubKeyUncompressedP521Hex = "04" + pubKeyXP521Hex + pubKeyYP521Hex

	// From https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.4
	pubKeyXP224Hex            = "00CF08DA5AD719E42707FA431292DEA11244D64FC51610D94B130D6C"
	pubKeyYP224Hex            = "EEAB6F3DEBE455E3DBF85416F7030CBD94F34F2D6F232C69F3C1385A"
	pubKeyUncompressedP224Hex = "04" + pubKeyXP224Hex + pubKeyYP224Hex
)

func bytesFromHex(t *testing.T, hexStr string) []byte {
	t.Helper()
	x, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex.DecodeString(%v) err = %v, want nil", hexStr, err)
	}
	return x
}

func TestNewPublicKeyInvalidValues(t *testing.T) {
	validPoint := bytesFromHex(t, pubKeyUncompressedP256Hex)
	invalidPoint := bytesFromHex(t, pubKeyUncompressedP256InvalidHex)
	validParams, err := ecdsa.NewParameters(ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantTink)
	if err != nil {
		t.Fatalf("ecdsa.NewParameters(%v, %v, %v, %v) = %v, want nil", ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantTink, err)
	}
	validParamsNoPrefix, err := ecdsa.NewParameters(ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantNoPrefix)
	if err != nil {
		t.Fatalf("ecdsa.NewParameters(%v, %v, %v, %v) = %v, want nil", ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantNoPrefix, err)
	}
	validPointOnAnotherCurve := bytesFromHex(t, pubKeyUncompressedP521Hex)

	validPointOnP224 := bytesFromHex(t, pubKeyUncompressedP224Hex)
	for _, tc := range []struct {
		name       string
		point      []byte
		keyID      uint32
		parameters *ecdsa.Parameters
	}{
		{
			name:       "nil params",
			point:      validPoint,
			keyID:      123,
			parameters: nil,
		},
		{
			name:       "empty params",
			point:      validPoint,
			keyID:      123,
			parameters: &ecdsa.Parameters{},
		},
		{
			name:       "nil point",
			point:      nil,
			keyID:      123,
			parameters: validParams,
		},
		{
			name:       "empty point",
			point:      []byte{},
			keyID:      123,
			parameters: validParams,
		},
		{
			name:       "valid point with extra byte",
			point:      append(validPoint, 0xFF),
			keyID:      123,
			parameters: validParams,
		},
		{
			name:       "valid point in cruncy uncompressed format",
			point:      validPoint[1:],
			keyID:      123,
			parameters: validParams,
		},
		{
			name:       "valid point missing last byte",
			point:      validPoint[:len(validPoint)-1],
			keyID:      123,
			parameters: validParams,
		},
		{
			name:       "valid point on wrong curve",
			point:      validPointOnAnotherCurve,
			keyID:      123,
			parameters: validParams,
		},
		{
			name:       "valid point on unsupported curve",
			point:      validPointOnP224,
			keyID:      123,
			parameters: validParams,
		},
		{
			name:       "invalid point",
			point:      invalidPoint,
			keyID:      123,
			parameters: validParams,
		},
		{
			name:       "invalid key ID",
			point:      validPoint,
			keyID:      123,
			parameters: validParamsNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ecdsa.NewPublicKey(tc.point, tc.keyID, tc.parameters); err == nil {
				t.Errorf("ecdsa.NewPublicKey(%v, %d, %v) = nil, want error", tc.point, tc.keyID, tc.parameters)
			}
		})
	}
}

type testCase struct {
	name      string
	point, d  string
	id        uint32
	curveType ecdsa.CurveType
	hashType  ecdsa.HashType
	encoding  ecdsa.SignatureEncoding
	variant   ecdsa.Variant
}

var (
	// Sampled from
	// https://github.com/google/boringssl/blob/f10c1dc37174843c504a80e94c252e35b7b1eb61/crypto/fipsmodule/ecdsa/ecdsa_sign_tests.txt
	testVectors = []struct {
		point, d  string
		curveType ecdsa.CurveType
	}{
		{
			point:     "0429578c7ab6ce0d11493c95d5ea05d299d536801ca9cbd50e9924e43b733b83ab08c8049879c6278b2273348474158515accaa38344106ef96803c5a05adc4800",
			d:         "708309a7449e156b0db70e5b52e606c7e094ed676ce8953bf6c14757c826f590",
			curveType: ecdsa.NistP256,
		},
		{
			point:     "044a92396ff7930b1da9a873a479a28a9896af6cc3d39345b949b726dc3cd978b5475abb18eaed948879b9c1453e3ef2755dd90f77519ec7b6a30297aad08e4931",
			d:         "90c5386100b137a75b0bb495002b28697a451add2f1f22cb65f735e8aaeace98",
			curveType: ecdsa.NistP256,
		},
		{
			point:     "045775174deb0248112e069cb86f1546ac7a78bc2127d0cb953bad46384dd6be5ba27020952971cc0b0c3abd06e9ca3e141a4943f560564eba31e5288928bc7ce7",
			d:         "a3a43cece9c1abeff81099fb344d01f7d8df66447b95a667ee368f924bccf870",
			curveType: ecdsa.NistP256,
		},
		{
			point:     "0400ea9d109dbaa3900461a9236453952b1f1c2a5aa12f6d500ac774acdff84ab7cb71a0f91bcd55aaa57cb8b4fbb3087d0fc0e3116c9e94be583b02b21b1eb168d8facf3955279360cbcd86e04ee50751054cfaebcf542538ac113d56ccc38b3e",
			d:         "0af857beff08046f23b03c4299eda86490393bde88e4f74348886b200555276b93b37d4f6fdec17c0ea581a30c59c727",
			curveType: ecdsa.NistP384,
		},
		{
			point:     "04de92ff09af2950854a70f2178d2ed50cc7042a7188301a1ea81d9629ad3c29795cb7f0d56630a401e4d6e5bed0068d1e6135adbd8624130735e64e65ecbd43770dcc12b28e737b5ed033666f34c918eb5589508e4a13b9243374a118a628dd0b",
			d:         "047dd5baab23f439ec23b58b7e6ff4cc37813cccb4ea73bb2308e6b82b3170edfe0e131eca50841bf1b686e651c57246",
			curveType: ecdsa.NistP384,
		},
		{
			point:     "043db95ded500b2506b627270bac75688dd7d44f47029adeff99397ab4b6329a38dbb278a0fc58fe4914e6ae31721a6875049288341553a9ac3dc2d9e18e7a92c43dd3c25ca866f0cb4c68127bef6b0e4ba85713d27d45c7d0dc57e5782a6bf733",
			d:         "54ba9c740535574cebc41ca5dc950629674ee94730353ac521aafd1c342d3f8ac52046ed804264e1440d7fe409c45c83",
			curveType: ecdsa.NistP384,
		},
		{
			point:     "0401a7596d38aac7868327ddc1ef5e8178cf052b7ebc512828e8a45955d85bef49494d15278198bbcc5454358c12a2af9a3874e7002e1a2f02fcb36ff3e3b4bc0c69e70184902e515982bb225b8c84f245e61b327c08e94d41c07d0b4101a963e02fe52f6a9f33e8b1de2394e0cb74c40790b4e489b5500e6804cabed0fe8c192443d4027b",
			d:         "01d7bb864c5b5ecae019296cf9b5c63a166f5f1113942819b1933d889a96d12245777a99428f93de4fc9a18d709bf91889d7f8dddd522b4c364aeae13c983e9fae46",
			curveType: ecdsa.NistP521,
		},
		{
			point:     "0400156cd2c485012ea5d5aadad724fb87558637de37b34485c4cf7c8cbc3e4f106cb1efd3e64f0adf99ddb51e3ac991bdd90785172386cdaf2c582cc46d6c99b0fed101edeeda717554252b9f1e13553d4af028ec9e158dbe12332684fc1676dc731f39138a5d301376505a9ab04d562cc1659b0be9cb2b5e03bad8b412f2699c245b0ba2",
			d:         "017e49b8ea8f9d1b7c0378e378a7a42e68e12cf78779ed41dcd29a090ae7e0f883b0d0f2cbc8f0473c0ad6732bea40d371a7f363bc6537d075bd1a4c23e558b0bc73",
			curveType: ecdsa.NistP521,
		},
		{
			point:     "04018d40cc4573892b3e467d314c39c95615ee0510e3e4dbc9fa28f6cd1f73e7acde15ad7c8c5339df9a7774f8155130e7d1f8de9139ddd6dfe1841c1e64c38ea98243017021782d33dc513716c83afe7ba5e7abef9cb25b31f483661115b8d6b5ae469aaf6f3d54baa3b658a9af9b6249fd4d5ea7a07cb8b600f1df72b81dac614cfc384a",
			d:         "0135ea346852f837d10c1b2dfb8012ae8215801a7e85d4446dadd993c68d1e9206e1d8651b7ed763b95f707a52410eeef4f21ae9429828289eaea1fd9caadf826ace",
			curveType: ecdsa.NistP521,
		},
	}
	testCases = func() []testCase {
		tc := []testCase{}
		for _, variantAndID := range []struct {
			variant ecdsa.Variant
			id      uint32
		}{
			{
				variant: ecdsa.VariantTink,
				id:      123,
			},
			{
				variant: ecdsa.VariantCrunchy,
				id:      123,
			},
			{
				variant: ecdsa.VariantLegacy,
				id:      123,
			},
			{
				variant: ecdsa.VariantNoPrefix,
				id:      0,
			},
		} {
			for _, encoding := range []ecdsa.SignatureEncoding{ecdsa.DER, ecdsa.IEEEP1363} {
				for _, tv := range testVectors {
					switch tv.curveType {
					case ecdsa.NistP256:
						{
							tc = append(tc, testCase{
								point:     tv.point,
								d:         tv.d,
								id:        variantAndID.id,
								hashType:  ecdsa.SHA256,
								curveType: tv.curveType,
								encoding:  encoding,
								variant:   variantAndID.variant,
							})
						}
					case ecdsa.NistP384:
						{
							tc = append(tc, testCase{
								point:     tv.point,
								d:         tv.d,
								id:        variantAndID.id,
								hashType:  ecdsa.SHA384,
								curveType: tv.curveType,
								encoding:  encoding,
								variant:   variantAndID.variant,
							})
							tc = append(tc, testCase{
								point:     tv.point,
								d:         tv.d,
								id:        variantAndID.id,
								hashType:  ecdsa.SHA512,
								curveType: tv.curveType,
								encoding:  encoding,
								variant:   variantAndID.variant,
							})
						}
					case ecdsa.NistP521:
						{
							tc = append(tc, testCase{
								point:     tv.point,
								d:         tv.d,
								id:        variantAndID.id,
								hashType:  ecdsa.SHA512,
								curveType: tv.curveType,
								encoding:  encoding,
								variant:   variantAndID.variant,
							})
						}
					}
				}
			}
		}
		return tc
	}()
)

func TestNewPublicKey(t *testing.T) {
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("curveType: %v, hashType: %v, encoding: %v, variant: %v, id: %d", tc.curveType, tc.hashType, tc.encoding, tc.variant, tc.id), func(t *testing.T) {
			point := bytesFromHex(t, tc.point)
			params, err := ecdsa.NewParameters(tc.curveType, tc.hashType, tc.encoding, tc.variant)
			if err != nil {
				t.Fatalf("ecdsa.NewParameters(%v, %v, %v, %v) = %v, want nil", tc.curveType, tc.hashType, tc.encoding, tc.variant, err)
			}
			pubKey, err := ecdsa.NewPublicKey(point, tc.id, params)
			if err != nil {
				t.Errorf("ecdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", point, tc.id, params, err)
			}
			if got, want := pubKey.PublicPoint(), point; !bytes.Equal(got, want) {
				t.Errorf("pubKey.PublicKey() = %v, want %v", got, want)
			}
			if got, want := pubKey.Parameters(), params; !got.Equals(want) {
				t.Errorf("pubKey.Parameters() = %v, want %v", got, want)
			}
			gotIDRequirement, gotRequired := pubKey.IDRequirement()
			wantIDRequirement, wantRequired := tc.id, params.HasIDRequirement()
			if gotIDRequirement != wantIDRequirement || gotRequired != wantRequired {
				t.Errorf("pubKey.IDRequirement() = (%v, %v), want (%v, %v)", gotIDRequirement, gotRequired, wantIDRequirement, wantRequired)
			}
			otherKey, err := ecdsa.NewPublicKey(point, tc.id, params)
			if err != nil {
				t.Fatalf("ecdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", point, tc.id, params, err)
			}
			if !pubKey.Equals(otherKey) {
				t.Errorf("pubKey.Equals(otherKey) = false, want true")
			}
		})
	}
}

func TestPublicKeyOutputPrefix(t *testing.T) {
	publicPoint := bytesFromHex(t, pubKeyUncompressedP256Hex)
	for _, tc := range []struct {
		name    string
		variant ecdsa.Variant
		id      uint32
		want    []byte
	}{
		{
			name:    "Tink",
			variant: ecdsa.VariantTink,
			id:      uint32(0x01020304),
			want:    []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "Crunchy",
			variant: ecdsa.VariantCrunchy,
			id:      uint32(0x01020304),
			want:    []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "Legacy",
			variant: ecdsa.VariantLegacy,
			id:      uint32(0x01020304),
			want:    []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "NoPrefix",
			variant: ecdsa.VariantNoPrefix,
			id:      0,
			want:    nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := ecdsa.NewParameters(ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, tc.variant)
			if err != nil {
				t.Fatalf("ecdsa.NewParameters(%v, %v, %v, %v) = %v, want nil", ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, tc.variant, err)
			}
			pubKey, err := ecdsa.NewPublicKey(publicPoint, tc.id, params)
			if err != nil {
				t.Fatalf("ecdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", publicPoint, tc.id, params, err)
			}
			if got, want := pubKey.OutputPrefix(), tc.want; !bytes.Equal(got, want) {
				t.Errorf("pubKey.OutputPrefix() = %v, want %v", got, want)
			}
		})
	}
}

func newParameters(t *testing.T, curveType ecdsa.CurveType, hashType ecdsa.HashType, signatureEncoding ecdsa.SignatureEncoding, variant ecdsa.Variant) *ecdsa.Parameters {
	t.Helper()
	params, err := ecdsa.NewParameters(curveType, hashType, signatureEncoding, variant)
	if err != nil {
		t.Fatalf("ecdsa.NewParameters(%v, %v, %v, %v) = %v, want nil", curveType, hashType, signatureEncoding, variant, err)
	}
	return params
}

func newPublicKey(t *testing.T, point []byte, id uint32, params *ecdsa.Parameters) *ecdsa.PublicKey {
	t.Helper()
	pubKey, err := ecdsa.NewPublicKey(point, id, params)
	if err != nil {
		t.Fatalf("ecdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", point, id, params, err)
	}
	return pubKey
}

func TestNewPrivateKeyInvalidValues(t *testing.T) {
	params := newParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantTink)
	token := insecuresecretdataaccess.Token{}
	for _, tc := range []struct {
		name            string
		params          *ecdsa.Parameters
		privateKeyValue secretdata.Bytes
	}{
		{
			name:            "nil params key",
			params:          nil,
			privateKeyValue: secretdata.NewBytesFromData(bytesFromHex(t, privKeyValueP256Hex), token),
		},
		{
			name:            "empty params key",
			params:          &ecdsa.Parameters{},
			privateKeyValue: secretdata.NewBytesFromData(bytesFromHex(t, privKeyValueP256Hex), token),
		},
		{
			name:            "empty private key value",
			params:          params,
			privateKeyValue: secretdata.NewBytesFromData([]byte{}, token),
		},
		{
			name:            "nil private key value",
			params:          params,
			privateKeyValue: secretdata.NewBytesFromData(nil, token),
		},
		{
			name:            "too small private key value",
			params:          params,
			privateKeyValue: secretdata.NewBytesFromData([]byte("123"), token),
		},
		{
			name:            "too large private key value",
			params:          params,
			privateKeyValue: secretdata.NewBytesFromData([]byte("000000000000000000000000000000000000000000000000"), token),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ecdsa.NewPrivateKey(tc.privateKeyValue, 123, tc.params); err == nil {
				t.Errorf("ecdsa.NewPrivateKey(tc.privateKeyValue, 123, %v) = nil, want error", tc.params)
			}
		})
	}
}

func TestNewPrivateKey(t *testing.T) {
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("curveType: %v, hashType: %v, encoding: %v, variant: %v, id: %d", tc.curveType, tc.hashType, tc.encoding, tc.variant, tc.id), func(t *testing.T) {
			params := newParameters(t, tc.curveType, tc.hashType, tc.encoding, tc.variant)
			publicKey := newPublicKey(t, bytesFromHex(t, tc.point), tc.id, params)
			token := insecuresecretdataaccess.Token{}

			privateKeyValueBytes := bytesFromHex(t, tc.d)
			privateKeyValue := secretdata.NewBytesFromData(privateKeyValueBytes, token)
			prvKey, err := ecdsa.NewPrivateKey(privateKeyValue, tc.id, params)
			if err != nil {
				t.Errorf("ecdsa.NewPrivateKey(privateKeyValue, %v, %v) err = %v, want nil", tc.id, params, err)
			}

			// Check accessor methods.
			if got, want := prvKey.PrivateKeyValue(), privateKeyValue; !got.Equals(want) {
				t.Errorf("prvKey.PrivateKeyValue() = %x, want %x", got.Data(token), want.Data(token))
			}
			gotIDRequirement, gotRequired := prvKey.IDRequirement()
			wantIDRequirement, wantRequired := publicKey.IDRequirement()
			if gotIDRequirement != wantIDRequirement || gotRequired != wantRequired {
				t.Errorf("invalid ID requirement: got (%v, %v), want (%v, %v)", gotIDRequirement, gotRequired, wantIDRequirement, wantRequired)
			}
			if got, want := prvKey.OutputPrefix(), publicKey.OutputPrefix(); !bytes.Equal(got, want) {
				t.Errorf("prvKey.OutputPrefix() = %v, want %v", got, want)
			}
			if got, want := prvKey.Parameters(), params; !got.Equals(want) {
				t.Errorf("prvKey.Parameters() = %v, want %v", got, want)
			}
			want, err := prvKey.PublicKey()
			if err != nil {
				t.Fatalf("prvKey.PublicKey() err = %v, want nil", err)
			}
			if got := publicKey; !got.Equals(want) {
				t.Errorf("prvKey.PublicKey() = %v, want %v", got, want)
			}

			otherPrvKey, err := ecdsa.NewPrivateKey(privateKeyValue, tc.id, params)
			if err != nil {
				t.Fatalf("ecdsa.NewPrivateKey(privateKeyValue, %v, %v) err = %v, want nil", tc.id, params, err)
			}
			if !otherPrvKey.Equals(prvKey) {
				t.Errorf("otherPrvKey.Equals(prvKey) = false, want true")
			}
		})
	}
}

func TestNewPrivateKeyFromPublicKeyInvalidValues(t *testing.T) {
	publicPoint := bytesFromHex(t, pubKeyUncompressedP256Hex)
	publicKey := newPublicKey(t, publicPoint, 123, newParameters(t, ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantCrunchy))
	token := insecuresecretdataaccess.Token{}
	for _, tc := range []struct {
		name            string
		publicKey       *ecdsa.PublicKey
		privateKeyValue secretdata.Bytes
	}{
		{
			name:            "nil public key",
			publicKey:       nil,
			privateKeyValue: secretdata.NewBytesFromData(bytesFromHex(t, privKeyValueP256Hex), token),
		},
		{
			name:            "empty public key",
			publicKey:       &ecdsa.PublicKey{},
			privateKeyValue: secretdata.NewBytesFromData(bytesFromHex(t, privKeyValueP256Hex), token),
		},
		{
			name:            "empty private key value",
			publicKey:       publicKey,
			privateKeyValue: secretdata.NewBytesFromData([]byte{}, token),
		},
		{
			name:            "nil private key value",
			publicKey:       publicKey,
			privateKeyValue: secretdata.NewBytesFromData(nil, token),
		},
		{
			name:            "too small private key value",
			publicKey:       publicKey,
			privateKeyValue: secretdata.NewBytesFromData([]byte("123"), token),
		},
		{
			name:            "too large private key value",
			publicKey:       publicKey,
			privateKeyValue: secretdata.NewBytesFromData([]byte("000000000000000000000000000000000000000000000000"), token),
		},
		{
			name:            "invalid private key value",
			publicKey:       publicKey,
			privateKeyValue: secretdata.NewBytesFromData([]byte("00000000000000000000000000000000"), token),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ecdsa.NewPrivateKeyFromPublicKey(tc.publicKey, tc.privateKeyValue); err == nil {
				t.Errorf("ecdsa.NewPrivateKeyFromPublicKey(%v, tc.privateKeyValue) = nil, want error", tc.publicKey)
			}
		})
	}
}

func TestNewPrivateKeyFromPublicKey(t *testing.T) {
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("curveType: %v, hashType: %v, encoding: %v, variant: %v, id: %d", tc.curveType, tc.hashType, tc.encoding, tc.variant, tc.id), func(t *testing.T) {
			params := newParameters(t, tc.curveType, tc.hashType, tc.encoding, tc.variant)
			publicKey := newPublicKey(t, bytesFromHex(t, tc.point), tc.id, params)
			token := insecuresecretdataaccess.Token{}

			privateKeyValueBytes := bytesFromHex(t, tc.d)
			privateKeyValue := secretdata.NewBytesFromData(privateKeyValueBytes, token)
			prvKey, err := ecdsa.NewPrivateKeyFromPublicKey(publicKey, privateKeyValue)
			if err != nil {
				t.Errorf("ecdsa.NewPrivateKeyFromPublicKey(%v, privateKeyValue) err = %v, want nil", publicKey, err)
			}

			// Check accessor methods.
			if got, want := prvKey.PrivateKeyValue(), privateKeyValue; !got.Equals(want) {
				t.Errorf("prvKey.PrivateKeyValue() = %x, want %x", got.Data(token), want.Data(token))
			}
			gotIDRequirement, gotRequired := prvKey.IDRequirement()
			wantIDRequirement, wantRequired := publicKey.IDRequirement()
			if gotIDRequirement != wantIDRequirement || gotRequired != wantRequired {
				t.Errorf("invalid ID requirement: got (%v, %v), want (%v, %v)", gotIDRequirement, gotRequired, wantIDRequirement, wantRequired)
			}
			if got, want := prvKey.OutputPrefix(), publicKey.OutputPrefix(); !bytes.Equal(got, want) {
				t.Errorf("prvKey.OutputPrefix() = %v, want %v", got, want)
			}
			if got, want := prvKey.Parameters(), params; !got.Equals(want) {
				t.Errorf("prvKey.Parameters() = %v, want %v", got, want)
			}
			want, err := prvKey.PublicKey()
			if err != nil {
				t.Fatalf("prvKey.PublicKey() err = %v, want nil", err)
			}
			if got := publicKey; !got.Equals(want) {
				t.Errorf("prvKey.PublicKey() = %v, want %v", got, want)
			}

			otherPrvKey, err := ecdsa.NewPrivateKeyFromPublicKey(publicKey, privateKeyValue)
			if err != nil {
				t.Fatalf("ecdsa.NewPrivateKeyFromPublicKey(%v, privateKeyValue) err = %v, want nil", publicKey, err)
			}
			if !otherPrvKey.Equals(prvKey) {
				t.Errorf("otherPrvKey.Equals(prvKey) = false, want true")
			}
		})
	}
}

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
	// Taken from
	// https://github.com/google/boringssl/blob/59c222fcf123ec2026da450a0a8676436751a351/crypto/fipsmodule/ecdsa/ecdsa_sign_tests.txt#L550
	pubKeyXP256Hex = "29578c7ab6ce0d11493c95d5ea05d299d536801ca9cbd50e9924e43b733b83ab"
	pubKeyYP256Hex = "08c8049879c6278b2273348474158515accaa38344106ef96803c5a05adc4800"

	// Taken from
	// https://github.com/google/boringssl/blob/59c222fcf123ec2026da450a0a8676436751a351/crypto/fipsmodule/ecdsa/ecdsa_sign_tests.txt#L1630
	pubKeyXP521Hex = "01a7596d38aac7868327ddc1ef5e8178cf052b7ebc512828e8a45955d85bef49494d15278198bbcc5454358c12a2af9a3874e7002e1a2f02fcb36ff3e3b4bc0c69e7"
	pubKeyYP521Hex = "0184902e515982bb225b8c84f245e61b327c08e94d41c07d0b4101a963e02fe52f6a9f33e8b1de2394e0cb74c40790b4e489b5500e6804cabed0fe8c192443d4027b"
)

func getPubKeyPoint(t *testing.T, xHex, yHex string) []byte {
	t.Helper()
	x, err := hex.DecodeString(xHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(%v) err = %v, want nil", xHex, err)
	}
	y, err := hex.DecodeString(yHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(%v) err = %v, want nil", yHex, err)
	}
	// Encoded as an uncompressed octet string as per SEC 1 v2.0, Section 2.3.3
	// (https://www.secg.org/sec1-v2.pdf#page=17.08).
	point := []byte{0x04}
	point = append(point, x...)
	point = append(point, y...)
	return point
}

func TestNewPublicKeyInvalidValues(t *testing.T) {
	validPoint := getPubKeyPoint(t, pubKeyXP256Hex, pubKeyYP256Hex)
	invalidPoint := getPubKeyPoint(t, pubKeyXP256Hex, "0000000000000000000000000000000000000000000000000000000000000000")
	validParams, err := ecdsa.NewParameters(ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantTink)
	if err != nil {
		t.Fatalf("ecdsa.NewParameters(%v, %v, %v, %v) = %v, want nil", ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantTink, err)
	}
	validParamsNoPrefix, err := ecdsa.NewParameters(ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantNoPrefix)
	if err != nil {
		t.Fatalf("ecdsa.NewParameters(%v, %v, %v, %v) = %v, want nil", ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantNoPrefix, err)
	}
	validPointOnAnotherCurve := getPubKeyPoint(t, pubKeyXP521Hex, pubKeyYP521Hex)
	// From
	// https://github.com/google/boringssl/blob/59c222fcf123ec2026da450a0a8676436751a351/crypto/fipsmodule/ecdsa/ecdsa_sign_tests.txt#L10
	X := "605495756e6e88f1d07ae5f98787af9b4da8a641d1a9492a12174eab"
	Y := "f5cc733b17decc806ef1df861a42505d0af9ef7c3df3959b8dfc6669"
	validPointOnP224 := getPubKeyPoint(t, X, Y)
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
	x, y, d   string
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
		x, y, d   string
		curveType ecdsa.CurveType
	}{
		{
			x:         "29578c7ab6ce0d11493c95d5ea05d299d536801ca9cbd50e9924e43b733b83ab",
			y:         "08c8049879c6278b2273348474158515accaa38344106ef96803c5a05adc4800",
			d:         "708309a7449e156b0db70e5b52e606c7e094ed676ce8953bf6c14757c826f590",
			curveType: ecdsa.NistP256,
		},
		{
			x:         "4a92396ff7930b1da9a873a479a28a9896af6cc3d39345b949b726dc3cd978b5",
			y:         "475abb18eaed948879b9c1453e3ef2755dd90f77519ec7b6a30297aad08e4931",
			d:         "90c5386100b137a75b0bb495002b28697a451add2f1f22cb65f735e8aaeace98",
			curveType: ecdsa.NistP256,
		},
		{
			x:         "5775174deb0248112e069cb86f1546ac7a78bc2127d0cb953bad46384dd6be5b",
			y:         "a27020952971cc0b0c3abd06e9ca3e141a4943f560564eba31e5288928bc7ce7",
			d:         "a3a43cece9c1abeff81099fb344d01f7d8df66447b95a667ee368f924bccf870",
			curveType: ecdsa.NistP256,
		},
		{
			d:         "0af857beff08046f23b03c4299eda86490393bde88e4f74348886b200555276b93b37d4f6fdec17c0ea581a30c59c727",
			x:         "00ea9d109dbaa3900461a9236453952b1f1c2a5aa12f6d500ac774acdff84ab7cb71a0f91bcd55aaa57cb8b4fbb3087d",
			y:         "0fc0e3116c9e94be583b02b21b1eb168d8facf3955279360cbcd86e04ee50751054cfaebcf542538ac113d56ccc38b3e",
			curveType: ecdsa.NistP384,
		},
		{
			d:         "047dd5baab23f439ec23b58b7e6ff4cc37813cccb4ea73bb2308e6b82b3170edfe0e131eca50841bf1b686e651c57246",
			x:         "de92ff09af2950854a70f2178d2ed50cc7042a7188301a1ea81d9629ad3c29795cb7f0d56630a401e4d6e5bed0068d1e",
			y:         "6135adbd8624130735e64e65ecbd43770dcc12b28e737b5ed033666f34c918eb5589508e4a13b9243374a118a628dd0b",
			curveType: ecdsa.NistP384,
		},
		{
			d:         "54ba9c740535574cebc41ca5dc950629674ee94730353ac521aafd1c342d3f8ac52046ed804264e1440d7fe409c45c83",
			x:         "3db95ded500b2506b627270bac75688dd7d44f47029adeff99397ab4b6329a38dbb278a0fc58fe4914e6ae31721a6875",
			y:         "049288341553a9ac3dc2d9e18e7a92c43dd3c25ca866f0cb4c68127bef6b0e4ba85713d27d45c7d0dc57e5782a6bf733",
			curveType: ecdsa.NistP384,
		},
		{
			x:         "01a7596d38aac7868327ddc1ef5e8178cf052b7ebc512828e8a45955d85bef49494d15278198bbcc5454358c12a2af9a3874e7002e1a2f02fcb36ff3e3b4bc0c69e7",
			y:         "0184902e515982bb225b8c84f245e61b327c08e94d41c07d0b4101a963e02fe52f6a9f33e8b1de2394e0cb74c40790b4e489b5500e6804cabed0fe8c192443d4027b",
			d:         "01d7bb864c5b5ecae019296cf9b5c63a166f5f1113942819b1933d889a96d12245777a99428f93de4fc9a18d709bf91889d7f8dddd522b4c364aeae13c983e9fae46",
			curveType: ecdsa.NistP521,
		},
		{
			x:         "01a7596d38aac7868327ddc1ef5e8178cf052b7ebc512828e8a45955d85bef49494d15278198bbcc5454358c12a2af9a3874e7002e1a2f02fcb36ff3e3b4bc0c69e7",
			y:         "0184902e515982bb225b8c84f245e61b327c08e94d41c07d0b4101a963e02fe52f6a9f33e8b1de2394e0cb74c40790b4e489b5500e6804cabed0fe8c192443d4027b",
			d:         "01d7bb864c5b5ecae019296cf9b5c63a166f5f1113942819b1933d889a96d12245777a99428f93de4fc9a18d709bf91889d7f8dddd522b4c364aeae13c983e9fae46",
			curveType: ecdsa.NistP521,
		},
		{
			x:         "01a7596d38aac7868327ddc1ef5e8178cf052b7ebc512828e8a45955d85bef49494d15278198bbcc5454358c12a2af9a3874e7002e1a2f02fcb36ff3e3b4bc0c69e7",
			y:         "0184902e515982bb225b8c84f245e61b327c08e94d41c07d0b4101a963e02fe52f6a9f33e8b1de2394e0cb74c40790b4e489b5500e6804cabed0fe8c192443d4027b",
			d:         "01d7bb864c5b5ecae019296cf9b5c63a166f5f1113942819b1933d889a96d12245777a99428f93de4fc9a18d709bf91889d7f8dddd522b4c364aeae13c983e9fae46",
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
								x:         tv.x,
								y:         tv.y,
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
								x:         tv.x,
								y:         tv.y,
								d:         tv.d,
								id:        variantAndID.id,
								hashType:  ecdsa.SHA384,
								curveType: tv.curveType,
								encoding:  encoding,
								variant:   variantAndID.variant,
							})
							tc = append(tc, testCase{
								x:         tv.x,
								y:         tv.y,
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
								x:         tv.x,
								y:         tv.y,
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
			point := getPubKeyPoint(t, tc.x, tc.y)
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
	publicPoint := getPubKeyPoint(t, pubKeyXP256Hex, pubKeyYP256Hex)
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

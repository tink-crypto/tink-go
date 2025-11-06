// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hmac_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac/hmac"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
)

type testVector struct {
	name          string
	keyBytes      []byte
	message       []byte
	hashType      hmac.HashType
	tag           []byte
	variant       hmac.Variant
	idRequirement uint32
	tagSize       uint32
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex string %q: %v", s, err)
	}
	return b
}

func testVectors(t *testing.T) []testVector {
	testVectors := []testVector{}
	for _, tagSize := range []uint32{10, 16} {
		for _, variant := range []struct {
			value         hmac.Variant
			prefix        []byte
			idRequirement uint32
		}{
			{hmac.VariantNoPrefix, nil, 0},
			{hmac.VariantTink, slices.Concat([]byte{cryptofmt.TinkStartByte}, []byte{0x01, 0x02, 0x03, 0x04}), 0x01020304},
			{hmac.VariantCrunchy, slices.Concat([]byte{cryptofmt.LegacyStartByte}, []byte{0x01, 0x02, 0x03, 0x04}), 0x01020304},
		} {
			// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hmac_sha1_test.json#L19
			testVectors = append(testVectors, testVector{
				name:          fmt.Sprintf("EmptyMessage,HashType=%v,Variant=%s,TagSize=%d", hmac.SHA1, variant.value, tagSize),
				keyBytes:      mustHexDecode(t, "06c0dcdc16ff81dce92807fa2c82b44d28ac178a"),
				message:       nil,
				hashType:      hmac.SHA1,
				tag:           slices.Concat(variant.prefix, mustHexDecode(t, "7d91d1b4748077b28911b4509762b6df24365810")[:tagSize]),
				variant:       variant.value,
				idRequirement: variant.idRequirement,
				tagSize:       tagSize,
			})
			// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hmac_sha1_test.json#L28
			testVectors = append(testVectors, testVector{
				name:          fmt.Sprintf("HashType=%v,Variant=%s,TagSize=%d", hmac.SHA1, variant.value, tagSize),
				keyBytes:      mustHexDecode(t, "4cd64efdb76df5a85dce3d347012cad06b0c3db4"),
				message:       mustHexDecode(t, "6c"),
				hashType:      hmac.SHA1,
				tag:           slices.Concat(variant.prefix, mustHexDecode(t, "6d3d37af55c75d872d2da07b9b907ba22ad487d4")[:tagSize]),
				variant:       variant.value,
				idRequirement: variant.idRequirement,
				tagSize:       tagSize,
			})
			// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hmac_sha224_test.json#L19
			testVectors = append(testVectors, testVector{
				name:          fmt.Sprintf("EmptyMessage,HashType=%v,Variant=%s,TagSize=%d", hmac.SHA224, variant.value, tagSize),
				keyBytes:      mustHexDecode(t, "7eef1e40253350eb9307cc6bd8ab8df434bc2faf7095e45b50ffdd64"),
				message:       nil,
				hashType:      hmac.SHA224,
				tag:           slices.Concat(variant.prefix, mustHexDecode(t, "45b466021214d19245506900532f5272f44b5ad9b3d829f0f5c2108c")[:tagSize]),
				variant:       variant.value,
				idRequirement: variant.idRequirement,
				tagSize:       tagSize,
			})
			// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hmac_sha224_test.json#L28
			testVectors = append(testVectors, testVector{
				name:          fmt.Sprintf("HashType=%v,Variant=%s,TagSize=%d", hmac.SHA224, variant.value, tagSize),
				keyBytes:      mustHexDecode(t, "8648ee936c6ebc5ae4bb48c1139a54e3ac5d897beec492dc4d740752"),
				message:       mustHexDecode(t, "2e"),
				hashType:      hmac.SHA224,
				tag:           slices.Concat(variant.prefix, mustHexDecode(t, "5b72e3208679e63f929e6ee19a257d0555f21484c7caac7c9861be43")[:tagSize]),
				variant:       variant.value,
				idRequirement: variant.idRequirement,
				tagSize:       tagSize,
			})
			// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hmac_sha256_test.json#L19
			testVectors = append(testVectors, testVector{
				name:          fmt.Sprintf("EmptyMessage,HashType=%v,Variant=%s,TagSize=%d", hmac.SHA256, variant.value, tagSize),
				keyBytes:      mustHexDecode(t, "1e225cafb90339bba1b24076d4206c3e79c355805d851682bc818baa4f5a7779"),
				message:       nil,
				hashType:      hmac.SHA256,
				tag:           slices.Concat(variant.prefix, mustHexDecode(t, "b175b57d89ea6cb606fb3363f2538abd73a4c00b4a1386905bac809004cf1933")[:tagSize]),
				variant:       variant.value,
				idRequirement: variant.idRequirement,
				tagSize:       tagSize,
			})
			// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hmac_sha256_test.json#L37
			testVectors = append(testVectors, testVector{
				name:          fmt.Sprintf("HashType=%v,Variant=%s,TagSize=%d", hmac.SHA256, variant.value, tagSize),
				keyBytes:      mustHexDecode(t, "85a7cbaae825bb82c9b6f6c5c2af5ac03d1f6daa63d2a93c189948ec41b9ded9"),
				message:       mustHexDecode(t, "a59b"),
				hashType:      hmac.SHA256,
				tag:           slices.Concat(variant.prefix, mustHexDecode(t, "0fe2f13bba2198f6dda1a084be928e304e9cb16a56bc0b7b939a073280244373")[:tagSize]),
				variant:       variant.value,
				idRequirement: variant.idRequirement,
				tagSize:       tagSize,
			})
			// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hmac_sha384_test.json#L19
			testVectors = append(testVectors, testVector{
				name:          fmt.Sprintf("EmptyMessage,HashType=%v,Variant=%s,TagSize=%d", hmac.SHA384, variant.value, tagSize),
				keyBytes:      mustHexDecode(t, "ee8df067857df2300fa71a10c30997178bb3796127b5ece5f2ccc170932be0e78ea9b0a5936c09157e671ce7ec9fc510"),
				message:       nil,
				hashType:      hmac.SHA384,
				tag:           slices.Concat(variant.prefix, mustHexDecode(t, "a655184daf3346ffc6629d493c8442644e4996a2799e42e3306fa6f5b0967b6cf3a6f819bab89bce297d1d1a5907b2d0")[:tagSize]),
				variant:       variant.value,
				idRequirement: variant.idRequirement,
				tagSize:       tagSize,
			})
			// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hmac_sha384_test.json#L28
			testVectors = append(testVectors, testVector{
				name:          fmt.Sprintf("HashType=%v,Variant=%s,TagSize=%d", hmac.SHA384, variant.value, tagSize),
				keyBytes:      mustHexDecode(t, "976696c0dc97182ca771975c3928ff9168ef89cd740cd2292858fd916068a702bc1df7c6cd8ee1f0d25e61d4c514cc5d"),
				message:       mustHexDecode(t, "2b"),
				hashType:      hmac.SHA384,
				tag:           slices.Concat(variant.prefix, mustHexDecode(t, "363e8973fedcf7892013dfae0b7065d61d80b98c635bc09ed860a01473b9bcd0dc550dbf66cf0d601fe9cbf3ae59620d")[:tagSize]),
				variant:       variant.value,
				idRequirement: variant.idRequirement,
				tagSize:       tagSize,
			})
			// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hmac_sha512_test.json#L19
			testVectors = append(testVectors, testVector{
				name:          fmt.Sprintf("EmptyMessage,HashType=%v,Variant=%s,TagSize=%d", hmac.SHA512, variant.value, tagSize),
				keyBytes:      mustHexDecode(t, "5365244bb43f23f18dfc86c09d62db4741138bec1fbddc282d295e0a098eb5c3e37bd6f4cc16d5ce7d77b1d474a1eb4db313cc0c24e48992ac125196549df9a8"),
				message:       nil,
				hashType:      hmac.SHA512,
				tag:           slices.Concat(variant.prefix, mustHexDecode(t, "d0a556bd1afa8df1ebf9e3ee683a8a2450a7c83eba2daf2e2ff2f953f0cd64da216e67134cf55578b205c8a1e241ba1369516a5ef4298b9c1d31e9d59fc04fe4")[:tagSize]),
				variant:       variant.value,
				idRequirement: variant.idRequirement,
				tagSize:       tagSize,
			})
			// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hmac_sha512_test.json#L28
			testVectors = append(testVectors, testVector{
				name:          fmt.Sprintf("HashType=%v,Variant=%s,TagSize=%d", hmac.SHA512, variant.value, tagSize),
				keyBytes:      mustHexDecode(t, "00698977f7102c67b594166919aa99dc3e58c7b6697a6422e238d04d2f57b2c74e4e84f5c4c6b792952df72f1c09244802f0bcf8752efb90e836110703bfa21c"),
				message:       mustHexDecode(t, "01"),
				hashType:      hmac.SHA512,
				tag:           slices.Concat(variant.prefix, mustHexDecode(t, "4d1609cc2c2f1ab5ddc35815ae1b5dc046f226bde17ec37a4c89ec46fbd31af2aeb810b196dffdd11924d3772bef26a7a542e0a1673b76b915d41cbd3df0f6a6")[:tagSize]),
				variant:       variant.value,
				idRequirement: variant.idRequirement,
				tagSize:       tagSize,
			})
		}
		// Legacy,
		prefix := slices.Concat([]byte{cryptofmt.LegacyStartByte}, []byte{0x01, 0x02, 0x03, 0x04})
		testVectors = append(testVectors, testVector{
			name:          fmt.Sprintf("EmptyMessage,HashType=%v,Variant=%s,TagSize=%d", hmac.SHA1, hmac.VariantLegacy, tagSize),
			keyBytes:      mustHexDecode(t, "06c0dcdc16ff81dce92807fa2c82b44d28ac178a"),
			message:       nil,
			hashType:      hmac.SHA1,
			tag:           slices.Concat(prefix, mustHexDecode(t, "175da7db82ce56a87b9943d719d4e38152b0541b")[:tagSize]),
			variant:       hmac.VariantLegacy,
			idRequirement: 0x01020304,
			tagSize:       tagSize,
		})
		testVectors = append(testVectors, testVector{
			name:          fmt.Sprintf("HashType=%v,Variant=%s,TagSize=%d", hmac.SHA1, hmac.VariantLegacy, tagSize),
			keyBytes:      mustHexDecode(t, "552b9c042b7878eaa4faa5f2de90ff9751509c74"),
			message:       mustHexDecode(t, "6c"),
			hashType:      hmac.SHA1,
			tag:           slices.Concat(prefix, mustHexDecode(t, "50e2bb3bee94044324f93dbac0024fe2f185385a")[:tagSize]),
			variant:       hmac.VariantLegacy,
			idRequirement: 0x01020304,
			tagSize:       tagSize,
		})
		testVectors = append(testVectors, testVector{
			name:          fmt.Sprintf("EmptyMessage,HashType=%v,Variant=%s,TagSize=%d", hmac.SHA224, hmac.VariantLegacy, tagSize),
			keyBytes:      mustHexDecode(t, "7eef1e40253350eb9307cc6bd8ab8df434bc2faf7095e45b50ffdd64"),
			message:       nil,
			hashType:      hmac.SHA224,
			tag:           slices.Concat(prefix, mustHexDecode(t, "8ecf6a239e06f1a1232c2c43d7efbaeaaf6500e55cced879f4866cf7")[:tagSize]),
			variant:       hmac.VariantLegacy,
			idRequirement: 0x01020304,
			tagSize:       tagSize,
		})
		testVectors = append(testVectors, testVector{
			name:          fmt.Sprintf("HashType=%v,Variant=%s,TagSize=%d", hmac.SHA224, hmac.VariantLegacy, tagSize),
			keyBytes:      mustHexDecode(t, "8648ee936c6ebc5ae4bb48c1139a54e3ac5d897beec492dc4d740752"),
			message:       mustHexDecode(t, "2e"),
			hashType:      hmac.SHA224,
			tag:           slices.Concat(prefix, mustHexDecode(t, "0189e519f229953d8a558d460c4835dc2af91bd8b7b85fa5badbd559")[:tagSize]),
			variant:       hmac.VariantLegacy,
			idRequirement: 0x01020304,
			tagSize:       tagSize,
		})
		testVectors = append(testVectors, testVector{
			name:          fmt.Sprintf("EmptyMessage,HashType=%v,Variant=%s,TagSize=%d", hmac.SHA256, hmac.VariantLegacy, tagSize),
			keyBytes:      mustHexDecode(t, "1e225cafb90339bba1b24076d4206c3e79c355805d851682bc818baa4f5a7779"),
			message:       nil,
			hashType:      hmac.SHA256,
			tag:           slices.Concat(prefix, mustHexDecode(t, "e21bcdafb37f133b64087bef354d4e6ae96e4ca7760c185a07550f4bde18bded")[:tagSize]),
			variant:       hmac.VariantLegacy,
			idRequirement: 0x01020304,
			tagSize:       tagSize,
		})
		testVectors = append(testVectors, testVector{
			name:          fmt.Sprintf("HashType=%v,Variant=%s,TagSize=%d", hmac.SHA256, hmac.VariantLegacy, tagSize),
			keyBytes:      mustHexDecode(t, "85a7cbaae825bb82c9b6f6c5c2af5ac03d1f6daa63d2a93c189948ec41b9ded9"),
			message:       mustHexDecode(t, "a59b"),
			hashType:      hmac.SHA256,
			tag:           slices.Concat(prefix, mustHexDecode(t, "1de772af9be71f27294f07a281c5d2f69e179eeaa00c12419b69f4ad8492a67e")[:tagSize]),
			variant:       hmac.VariantLegacy,
			idRequirement: 0x01020304,
			tagSize:       tagSize,
		})
		testVectors = append(testVectors, testVector{
			name:          fmt.Sprintf("EmptyMessage,HashType=%v,Variant=%s,TagSize=%d", hmac.SHA384, hmac.VariantLegacy, tagSize),
			keyBytes:      mustHexDecode(t, "ee8df067857df2300fa71a10c30997178bb3796127b5ece5f2ccc170932be0e78ea9b0a5936c09157e671ce7ec9fc510"),
			message:       nil,
			hashType:      hmac.SHA384,
			tag:           slices.Concat(prefix, mustHexDecode(t, "e5d2b1fff7dc207e3b15ee2b4244eaf20e0141596566459b1edd7b766e00480ff29e9d33bafa12c204c1a4ebec826643")[:tagSize]),
			variant:       hmac.VariantLegacy,
			idRequirement: 0x01020304,
			tagSize:       tagSize,
		})
		testVectors = append(testVectors, testVector{
			name:          fmt.Sprintf("HashType=%v,Variant=%s,TagSize=%d", hmac.SHA384, hmac.VariantLegacy, tagSize),
			keyBytes:      mustHexDecode(t, "976696c0dc97182ca771975c3928ff9168ef89cd740cd2292858fd916068a702bc1df7c6cd8ee1f0d25e61d4c514cc5d"),
			message:       mustHexDecode(t, "2b"),
			hashType:      hmac.SHA384,
			tag:           slices.Concat(prefix, mustHexDecode(t, "04d1cfadc21c6e807cc38d0695c58e3ea5086822a552cab6e4d43f75539dc79f2edbc48460334bdab358a12c99e27073")[:tagSize]),
			variant:       hmac.VariantLegacy,
			idRequirement: 0x01020304,
			tagSize:       tagSize,
		})
		testVectors = append(testVectors, testVector{
			name:          fmt.Sprintf("EmptyMessage,HashType=%v,Variant=%s,TagSize=%d", hmac.SHA512, hmac.VariantLegacy, tagSize),
			keyBytes:      mustHexDecode(t, "5365244bb43f23f18dfc86c09d62db4741138bec1fbddc282d295e0a098eb5c3e37bd6f4cc16d5ce7d77b1d474a1eb4db313cc0c24e48992ac125196549df9a8"),
			message:       nil,
			hashType:      hmac.SHA512,
			tag:           slices.Concat(prefix, mustHexDecode(t, "8489187538dbc6516e13720e643a28a7d8427a3b09486ea7f041c72d28974f103d058fc1817939be71b73d8796fabdd4aa96430d43c8fbeaa3b5312e8fc4ad92")[:tagSize]),
			variant:       hmac.VariantLegacy,
			idRequirement: 0x01020304,
			tagSize:       tagSize,
		})
		testVectors = append(testVectors, testVector{
			name:          fmt.Sprintf("HashType=%v,Variant=%s,TagSize=%d", hmac.SHA512, hmac.VariantLegacy, tagSize),
			keyBytes:      mustHexDecode(t, "00698977f7102c67b594166919aa99dc3e58c7b6697a6422e238d04d2f57b2c74e4e84f5c4c6b792952df72f1c09244802f0bcf8752efb90e836110703bfa21c"),
			message:       mustHexDecode(t, "01"),
			hashType:      hmac.SHA512,
			tag:           slices.Concat(prefix, mustHexDecode(t, "e047d6bc61b4c0e62490b62fb1a29461f2afdd675ab9e316013c332c844f2f32a68af66e0bc0663815d5d3bd1a01881150510a8d4333d153eb20d7593ec24e6b")[:tagSize]),
			variant:       hmac.VariantLegacy,
			idRequirement: 0x01020304,
			tagSize:       tagSize,
		})
	}
	return testVectors
}

func TestMACTestVectors(t *testing.T) {
	for _, tc := range testVectors(t) {
		t.Run(tc.name, func(t *testing.T) {
			opts := hmac.ParametersOpts{
				KeySizeInBytes: len(tc.keyBytes),
				TagSizeInBytes: int(tc.tagSize),
				HashType:       tc.hashType,
				Variant:        tc.variant,
			}
			params, err := hmac.NewParameters(opts)
			if err != nil {
				t.Fatalf("hmac.NewParameters(%v) err = %v, want nil", opts, err)
			}
			key, err := hmac.NewKey(secretdata.NewBytesFromData(tc.keyBytes, testonlyinsecuresecretdataaccess.Token()), params, tc.idRequirement)
			if err != nil {
				t.Fatalf("hmac.NewKey(%v, %v, %v) err = %v, want nil", tc.keyBytes, params, tc.idRequirement, err)
			}
			mac, err := hmac.NewMAC(key, internalapi.Token{})
			if err != nil {
				t.Fatalf("hmac.NewMAC(%v, %v) err = %v, want nil", key, internalapi.Token{}, err)
			}
			tag, err := mac.ComputeMAC(tc.message)
			if err != nil {
				t.Fatalf("mac.ComputeMAC(%v) err = %v, want nil", tc.message, err)
			}
			if !bytes.Equal(tag, tc.tag) {
				t.Errorf("mac.ComputeMAC(%v) = %x, want %x", tc.message, tag, tc.tag)
			}
			if err := mac.VerifyMAC(tag, tc.message); err != nil {
				t.Errorf("mac.VerifyMAC(%v, %v) err = %v, want nil", tag, tc.message, err)
			}
		})
	}
}

func TestMACFromPublicAPITestVectors(t *testing.T) {
	for _, tc := range testVectors(t) {
		t.Run(tc.name, func(t *testing.T) {
			params, err := hmac.NewParameters(hmac.ParametersOpts{
				KeySizeInBytes: len(tc.keyBytes),
				TagSizeInBytes: int(tc.tagSize),
				HashType:       tc.hashType,
				Variant:        tc.variant,
			})
			if err != nil {
				t.Fatalf("hmac.NewParameters(%v, %v) err = %v, want nil", tc.variant, 16, err)
			}
			key, err := hmac.NewKey(secretdata.NewBytesFromData(tc.keyBytes, testonlyinsecuresecretdataaccess.Token()), params, tc.idRequirement)
			if err != nil {
				t.Fatalf("hmac.NewKey(%v, %v, %v) err = %v, want nil", tc.keyBytes, params, tc.idRequirement, err)
			}
			km := keyset.NewManager()
			id, err := km.AddKey(key)
			if err != nil {
				t.Fatalf("km.AddKey(%v) err = %v, want nil", key, err)
			}
			if err := km.SetPrimary(id); err != nil {
				t.Fatalf("km.SetPrimary(%v) err = %v, want nil", id, err)
			}
			handle, err := km.Handle()
			if err != nil {
				t.Fatalf("km.Handle() err = %v, want nil", err)
			}
			mac, err := mac.New(handle)
			if err != nil {
				t.Fatalf("mac.New(handle) err = %v, want nil", err)
			}
			tag, err := mac.ComputeMAC(tc.message)
			if err != nil {
				t.Fatalf("mac.ComputeMAC(%v) err = %v, want nil", tc.message, err)
			}
			if !bytes.Equal(tag, tc.tag) {
				t.Errorf("mac.ComputeMAC(%v) = %v, want %v", tc.message, tag, tc.tag)
			}
			if err := mac.VerifyMAC(tag, tc.message); err != nil {
				t.Errorf("mac.VerifyMAC(%v, %v) err = %v, want nil", tag, tc.message, err)
			}
		})
	}
}

func TestDecryptFailsWithInvalidInputs(t *testing.T) {
	for _, variant := range []hmac.Variant{
		hmac.VariantNoPrefix,
		hmac.VariantTink,
		hmac.VariantCrunchy,
		hmac.VariantLegacy,
	} {
		t.Run(variant.String(), func(t *testing.T) {
			params, err := hmac.NewParameters(hmac.ParametersOpts{
				KeySizeInBytes: 32,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        variant,
			})
			if err != nil {
				t.Fatalf("hmac.NewParameters() err = %v, want nil", err)
			}
			keyBytes := secretdata.NewBytesFromData([]byte("01010101010101010101010101010101"), testonlyinsecuresecretdataaccess.Token())
			key, err := hmac.NewKey(keyBytes, params, 0)
			if err != nil {
				t.Fatalf("hmac.NewKey() err = %v, want nil", err)
			}
			m, err := hmac.NewMAC(key, internalapi.Token{})
			if err != nil {
				t.Fatalf("hmac.NewMAC(%v, %v) err = %v, want nil", key, internalapi.Token{}, err)
			}

			message := []byte("Some data to sign.")
			tag, err := m.ComputeMAC(message)
			if err != nil {
				t.Fatalf("m.ComputeMAC(message) err = %v, want nil", err)
			}

			prefix := tag[:len(key.OutputPrefix())]
			rawTag := tag[len(prefix):]

			// Invalid prefix.
			if len(prefix) > 0 {
				wrongPrefix := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
				if err := m.VerifyMAC(slices.Concat(wrongPrefix, rawTag), message); err == nil {
					t.Errorf("m.VerifyMAC() err = nil, want error")
				}
			}

			// Corrupted tag.
			wrongTag := bytes.Clone(rawTag)
			wrongTag[0] ^= 1
			if err := m.VerifyMAC(slices.Concat(prefix, wrongTag), message); err == nil {
				t.Errorf("m.VerifyMAC() err = nil, want error")
			}

			// Truncated tag.
			for i := 1; i < len(tag); i++ {
				if err := m.VerifyMAC(tag[:i], message); err == nil {
					t.Errorf("m.VerifyMAC(tag[:%d], message) err = nil, want error", i)
				}
			}

			// Invalid message.
			if err := m.VerifyMAC(tag, []byte("invalid")); err == nil {
				t.Errorf("m.VerifyMAC() err = nil, want error")
			}
		})
	}
}

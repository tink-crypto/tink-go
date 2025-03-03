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

package ecies_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/aead/aesctrhmac"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/daead/aessiv"
	"github.com/tink-crypto/tink-go/v2/hybrid/ecies"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
)

type hybridEncryptTestVector struct {
	name        string
	privateKey  *ecies.PrivateKey
	plaintext   []byte
	contextInfo []byte
	ciphertext  []byte
}

// hybridTestVectors creates test vectors for ECIES.
//
// This are the same as
// https://github.com/tink-crypto/tink-cc/blob/0af209005edb9cd63edd2bd4c70e78b78613acc5/tink/hybrid/internal/testing/ecies_aead_hkdf_test_vectors.cc.
func hybridTestVectors(t *testing.T) []hybridEncryptTestVector {
	t.Helper()
	aes128GCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	aes256GCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	aes128CtrHMACSHA256Params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		AESKeySizeInBytes:  16,
		HMACKeySizeInBytes: 32,
		IVSizeInBytes:      16,
		HashType:           aesctrhmac.SHA256,
		TagSizeInBytes:     16,
		Variant:            aesctrhmac.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
	}
	aes256CtrHMACSHA256Params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		AESKeySizeInBytes:  32,
		HMACKeySizeInBytes: 32,
		IVSizeInBytes:      16,
		HashType:           aesctrhmac.SHA256,
		TagSizeInBytes:     32,
		Variant:            aesctrhmac.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
	}
	aes256SIVParams, err := aessiv.NewParameters(64, aessiv.VariantNoPrefix)
	if err != nil {
		t.Fatalf("aessiv.NewParameters() err = %v, want nil", err)
	}

	return []hybridEncryptTestVector{
		hybridEncryptTestVector{
			name: "RAW_NIST_P256_SHA256_AES128GCM_NO_SALT_UNCOMPRESSED",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 0,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantNoPrefix,
				})),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "04207f1c9bd3bce6864bdbb611bdb9852dea7e12dbe5894c642bd5cc8cde79de9e8a"+
				"e3199875eba161d413ce3a29cfa0b27c6717d7d4cfbace5706ae4bbf8f7d1eb76965"+
				"7992f5e7f5450091cc61c7b3a7b811fe5578e82e5123cb38855c"),
		},
		hybridEncryptTestVector{
			name: "RAW_NIST_P256_SHA256_AES128GCM_NO_SALT_COMPRESSED",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 0,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.CompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantNoPrefix,
				})),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "02f1885dcb9240136f3305a18ac3857dd5de948cb0c4c78dbb087d37815800936340"+
				"e2c351380bb615b26fd7d78c9c864f4a0e31863e864140f1f7e1205b"),
		},
		hybridEncryptTestVector{
			name: "RAW_NIST_P256_SHA256_AES256GCM_NO_SALT_COMPRESSED",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 0,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.CompressedPointFormat,
					DEMParameters:        aes256GCMParams,
					Variant:              ecies.VariantNoPrefix,
				})),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "029f1ad546b1b60a0cff3cc356977ab608f5c4c17b693d2778d1e3354ec43500ea65"+
				"bb5cce0fdc55e1fd0b9b07ee1ac642f7dcb5abd94b6b42691cd8e206"),
		},
		hybridEncryptTestVector{
			name: "RAW_NIST_P256_SHA256_AES128CTRHMACSHA256_NO_SALT_COMPRESSED",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 0,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.CompressedPointFormat,
					DEMParameters:        aes128CtrHMACSHA256Params,
					Variant:              ecies.VariantNoPrefix,
				})),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "029f86d6f944e163d1b787a261caa65e47f7c59368170b5e8da0e7a14a4ce1bfab8e"+
				"6c2e283562a2bc52fb5145ec0a4737ecfe52f725e1c70df17a02dfdda7e6188b"),
		},
		hybridEncryptTestVector{
			name: "RAW_NIST_P256_SHA256_AES256CTRHMACSHA256_NO_SALT_UNCOMPRESSED",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 0,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes256CtrHMACSHA256Params,
					Variant:              ecies.VariantNoPrefix,
				})),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "043e59fd951974bfe1b2c7a33d4bf89aa3b461e3aedcf44928eda6744f9880fb893b"+
				"66899217736dd6db73"+
				"763ba540469ff0d240a95bbd05b7716932082983883db5cba086eebbcc6fe0757644"+
				"fb0c612fff2c"+
				"a86dc9077e7089ddf107492251413d99a679b86d4d07c0a70d1a6329f6da6f"),
		},
		hybridEncryptTestVector{
			name: "RAW_NIST_P256_SHA256_AES256SIV_NO_SALT_UNCOMPRESSED",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 0,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes256SIVParams,
					Variant:              ecies.VariantNoPrefix,
				})),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "0425975e19677c2110915beb293e3833cd40c9beeff376b83b8cf01aa"+
				"8282a1416b3b8deffd34b7c33044848a3ba8a722d60946757ae29ee31"+
				"7ceefae84890325ca1a246d24696a3f5acd351690763212961"),
		},
		hybridEncryptTestVector{
			name: "TINK_NIST_P256_SHA256_AES128GCM_NO_SALT_UNCOMPRESSED",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 0x88668866,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantTink,
				})),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "0188668866"+
				"04207f1c9bd3bce6864bdbb611bdb9852dea7e12dbe5894c642bd5cc8cde79de9e8a"+
				"e3199875eba161d413ce3a29cfa0b27c6717d7d4cfbace5706ae4bbf8f7d1eb76965"+
				"7992f5e7f5450091cc61c7b3a7b811fe5578e82e5123cb38855c"),
		},
		hybridEncryptTestVector{
			name: "CRUNCHY_NIST_P256_SHA256_AES128GCM_NO_SALT_UNCOMPRESSED",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 0x88668866,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantCrunchy,
				})),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "0088668866"+
				"04207f1c9bd3bce6864bdbb611bdb9852dea7e12dbe5894c642bd5cc8cde79de9e8a"+
				"e3199875eba161d413ce3a29cfa0b27c6717d7d4cfbace5706ae4bbf8f7d1eb76965"+
				"7992f5e7f5450091cc61c7b3a7b811fe5578e82e5123cb38855c"),
		},
		hybridEncryptTestVector{
			name: "RAW_NIST_P256_SHA384_AES128GCM_NO_SALT_UNCOMPRESSED",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 0,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA384,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantNoPrefix,
				})),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "0484b996da02ef1e0169f220cfec0c1f0bb259d245b0131e2826619ffc19886d9208"+
				"76e7444976ca8ec6fa3bd0301680e7d91ecc09196b2b2079db8f00f1775ca2d2f633"+
				"41cd6eadffd4332af8f4c2c91acb8872a7f22342a8e6dff119d0"),
		},
		hybridEncryptTestVector{
			name: "RAW_NIST_P256_SHA512_AES128GCM_NO_SALT_UNCOMPRESSED",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 0,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA512,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantNoPrefix,
				})),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "044668af1e50e4a24bb30fb763788f2c7151c33aa30542843b8699519ff3b9cf78a8"+
				"421466249330ee955220591444f0eb2f910cf530f9cea17e277c393c0796de08184b"+
				"6d90cc229efc70f6748c4ff26abc572b08ddffabab04a307e194"),
		},
		hybridEncryptTestVector{
			name: "RAW_NIST_P256_SHA256_AES128GCM_NO_SALT_UNCOMPRESSED_EMPTY_MESSAGE",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 0,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantNoPrefix,
				})),
			plaintext:   []byte{},
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "0471855fecd89b62ae67a4d62be5fe31f5368e271b3b1775362161eab5701ab6fb21"+
				"048c406a31ffa2dde42bd68b88a20daf9cf3873a2fde4e745d404dd1dcab21ee0e05"+
				"a32e919c1bcbecd7fb18c6b8fe7f91ea9c7e0abba5855dd0a2"),
		},
		hybridEncryptTestVector{
			name: "RAW_NIST_P256_SHA256_AES128GCM_NO_SALT_UNCOMPRESSED_EMPTY_CONTEXT_INFO",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 0,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantNoPrefix,
				})),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: []byte{},
			ciphertext: mustHexDecode(t, "045c1ef99f7c3a2c9ea0022bcd8c87e9b90d3dec4687a3e94a006c01136d7b50c0db"+
				"443b67ed69d432bc949b7ba76859343577fe702437ebb105e18abdaf6d3f88fb1b12"+
				"ed80d0182e1f6ac5da5cb08cec330c861c897e34603a6b83de71"),
		},
		hybridEncryptTestVector{
			name: "RAW_NIST_P384_SHA256_AES128GCM_NO_SALT_UNCOMPRESSED",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "670dc60402d8a4fe52f4e552d2b71f0f81bcf195d8a71a6c7d84efb4f"+
				"0e4b4a5d0f60a27c94caac46bdeeb79897a3ed9"), 0,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP384,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantNoPrefix,
				})),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "04ff21e8d24773b1deaeb120aba62c2f19d0eb6112c3296d25be9302e0f31788db20"+
				"2e87ef1341f9fa05a2ac9b21ced6b0ef19407618ae6e2d86764f6a5ea582aec7cd69"+
				"07bebb9261b55eb4ba588dede42ec613992bd143c703b6af20cd927a501536191ec5"+
				"2e13326252968c3fcb2af021f25fcfd7d5993c180dfd916d"),
		},
		hybridEncryptTestVector{
			name: "RAW_NIST_P521_SHA256_AES128GCM_NO_SALT_UNCOMPRESSED",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C"+
				"AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83"+
				"538"), 0,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP521,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantNoPrefix,
				})),
			plaintext:   mustHexDecode(t, "01"),
			contextInfo: mustHexDecode(t, "02"),
			ciphertext: mustHexDecode(t, "0401a1051bd9ceedf066f31edea3465cf5170c72102c325b85e30ae2f80155ca7af0"+
				"abb8c8367b63dea022ebdf4d87f923bd02f9dc0d39b6e2facbef079b4737c392ad00"+
				"32b7beb0ccb56e160682b722c54b4bd7f288d66b3f25f856304c35cbf2368610d8fb"+
				"e3f83890c007c6ca5d2f5f32d1ef4445372751b1bc0e7104879b8c2e1e60f1c8862c"+
				"566d2b0718aed41bb763cb29e3e2ca1df63e46f859fa98478ea9"),
		},
	}
}

func TestNewHybridEncryptAndDecryptFailsIfX25519(t *testing.T) {
	aes128GCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	privateKey := mustCreatePrivateKey(t, mustHexDecode(t, "97d2e385c9968fbe2dc0b85a182199ed7e0b5b4bb6060f76583c0893241f698d"), 0,
		mustCreateParameters(t, ecies.ParametersOpts{
			CurveType:            ecies.X25519,
			HashType:             ecies.SHA256,
			DEMParameters:        aes128GCMParams,
			NISTCurvePointFormat: ecies.UnspecifiedPointFormat,
			Variant:              ecies.VariantNoPrefix,
		}))

	publicKey, err := privateKey.PublicKey()
	if err != nil {
		t.Fatalf("privateKey.PublicKey() err = %v, want nil", err)
	}
	if _, err := ecies.NewHybridEncrypt(publicKey.(*ecies.PublicKey), internalapi.Token{}); err == nil {
		t.Errorf("ecies.NewHybridEncrypt() err = nil, want error")
	}
	if _, err := ecies.NewHybridDecrypt(privateKey, internalapi.Token{}); err == nil {
		t.Errorf("ecies.NewHybridDecrypt() err = nil, want error")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	for _, tc := range hybridTestVectors(t) {
		t.Run(tc.name, func(t *testing.T) {
			publicKey, err := tc.privateKey.PublicKey()
			if err != nil {
				t.Fatalf("tc.privateKey.PublicKey() err = %v, want nil", err)
			}
			encrypter, err := ecies.NewHybridEncrypt(publicKey.(*ecies.PublicKey), internalapi.Token{})
			if err != nil {
				t.Fatalf("ecies.NewHybridEncrypt() err = %v, want nil", err)
			}
			decrypter, err := ecies.NewHybridDecrypt(tc.privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("ecies.NewHybridDecrypt() err = %v, want nil", err)
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

func mustEncrypt(t *testing.T, publicKey *ecies.PublicKey, plaintext, contextInfo []byte) []byte {
	t.Helper()
	encrypter, err := ecies.NewHybridEncrypt(publicKey, internalapi.Token{})
	if err != nil {
		t.Fatalf("ecies.NewHybridEncrypt() err = %v, want nil", err)
	}
	ciphertext, err := encrypter.Encrypt(plaintext, contextInfo)
	if err != nil {
		t.Fatalf("encrypter.Encrypt() err = %v, want nil", err)
	}
	return ciphertext
}

func TestDecryptFails(t *testing.T) {
	aes128GCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	data := []byte("plaintext")
	contextInfo := []byte("context")
	for _, tc := range []struct {
		name       string
		publicKey  *ecies.PublicKey
		privateKey *ecies.PrivateKey
		ciphertext []byte
	}{
		{
			name: "different prefix type",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 123,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantTink,
				})),
			ciphertext: mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantCrunchy,
				})), data, contextInfo),
		},
		{
			name: "missing prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 123,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantTink,
				})),
			ciphertext: mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 0,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantNoPrefix,
				})), data, contextInfo),
		},
		{
			name: "different key ID",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 123,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantTink,
				})),
			ciphertext: mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 456,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantTink,
				})), data, contextInfo),
		},
		{
			name: "different ciphertext encoding",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 123,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantTink,
				})),
			ciphertext: mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.CompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantTink,
				})), data, contextInfo),
		},
		{
			name: "invalid ciphertext",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 123,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantTink,
				})),
			ciphertext: func() []byte {
				ciphertext := mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123,
					mustCreateParameters(t, ecies.ParametersOpts{
						CurveType:            ecies.NISTP256,
						HashType:             ecies.SHA256,
						NISTCurvePointFormat: ecies.UncompressedPointFormat,
						DEMParameters:        aes128GCMParams,
						Variant:              ecies.VariantTink,
					})), data, contextInfo)
				ciphertext[5] ^= 1
				return ciphertext
			}(),
		},
		{
			name: "invalid prefix",
			privateKey: mustCreatePrivateKey(t, mustHexDecode(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"), 123,
				mustCreateParameters(t, ecies.ParametersOpts{
					CurveType:            ecies.NISTP256,
					HashType:             ecies.SHA256,
					NISTCurvePointFormat: ecies.UncompressedPointFormat,
					DEMParameters:        aes128GCMParams,
					Variant:              ecies.VariantTink,
				})),
			ciphertext: func() []byte {
				ciphertext := mustEncrypt(t, mustCreatePublicKey(t, mustHexDecode(t, "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), 123,
					mustCreateParameters(t, ecies.ParametersOpts{
						CurveType:            ecies.NISTP256,
						HashType:             ecies.SHA256,
						NISTCurvePointFormat: ecies.UncompressedPointFormat,
						DEMParameters:        aes128GCMParams,
						Variant:              ecies.VariantTink,
					})), data, contextInfo)
				ciphertext[0] ^= 1
				return ciphertext
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decrypter, err := ecies.NewHybridDecrypt(tc.privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("ecies.NewHybridDecrypt(%v) err = %v, want nil", tc.publicKey, err)
			}
			if _, err := decrypter.Decrypt(tc.ciphertext, contextInfo); err == nil {
				t.Errorf("decrypter.Decrypt(%v, %v) err = nil, want error", tc.ciphertext, contextInfo)
			}
		})
	}

}

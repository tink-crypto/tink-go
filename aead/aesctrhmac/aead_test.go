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

package aesctrhmac_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesctrhmac"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func createAEAD(encryptionKey []byte, ivSize int, hashType aesctrhmac.HashType, macKey []byte, tagSize int, variant aesctrhmac.Variant, idRequirement uint32) (tink.AEAD, error) {
	opts := aesctrhmac.ParametersOpts{
		AESKeySizeInBytes:  len(encryptionKey),
		HMACKeySizeInBytes: len(macKey),
		IVSizeInBytes:      ivSize,
		TagSizeInBytes:     tagSize,
		HashType:           hashType,
		Variant:            variant,
	}
	params, err := aesctrhmac.NewParameters(opts)
	if err != nil {
		return nil, err
	}
	key, err := aesctrhmac.NewKey(aesctrhmac.KeyOpts{
		AESKeyBytes:   secretdata.NewBytesFromData(encryptionKey, insecuresecretdataaccess.Token{}),
		HMACKeyBytes:  secretdata.NewBytesFromData(macKey, insecuresecretdataaccess.Token{}),
		IDRequirement: idRequirement,
		Parameters:    params,
	})
	if err != nil {
		return nil, err
	}
	km := keyset.NewManager()
	keyID, err := km.AddKey(key)
	if err != nil {
		return nil, err
	}
	if err := km.SetPrimary(keyID); err != nil {
		return nil, err
	}
	h, err := km.Handle()
	if err != nil {
		return nil, err
	}
	a, err := aead.New(h)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Copied from
// https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.
//
// We use CTR but the RFC uses CBC mode, so it's not possible to compare
// plaintexts. However, the tests are still valuable to ensure that we
// correctly compute HMAC over ciphertext and associatedData.
var rfcTestVectors = []struct {
	macKey         string
	encryptionKey  string
	ciphertext     string
	associatedData string
	hashAlgo       aesctrhmac.HashType
	ivSize         int
	tagSize        int
}{
	{
		macKey:        "000102030405060708090a0b0c0d0e0f",
		encryptionKey: "101112131415161718191a1b1c1d1e1f",
		ciphertext: "" +
			"1af38c2dc2b96ffdd86694092341bc04" +
			"c80edfa32ddf39d5ef00c0b468834279" +
			"a2e46a1b8049f792f76bfe54b903a9c9" +
			"a94ac9b47ad2655c5f10f9aef71427e2" +
			"fc6f9b3f399a221489f16362c7032336" +
			"09d45ac69864e3321cf82935ac4096c8" +
			"6e133314c54019e8ca7980dfa4b9cf1b" +
			"384c486f3a54c51078158ee5d79de59f" +
			"bd34d848b3d69550a67646344427ade5" +
			"4b8851ffb598f7f80074b9473c82e2db" +
			"652c3fa36b0a7c5b3219fab3a30bc1c4",
		associatedData: "" +
			"546865207365636f6e64207072696e63" +
			"69706c65206f66204175677573746520" +
			"4b6572636b686f666673",
		hashAlgo: aesctrhmac.SHA256,
		ivSize:   16,
		tagSize:  16,
	},
	{
		macKey:        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		encryptionKey: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		ciphertext: "" +
			"1af38c2dc2b96ffdd86694092341bc04" +
			"4affaaadb78c31c5da4b1b590d10ffbd" +
			"3dd8d5d302423526912da037ecbcc7bd" +
			"822c301dd67c373bccb584ad3e9279c2" +
			"e6d12a1374b77f077553df829410446b" +
			"36ebd97066296ae6427ea75c2e0846a1" +
			"1a09ccf5370dc80bfecbad28c73f09b3" +
			"a3b75e662a2594410ae496b2e2e6609e" +
			"31e6e02cc837f053d21f37ff4f51950b" +
			"be2638d09dd7a4930930806d0703b1f6" +
			"4dd3b4c088a7f45c216839645b2012bf" +
			"2e6269a8c56a816dbc1b267761955bc5",
		associatedData: "" +
			"546865207365636f6e64207072696e63" +
			"69706c65206f66204175677573746520" +
			"4b6572636b686f666673",
		hashAlgo: aesctrhmac.SHA512,
		ivSize:   16,
		tagSize:  32,
	},
}

func mustDecodeHex(t *testing.T, data string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestAEADRFCTestVectors(t *testing.T) {
	for _, tc := range []struct {
		name           string
		macKey         string
		encryptionKey  string
		ciphertext     string
		associatedData string
		hashAlgo       aesctrhmac.HashType
		ivSize         int
		tagSize        int
		idRequirement  uint32
		variant        aesctrhmac.Variant
	}{
		{
			name:           "SHA256-NoPrefix",
			macKey:         rfcTestVectors[0].macKey,
			encryptionKey:  rfcTestVectors[0].encryptionKey,
			ciphertext:     rfcTestVectors[0].ciphertext,
			associatedData: rfcTestVectors[0].associatedData,
			hashAlgo:       rfcTestVectors[0].hashAlgo,
			ivSize:         rfcTestVectors[0].ivSize,
			tagSize:        rfcTestVectors[0].tagSize,
			variant:        aesctrhmac.VariantNoPrefix,
			idRequirement:  0,
		},
		{
			name:           "SHA512-NoPrefix",
			macKey:         rfcTestVectors[1].macKey,
			encryptionKey:  rfcTestVectors[1].encryptionKey,
			ciphertext:     rfcTestVectors[1].ciphertext,
			associatedData: rfcTestVectors[1].associatedData,
			hashAlgo:       rfcTestVectors[1].hashAlgo,
			ivSize:         rfcTestVectors[1].ivSize,
			tagSize:        rfcTestVectors[1].tagSize,
			variant:        aesctrhmac.VariantNoPrefix,
			idRequirement:  0,
		},
		{
			name:           "SHA256-Tink",
			macKey:         rfcTestVectors[0].macKey,
			encryptionKey:  rfcTestVectors[0].encryptionKey,
			ciphertext:     "0111223344" + rfcTestVectors[0].ciphertext,
			associatedData: rfcTestVectors[0].associatedData,
			hashAlgo:       rfcTestVectors[0].hashAlgo,
			ivSize:         rfcTestVectors[0].ivSize,
			tagSize:        rfcTestVectors[0].tagSize,
			variant:        aesctrhmac.VariantTink,
			idRequirement:  0x11223344,
		},
		{
			name:           "SHA512-Tink",
			macKey:         rfcTestVectors[1].macKey,
			encryptionKey:  rfcTestVectors[1].encryptionKey,
			ciphertext:     "0111223344" + rfcTestVectors[1].ciphertext,
			associatedData: rfcTestVectors[1].associatedData,
			hashAlgo:       rfcTestVectors[1].hashAlgo,
			ivSize:         rfcTestVectors[1].ivSize,
			tagSize:        rfcTestVectors[1].tagSize,
			variant:        aesctrhmac.VariantTink,
			idRequirement:  0x11223344,
		},
		{
			name:           "SHA256-Crunchy",
			macKey:         rfcTestVectors[0].macKey,
			encryptionKey:  rfcTestVectors[0].encryptionKey,
			ciphertext:     "0011223344" + rfcTestVectors[0].ciphertext,
			associatedData: rfcTestVectors[0].associatedData,
			hashAlgo:       rfcTestVectors[0].hashAlgo,
			ivSize:         rfcTestVectors[0].ivSize,
			tagSize:        rfcTestVectors[0].tagSize,
			variant:        aesctrhmac.VariantCrunchy,
			idRequirement:  0x11223344,
		},
		{
			name:           "SHA512-Crunchy",
			macKey:         rfcTestVectors[1].macKey,
			encryptionKey:  rfcTestVectors[1].encryptionKey,
			ciphertext:     "0011223344" + rfcTestVectors[1].ciphertext,
			associatedData: rfcTestVectors[1].associatedData,
			hashAlgo:       rfcTestVectors[1].hashAlgo,
			ivSize:         rfcTestVectors[1].ivSize,
			tagSize:        rfcTestVectors[1].tagSize,
			variant:        aesctrhmac.VariantCrunchy,
			idRequirement:  0x11223344,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			macKey := mustDecodeHex(t, tc.macKey)
			encryptionKey := mustDecodeHex(t, tc.encryptionKey)
			ciphertext := mustDecodeHex(t, tc.ciphertext)
			associatedData := mustDecodeHex(t, tc.associatedData)
			a, err := createAEAD(encryptionKey, tc.ivSize, tc.hashAlgo, macKey, tc.tagSize, tc.variant, tc.idRequirement)
			if err != nil {
				t.Fatalf("failed to create AEAD from RFC test vector: %v %v", tc, err)
			}
			if _, err := a.Decrypt(ciphertext, associatedData); err != nil {
				t.Errorf("decryption failed to RFC test vector: %v, error: %v", tc, err)
			}
		})
	}
}

func TestAEADEncryptDecrypt(t *testing.T) {
	const ivSize = 12
	const tagSize = 16
	for _, variant := range []aesctrhmac.Variant{aesctrhmac.VariantNoPrefix, aesctrhmac.VariantTink, aesctrhmac.VariantCrunchy} {
		t.Run(variant.String(), func(t *testing.T) {
			cipher, err := createAEAD([]byte("1111111111111111"), ivSize, aesctrhmac.SHA1, []byte("2222222222222222"), tagSize, variant, 0)
			if err != nil {
				t.Fatalf("got: %v, want: success", err)
			}

			message := []byte("Some data to encrypt.")
			associatedData := []byte("Some data to authenticate.")

			ciphertext, err := cipher.Encrypt(message, associatedData)
			if err != nil {
				t.Fatalf("encryption failed, error: %v", err)
			}

			wantCiphertextSize := len(message) + ivSize + tagSize
			if variant != aesctrhmac.VariantNoPrefix {
				wantCiphertextSize += 5
			}
			if len(ciphertext) != wantCiphertextSize {
				t.Errorf("invalid ciphertext size, got: %d, want: %d", len(ciphertext), wantCiphertextSize)
			}

			plaintext, err := cipher.Decrypt(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("decryption failed, error: %v", err)
			}

			if !bytes.Equal(plaintext, message) {
				t.Errorf("invalid plaintext, got: %q, want: %q", plaintext, message)
			}
		})
	}
}

func TestAEADWithAssociatedDataSlice(t *testing.T) {
	const ivSize = 12
	const tagSize = 16
	for _, variant := range []aesctrhmac.Variant{aesctrhmac.VariantNoPrefix, aesctrhmac.VariantTink, aesctrhmac.VariantCrunchy} {
		t.Run(variant.String(), func(t *testing.T) {
			cipher, err := createAEAD([]byte("1111111111111111"), ivSize, aesctrhmac.SHA1, []byte("2222222222222222"), tagSize, variant, 0)
			if err != nil {
				t.Fatalf("got: %v, want: success", err)
			}
			message := []byte("message")
			largeData := []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
			associatedData := largeData[:1]
			_, err = cipher.Encrypt(message, associatedData)
			if err != nil {
				t.Fatalf("encryption failed, error: %v", err)
			}
			wantLargeData := []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
			if !bytes.Equal(largeData, wantLargeData) {
				t.Errorf("largeData = %q, want: %q", largeData, wantLargeData)
			}
		})
	}
}

func TestAEADEncryptDecryptRandomMessage(t *testing.T) {
	const ivSize = 12
	const tagSize = 16
	for _, variant := range []aesctrhmac.Variant{aesctrhmac.VariantNoPrefix, aesctrhmac.VariantTink, aesctrhmac.VariantCrunchy} {
		t.Run(variant.String(), func(t *testing.T) {
			cipher, err := createAEAD([]byte("1111111111111111"), ivSize, aesctrhmac.SHA1, []byte("2222222222222222"), tagSize, aesctrhmac.VariantTink, 0)
			if err != nil {
				t.Fatalf("got: %v, want: success", err)
			}
			for i := 0; i < 256; i++ {
				message := random.GetRandomBytes(uint32(i))
				associatedData := random.GetRandomBytes(uint32(i))
				ciphertext, err := cipher.Encrypt(message, associatedData)
				if err != nil {
					t.Fatalf("encryption failed, error: %v", err)
				}
				plaintext, err := cipher.Decrypt(ciphertext, associatedData)
				if err != nil {
					t.Fatalf("decryption failed, error: %v", err)
				}
				if !bytes.Equal(plaintext, message) {
					t.Errorf("invalid plaintext, got: %q, want: %q", plaintext, message)
				}
			}
		})
	}
}

func TestAEADMultipleEncrypt(t *testing.T) {
	const ivSize = 12
	const tagSize = 16

	for _, variant := range []aesctrhmac.Variant{aesctrhmac.VariantNoPrefix, aesctrhmac.VariantTink, aesctrhmac.VariantCrunchy} {
		t.Run(variant.String(), func(t *testing.T) {
			cipher, err := createAEAD([]byte("1111111111111111"), ivSize, aesctrhmac.SHA256, []byte("2222222222222222"), tagSize, variant, 0)
			if err != nil {
				t.Fatalf("got: %v, want: success", err)
			}

			message := []byte("Some data to encrypt.")
			associatedData := []byte("Some data to authenticate.")

			ciphertext1, err := cipher.Encrypt(message, associatedData)
			if err != nil {
				t.Fatalf("encryption failed, error: %v", err)
			}

			ciphertext2, err := cipher.Encrypt(message, associatedData)
			if err != nil {
				t.Fatalf("encryption failed, error: %v", err)
			}

			if bytes.Equal(ciphertext1, ciphertext2) {
				t.Error("ciphertexts must not be the same")
			}
		})
	}
}

func TestAEADInvalidTagSize(t *testing.T) {
	const keySize = 16
	const ivSize = 12
	const macKeySize = 16
	const tagSize = 9 // Invalid!
	for _, variant := range []aesctrhmac.Variant{aesctrhmac.VariantNoPrefix, aesctrhmac.VariantTink, aesctrhmac.VariantCrunchy} {
		t.Run(variant.String(), func(t *testing.T) {
			if _, err := createAEAD([]byte("1111111111111111"), ivSize, aesctrhmac.SHA256, []byte("2222222222222222"), tagSize, variant, 0); err == nil {
				t.Error("got: success, want: error invalid tag size")
			}
		})
	}
}

func TestAEADDecryptModifiedCiphertext(t *testing.T) {
	const ivSize = 12
	const tagSize = 16
	for _, variant := range []aesctrhmac.Variant{aesctrhmac.VariantNoPrefix, aesctrhmac.VariantTink, aesctrhmac.VariantCrunchy} {
		t.Run(variant.String(), func(t *testing.T) {
			cipher, err := createAEAD([]byte("1111111111111111"), ivSize, aesctrhmac.SHA256, []byte("2222222222222222"), tagSize, variant, 0)
			if err != nil {
				t.Fatalf("got: %v, want: success", err)
			}

			message := []byte("Some data to encrypt.")
			associatedData := []byte("Some data to authenticate.")
			ciphertext, err := cipher.Encrypt(message, associatedData)
			if err != nil {
				t.Fatalf("encryption failed, error: %v", err)
			}

			// Modify the ciphertext and try to decrypt.
			modCiphertext := make([]byte, len(ciphertext))
			copy(modCiphertext, ciphertext)
			for i := 0; i < len(ciphertext)*8; i++ {
				// Save the byte to be modified.
				b := modCiphertext[i/8]
				modCiphertext[i/8] ^= (1 << uint(i%8))
				if bytes.Equal(ciphertext, modCiphertext) {
					t.Errorf("modCiphertext shouldn't be the same as ciphertext")
				}
				if _, err := cipher.Decrypt(modCiphertext, associatedData); err == nil {
					t.Errorf("successfully decrypted modified ciphertext (i = %d)", i)
				}
				// Restore the modified byte.
				modCiphertext[i/8] = b
			}

			// Modify the associated data.
			modAssociatedData := make([]byte, len(associatedData))
			copy(modAssociatedData, associatedData)
			for i := 0; i < len(associatedData)*8; i++ {
				// Save the byte to be modified.
				b := modAssociatedData[i/8]
				modAssociatedData[i/8] ^= (1 << uint(i%8))
				if bytes.Equal(associatedData, modAssociatedData) {
					t.Errorf("modAssociatedData shouldn't be the same as associatedData")
				}
				if _, err := cipher.Decrypt(ciphertext, modAssociatedData); err == nil {
					t.Errorf("successfully decrypted with modified associated data (i = %d)", i)
				}
				// Restore the modified byte.
				modAssociatedData[i/8] = b
			}

			// Truncate the ciphertext.
			truncatedCiphertext := make([]byte, len(ciphertext))
			copy(truncatedCiphertext, ciphertext)
			for i := 1; i <= len(ciphertext); i++ {
				truncatedCiphertext = truncatedCiphertext[:len(ciphertext)-i]
				if _, err := cipher.Decrypt(truncatedCiphertext, associatedData); err == nil {
					t.Errorf("successfully decrypted truncated ciphertext (i = %d)", i)
				}
			}
		})
	}
}

func TestAEADEmptyParams(t *testing.T) {
	const ivSize = 12
	const tagSize = 16
	for _, variant := range []aesctrhmac.Variant{aesctrhmac.VariantNoPrefix, aesctrhmac.VariantTink, aesctrhmac.VariantCrunchy} {
		t.Run(variant.String(), func(t *testing.T) {
			cipher, err := createAEAD([]byte("1111111111111111"), ivSize, aesctrhmac.SHA256, []byte("2222222222222222"), tagSize, variant, 0)
			if err != nil {
				t.Fatalf("got: %v, want: success", err)
			}

			message := []byte("Some data to encrypt.")
			if _, err := cipher.Encrypt(message, []byte{}); err != nil {
				t.Errorf("encryption failed with empty associatedData")
			}
			if _, err := cipher.Encrypt([]byte{}, []byte{}); err != nil {
				t.Errorf("encryption failed with empty ciphertext and associatedData")
			}
		})
	}
}

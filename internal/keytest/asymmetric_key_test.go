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

package keytest_test

import (
	"bytes"
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/internal/keytest"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

// reversedKey128Bits is key128Bits in reverse order, that is, the public key
// bytes of a private key with key128Bits as private key bytes.
var reversedKey128Bits = []byte{
	0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
}

func mustCreateAsymmetricParameters(t *testing.T, variant keytest.Variant) *keytest.AsymmetricParameters {
	t.Helper()
	params, err := keytest.NewAsymmetricParameters(variant)
	if err != nil {
		t.Fatalf("keytest.NewAsymmetricParameters(%v) err = %v, want nil", variant, err)
	}
	return params
}

func mustCreatePublicKey(t *testing.T, variant keytest.Variant, keyID uint32, keyBytes []byte) *keytest.PublicKey {
	t.Helper()
	params := mustCreateAsymmetricParameters(t, variant)
	k, err := keytest.NewPublicKey(keyBytes, keyID, params)
	if err != nil {
		t.Fatalf("keytest.NewPublicKey(%x, %v, %v) err = %v, want nil", keyBytes, keyID, params, err)
	}
	return k
}

func mustCreatePrivateKey(t *testing.T, variant keytest.Variant, keyID uint32, privateKeyBytes []byte) *keytest.PrivateKey {
	t.Helper()
	params := mustCreateAsymmetricParameters(t, variant)
	k, err := keytest.NewPrivateKey(secretdata.NewBytesFromData(privateKeyBytes, insecuresecretdataaccess.Token{}), keyID, params)
	if err != nil {
		t.Fatalf("keytest.NewPrivateKey(privateKeyBytes, %v, %v) err = %v, want nil", keyID, params, err)
	}
	return k
}

func mustGetPublicKey(t *testing.T, privateKey *keytest.PrivateKey) *keytest.PublicKey {
	t.Helper()
	k, err := privateKey.PublicKey()
	if err != nil {
		t.Fatalf("privateKey.PublicKey() err = %v, want nil", err)
	}
	publicKey, ok := k.(*keytest.PublicKey)
	if !ok {
		t.Fatalf("privateKey.PublicKey() returned key of type %T, want %T", k, (*keytest.PublicKey)(nil))
	}
	return publicKey
}

func TestNewAsymmetricParametersInvalidVariant(t *testing.T) {
	if _, err := keytest.NewAsymmetricParameters(keytest.VariantUnknown); err == nil {
		t.Errorf("keytest.NewAsymmetricParameters(keytest.VariantUnknown) err = nil, want error")
	}
}

func TestNewAsymmetricParametersWorks(t *testing.T) {
	for _, variant := range []keytest.Variant{
		keytest.VariantTink,
		keytest.VariantCrunchy,
		keytest.VariantNoPrefix,
	} {
		t.Run(variant.String(), func(t *testing.T) {
			params, err := keytest.NewAsymmetricParameters(variant)
			if err != nil {
				t.Fatalf("keytest.NewAsymmetricParameters(%v) err = %v, want nil", variant, err)
			}
			if got, want := params.HasIDRequirement(), variant != keytest.VariantNoPrefix; got != want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, want)
			}
			if got := params.Variant(); got != variant {
				t.Errorf("params.Variant() = %v, want %v", got, variant)
			}
			otherParams := mustCreateAsymmetricParameters(t, variant)
			if !params.Equal(otherParams) {
				t.Errorf("params.Equal(otherParams) = false, want true")
			}
		})
	}
}

func TestAsymmetricParametersEqualFalseIfDifferent(t *testing.T) {
	for _, test := range []struct {
		name     string
		variant1 keytest.Variant
		variant2 keytest.Variant
	}{
		{
			name:     "Crunchy vs Tink",
			variant1: keytest.VariantCrunchy,
			variant2: keytest.VariantTink,
		},
		{
			name:     "Tink vs NoPrefix",
			variant1: keytest.VariantTink,
			variant2: keytest.VariantNoPrefix,
		},
		{
			name:     "Crunchy vs NoPrefix",
			variant1: keytest.VariantCrunchy,
			variant2: keytest.VariantNoPrefix,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params1 := mustCreateAsymmetricParameters(t, test.variant1)
			params2 := mustCreateAsymmetricParameters(t, test.variant2)
			if params1.Equal(params2) {
				t.Errorf("params1.Equal(params2) = true, want false")
			}
		})
	}
}

// TestAsymmetricParametersNotEqualToSymmetricParameters tests that the
// parameters of the symmetric and of the asymmetric test-only keys are never
// equal, even if they have the same variant.
func TestAsymmetricParametersNotEqualToSymmetricParameters(t *testing.T) {
	for _, variant := range []keytest.Variant{
		keytest.VariantTink,
		keytest.VariantCrunchy,
		keytest.VariantNoPrefix,
	} {
		t.Run(variant.String(), func(t *testing.T) {
			asymmetricParams := mustCreateAsymmetricParameters(t, variant)
			symmetricParams := mustCreateParameters(t, variant)
			if asymmetricParams.Equal(symmetricParams) {
				t.Errorf("asymmetricParams.Equal(symmetricParams) = true, want false")
			}
			if symmetricParams.Equal(asymmetricParams) {
				t.Errorf("symmetricParams.Equal(asymmetricParams) = true, want false")
			}
		})
	}
}

// TestAsymmetricParametersEqualReturnsFalseIfNil tests that parameters are not
// equal to a nil pointer of their own type, and that the comparison doesn't
// panic.
func TestAsymmetricParametersEqualReturnsFalseIfNil(t *testing.T) {
	params := mustCreateAsymmetricParameters(t, keytest.VariantTink)
	if params.Equal((*keytest.AsymmetricParameters)(nil)) {
		t.Errorf("params.Equal((*keytest.AsymmetricParameters)(nil)) = true, want false")
	}
}

func TestNewPublicKeyWorks(t *testing.T) {
	for _, tc := range keyTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			params := mustCreateAsymmetricParameters(t, tc.variant)
			publicKey, err := keytest.NewPublicKey(tc.keyBytes, tc.keyID, params)
			if err != nil {
				t.Fatalf("keytest.NewPublicKey(%x, %v, %v) err = %v, want nil", tc.keyBytes, tc.keyID, params, err)
			}
			if got := publicKey.KeyBytes(); !bytes.Equal(got, tc.keyBytes) {
				t.Errorf("publicKey.KeyBytes() = %x, want %x", got, tc.keyBytes)
			}
			if !publicKey.Parameters().Equal(params) {
				t.Errorf("publicKey.Parameters() = %v, want %v", publicKey.Parameters(), params)
			}
			keyID, required := publicKey.IDRequirement()
			if wantRequired := tc.variant != keytest.VariantNoPrefix; keyID != tc.keyID || required != wantRequired {
				t.Errorf("publicKey.IDRequirement() = (%v, %v), want (%v, %v)", keyID, required, tc.keyID, wantRequired)
			}
			otherPublicKey, err := keytest.NewPublicKey(tc.keyBytes, tc.keyID, params)
			if err != nil {
				t.Fatalf("keytest.NewPublicKey(%x, %v, %v) err = %v, want nil", tc.keyBytes, tc.keyID, params, err)
			}
			if !publicKey.Equal(otherPublicKey) {
				t.Errorf("publicKey.Equal(otherPublicKey) = false, want true")
			}
		})
	}
}

func TestPublicKeyDoesNotAliasKeyBytes(t *testing.T) {
	keyBytes := bytes.Clone(key128Bits)
	publicKey := mustCreatePublicKey(t, keytest.VariantTink, 123, keyBytes)
	// Neither modifying the input of NewPublicKey nor the output of KeyBytes
	// changes the key.
	keyBytes[0] ^= 0xff
	publicKey.KeyBytes()[1] ^= 0xff
	if got := publicKey.KeyBytes(); !bytes.Equal(got, key128Bits) {
		t.Errorf("publicKey.KeyBytes() = %x, want %x", got, key128Bits)
	}
}

func TestNewPrivateKeyWorks(t *testing.T) {
	for _, tc := range keyTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			params := mustCreateAsymmetricParameters(t, tc.variant)
			privateKeyBytes := secretdata.NewBytesFromData(tc.keyBytes, insecuresecretdataaccess.Token{})
			privateKey, err := keytest.NewPrivateKey(privateKeyBytes, tc.keyID, params)
			if err != nil {
				t.Fatalf("keytest.NewPrivateKey(privateKeyBytes, %v, %v) err = %v, want nil", tc.keyID, params, err)
			}
			if !privateKey.PrivateKeyBytes().Equal(privateKeyBytes) {
				t.Errorf("privateKey.PrivateKeyBytes().Equal(privateKeyBytes) = false, want true")
			}
			if !privateKey.Parameters().Equal(params) {
				t.Errorf("privateKey.Parameters() = %v, want %v", privateKey.Parameters(), params)
			}
			keyID, required := privateKey.IDRequirement()
			if wantRequired := tc.variant != keytest.VariantNoPrefix; keyID != tc.keyID || required != wantRequired {
				t.Errorf("privateKey.IDRequirement() = (%v, %v), want (%v, %v)", keyID, required, tc.keyID, wantRequired)
			}
			otherPrivateKey, err := keytest.NewPrivateKey(privateKeyBytes, tc.keyID, params)
			if err != nil {
				t.Fatalf("keytest.NewPrivateKey(privateKeyBytes, %v, %v) err = %v, want nil", tc.keyID, params, err)
			}
			if !privateKey.Equal(otherPrivateKey) {
				t.Errorf("privateKey.Equal(otherPrivateKey) = false, want true")
			}
		})
	}
}

// TestPrivateKeyPublicKey tests that the public key of a private key is the
// [*keytest.PublicKey] with the private key bytes in reverse order, and with
// the same parameters, ID requirement and output prefix.
func TestPrivateKeyPublicKey(t *testing.T) {
	for _, tc := range keyTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			privateKey := mustCreatePrivateKey(t, tc.variant, tc.keyID, key128Bits)
			publicKey := mustGetPublicKey(t, privateKey)
			if got := publicKey.KeyBytes(); !bytes.Equal(got, reversedKey128Bits) {
				t.Errorf("publicKey.KeyBytes() = %x, want %x", got, reversedKey128Bits)
			}
			if want := mustCreatePublicKey(t, tc.variant, tc.keyID, reversedKey128Bits); !publicKey.Equal(want) {
				t.Errorf("privateKey.PublicKey() = %v, want %v", publicKey, want)
			}
			if !publicKey.Parameters().Equal(privateKey.Parameters()) {
				t.Errorf("publicKey.Parameters() = %v, want %v", publicKey.Parameters(), privateKey.Parameters())
			}
			gotID, gotRequired := publicKey.IDRequirement()
			wantID, wantRequired := privateKey.IDRequirement()
			if gotID != wantID || gotRequired != wantRequired {
				t.Errorf("publicKey.IDRequirement() = (%v, %v), want (%v, %v)", gotID, gotRequired, wantID, wantRequired)
			}
			if got, want := publicKey.OutputPrefix(), privateKey.OutputPrefix(); !bytes.Equal(got, want) {
				t.Errorf("publicKey.OutputPrefix() = %x, want %x", got, want)
			}
		})
	}
}

func TestNewAsymmetricKeysFailIfParametersIsNil(t *testing.T) {
	if _, err := keytest.NewPublicKey(key128Bits, 123, nil); err == nil {
		t.Errorf("keytest.NewPublicKey(%x, 123, nil) err = nil, want error", key128Bits)
	}
	privateKeyBytes := secretdata.NewBytesFromData(key128Bits, insecuresecretdataaccess.Token{})
	if _, err := keytest.NewPrivateKey(privateKeyBytes, 123, nil); err == nil {
		t.Errorf("keytest.NewPrivateKey(privateKeyBytes, 123, nil) err = nil, want error")
	}
}

func TestNewAsymmetricKeysFailIfKeySizeIsWrong(t *testing.T) {
	params := mustCreateAsymmetricParameters(t, keytest.VariantTink)
	for _, tc := range []struct {
		name     string
		keyBytes []byte
	}{
		{
			name:     "empty key",
			keyBytes: []byte{},
		},
		{
			name:     "15-byte key",
			keyBytes: key128Bits[:15],
		},
		{
			name:     "32-byte key",
			keyBytes: key256Bits,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := keytest.NewPublicKey(tc.keyBytes, 123, params); err == nil {
				t.Errorf("keytest.NewPublicKey(%x, 123, %v) err = nil, want error", tc.keyBytes, params)
			}
			privateKeyBytes := secretdata.NewBytesFromData(tc.keyBytes, insecuresecretdataaccess.Token{})
			if _, err := keytest.NewPrivateKey(privateKeyBytes, 123, params); err == nil {
				t.Errorf("keytest.NewPrivateKey(privateKeyBytes, 123, %v) err = nil, want error", params)
			}
		})
	}
}

// TestNewAsymmetricKeysFailIfIDRequirementIsInconsistent tests that creating a
// key fails if the ID requirement doesn't match the parameters.
//
// This includes invalid parameters, which can only be created as a struct
// literal with default values.
func TestNewAsymmetricKeysFailIfIDRequirementIsInconsistent(t *testing.T) {
	for _, tc := range []struct {
		name          string
		params        *keytest.AsymmetricParameters
		idRequirement uint32
	}{
		{
			name:          "NoPrefix with non-zero ID requirement",
			params:        mustCreateAsymmetricParameters(t, keytest.VariantNoPrefix),
			idRequirement: 123,
		},
		{
			name:          "Tink with zero ID requirement",
			params:        mustCreateAsymmetricParameters(t, keytest.VariantTink),
			idRequirement: 0,
		},
		{
			name:          "Crunchy with zero ID requirement",
			params:        mustCreateAsymmetricParameters(t, keytest.VariantCrunchy),
			idRequirement: 0,
		},
		{
			name:          "invalid parameters with zero ID requirement",
			params:        &keytest.AsymmetricParameters{},
			idRequirement: 0,
		},
		{
			name:          "invalid parameters with non-zero ID requirement",
			params:        &keytest.AsymmetricParameters{},
			idRequirement: 123,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := keytest.NewPublicKey(key128Bits, tc.idRequirement, tc.params); err == nil {
				t.Errorf("keytest.NewPublicKey(%x, %v, %v) err = nil, want error", key128Bits, tc.idRequirement, tc.params)
			}
			privateKeyBytes := secretdata.NewBytesFromData(key128Bits, insecuresecretdataaccess.Token{})
			if _, err := keytest.NewPrivateKey(privateKeyBytes, tc.idRequirement, tc.params); err == nil {
				t.Errorf("keytest.NewPrivateKey(privateKeyBytes, %v, %v) err = nil, want error", tc.idRequirement, tc.params)
			}
		})
	}
}

func TestAsymmetricKeysOutputPrefix(t *testing.T) {
	for _, test := range []struct {
		name    string
		variant keytest.Variant
		id      uint32
		want    []byte
	}{
		{
			name:    "Tink",
			variant: keytest.VariantTink,
			id:      uint32(0x01020304),
			want:    []byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "Crunchy",
			variant: keytest.VariantCrunchy,
			id:      uint32(0x01020304),
			want:    []byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:    "No prefix",
			variant: keytest.VariantNoPrefix,
			id:      0,
			want:    nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			publicKey := mustCreatePublicKey(t, test.variant, test.id, key128Bits)
			if got := publicKey.OutputPrefix(); !bytes.Equal(got, test.want) {
				t.Errorf("publicKey.OutputPrefix() = %v, want %v", got, test.want)
			}
			privateKey := mustCreatePrivateKey(t, test.variant, test.id, key128Bits)
			if got := privateKey.OutputPrefix(); !bytes.Equal(got, test.want) {
				t.Errorf("privateKey.OutputPrefix() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAsymmetricKeysEqualReturnsFalseIfDifferent(t *testing.T) {
	for _, test := range []struct {
		name   string
		first  testKey
		second testKey
	}{
		{
			name: "different prefix variant",
			first: testKey{
				variant: keytest.VariantTink,
				key:     key128Bits,
				id:      0x01,
			},
			second: testKey{
				variant: keytest.VariantCrunchy,
				key:     key128Bits,
				id:      0x01,
			},
		},
		{
			name: "different key IDs",
			first: testKey{
				variant: keytest.VariantTink,
				key:     key128Bits,
				id:      0x01,
			},
			second: testKey{
				variant: keytest.VariantTink,
				key:     key128Bits,
				id:      0x02,
			},
		},
		{
			name: "different key bytes",
			first: testKey{
				variant: keytest.VariantCrunchy,
				key:     key128Bits,
				id:      0x01,
			},
			second: testKey{
				variant: keytest.VariantCrunchy,
				key:     otherKey128Bits,
				id:      0x01,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			firstPublicKey := mustCreatePublicKey(t, test.first.variant, test.first.id, test.first.key)
			secondPublicKey := mustCreatePublicKey(t, test.second.variant, test.second.id, test.second.key)
			if firstPublicKey.Equal(secondPublicKey) {
				t.Errorf("firstPublicKey.Equal(secondPublicKey) = true, want false")
			}
			firstPrivateKey := mustCreatePrivateKey(t, test.first.variant, test.first.id, test.first.key)
			secondPrivateKey := mustCreatePrivateKey(t, test.second.variant, test.second.id, test.second.key)
			if firstPrivateKey.Equal(secondPrivateKey) {
				t.Errorf("firstPrivateKey.Equal(secondPrivateKey) = true, want false")
			}
		})
	}
}

func TestAsymmetricKeysEqualReturnsFalseIfDifferentType(t *testing.T) {
	// All the keys below have the same variant, ID requirement and key bytes;
	// in particular, publicKey is not the public key of privateKey.
	publicKey := mustCreatePublicKey(t, keytest.VariantTink, 1234, key128Bits)
	privateKey := mustCreatePrivateKey(t, keytest.VariantTink, 1234, key128Bits)
	symmetricKey := mustCreateKey(t, keytest.VariantTink, 1234, key128Bits)
	for _, tc := range []struct {
		name   string
		first  key.Key
		second key.Key
	}{
		{
			name:   "public key vs private key",
			first:  publicKey,
			second: privateKey,
		},
		{
			name:   "private key vs public key",
			first:  privateKey,
			second: publicKey,
		},
		{
			name:   "private key vs its public key",
			first:  privateKey,
			second: mustGetPublicKey(t, privateKey),
		},
		{
			name:   "public key vs symmetric key",
			first:  publicKey,
			second: symmetricKey,
		},
		{
			name:   "symmetric key vs public key",
			first:  symmetricKey,
			second: publicKey,
		},
		{
			name:   "private key vs symmetric key",
			first:  privateKey,
			second: symmetricKey,
		},
		{
			name:   "symmetric key vs private key",
			first:  symmetricKey,
			second: privateKey,
		},
		{
			name:   "public key vs stub key",
			first:  publicKey,
			second: &stubKey{},
		},
		{
			name:   "private key vs stub key",
			first:  privateKey,
			second: &stubKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.first.Equal(tc.second) {
				t.Errorf("first.Equal(second) = true, want false")
			}
		})
	}
}

// TestAsymmetricKeysEqualReturnsFalseIfNil tests that a key is not equal to a
// nil pointer of its own type, and that the comparison doesn't panic.
func TestAsymmetricKeysEqualReturnsFalseIfNil(t *testing.T) {
	publicKey := mustCreatePublicKey(t, keytest.VariantTink, 1234, key128Bits)
	if publicKey.Equal((*keytest.PublicKey)(nil)) {
		t.Errorf("publicKey.Equal((*keytest.PublicKey)(nil)) = true, want false")
	}
	privateKey := mustCreatePrivateKey(t, keytest.VariantTink, 1234, key128Bits)
	if privateKey.Equal((*keytest.PrivateKey)(nil)) {
		t.Errorf("privateKey.Equal((*keytest.PrivateKey)(nil)) = true, want false")
	}
}

// TestZeroValueAsymmetricKeys tests that keys created as struct literals with
// default values are invalid, but can be used without panicking.
func TestZeroValueAsymmetricKeys(t *testing.T) {
	validPublicKey := mustCreatePublicKey(t, keytest.VariantTink, 1234, key128Bits)
	validPrivateKey := mustCreatePrivateKey(t, keytest.VariantTink, 1234, key128Bits)
	for _, tc := range []struct {
		name     string
		key      key.Key
		sameKey  key.Key
		validKey key.Key
	}{
		{
			name:     "public key",
			key:      &keytest.PublicKey{},
			sameKey:  &keytest.PublicKey{},
			validKey: validPublicKey,
		},
		{
			name:     "private key",
			key:      &keytest.PrivateKey{},
			sameKey:  &keytest.PrivateKey{},
			validKey: validPrivateKey,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.key.Equal(tc.sameKey) {
				t.Errorf("key.Equal(sameKey) = false, want true")
			}
			if tc.key.Equal(tc.validKey) {
				t.Errorf("key.Equal(validKey) = true, want false")
			}
			if tc.validKey.Equal(tc.key) {
				t.Errorf("validKey.Equal(key) = true, want false")
			}
			if id, required := tc.key.IDRequirement(); id != 0 || required {
				t.Errorf("key.IDRequirement() = (%v, %v), want (0, false)", id, required)
			}
			params, ok := tc.key.Parameters().(*keytest.AsymmetricParameters)
			if !ok || params == nil {
				t.Fatalf("key.Parameters() = %v of type %T, want a non-nil %T", tc.key.Parameters(), tc.key.Parameters(), (*keytest.AsymmetricParameters)(nil))
			}
			if got := params.Variant(); got != keytest.VariantUnknown {
				t.Errorf("key.Parameters().Variant() = %v, want %v", got, keytest.VariantUnknown)
			}
			if params.HasIDRequirement() {
				t.Errorf("key.Parameters().HasIDRequirement() = true, want false")
			}
			if params.Equal(tc.validKey.Parameters()) {
				t.Errorf("key.Parameters().Equal(validKey.Parameters()) = true, want false")
			}
		})
	}

	publicKey := &keytest.PublicKey{}
	if got := publicKey.KeyBytes(); len(got) != 0 {
		t.Errorf("publicKey.KeyBytes() = %x, want empty", got)
	}
	if got := publicKey.OutputPrefix(); len(got) != 0 {
		t.Errorf("publicKey.OutputPrefix() = %x, want empty", got)
	}
	privateKey := &keytest.PrivateKey{}
	if got := privateKey.PrivateKeyBytes().Len(); got != 0 {
		t.Errorf("privateKey.PrivateKeyBytes().Len() = %v, want 0", got)
	}
	if got := privateKey.OutputPrefix(); len(got) != 0 {
		t.Errorf("privateKey.OutputPrefix() = %x, want empty", got)
	}
	if _, err := privateKey.PublicKey(); err == nil {
		t.Errorf("privateKey.PublicKey() err = nil, want error")
	}
}

func TestPrivateKeyCreator(t *testing.T) {
	for _, tc := range []struct {
		name          string
		variant       keytest.Variant
		idRequirement uint32
	}{
		{
			name:          "TINK",
			variant:       keytest.VariantTink,
			idRequirement: 123,
		},
		{
			name:          "CRUNCHY",
			variant:       keytest.VariantCrunchy,
			idRequirement: 123,
		},
		{
			name:          "NO_PREFIX",
			variant:       keytest.VariantNoPrefix,
			idRequirement: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := mustCreateAsymmetricParameters(t, tc.variant)
			k, err := keygenregistry.CreateKey(params, tc.idRequirement)
			if err != nil {
				t.Fatalf("keygenregistry.CreateKey(%v, %v) err = %v, want nil", params, tc.idRequirement, err)
			}
			privateKey, ok := k.(*keytest.PrivateKey)
			if !ok {
				t.Fatalf("keygenregistry.CreateKey(%v, %v) returned key of type %T, want %T", params, tc.idRequirement, k, (*keytest.PrivateKey)(nil))
			}
			idRequirement, hasIDRequirement := privateKey.IDRequirement()
			if wantRequired := tc.variant != keytest.VariantNoPrefix; idRequirement != tc.idRequirement || hasIDRequirement != wantRequired {
				t.Errorf("privateKey.IDRequirement() = (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, tc.idRequirement, wantRequired)
			}
			if got, want := privateKey.PrivateKeyBytes().Len(), 16; got != want {
				t.Errorf("privateKey.PrivateKeyBytes().Len() = %d, want %d", got, want)
			}
			if !privateKey.Parameters().Equal(params) {
				t.Errorf("privateKey.Parameters() = %v, want %v", privateKey.Parameters(), params)
			}

			// Two generated keys are different.
			otherKey, err := keygenregistry.CreateKey(params, tc.idRequirement)
			if err != nil {
				t.Fatalf("keygenregistry.CreateKey(%v, %v) err = %v, want nil", params, tc.idRequirement, err)
			}
			if privateKey.Equal(otherKey) {
				t.Errorf("privateKey.Equal(otherKey) = true, want false")
			}
		})
	}
}

func TestPrivateKeyCreator_FailsIfInvalidParameters(t *testing.T) {
	for _, tc := range []struct {
		name          string
		params        *keytest.AsymmetricParameters
		idRequirement uint32
	}{
		{
			name:          "NoPrefix with non-zero ID requirement",
			params:        mustCreateAsymmetricParameters(t, keytest.VariantNoPrefix),
			idRequirement: 123,
		},
		{
			name:          "Tink with zero ID requirement",
			params:        mustCreateAsymmetricParameters(t, keytest.VariantTink),
			idRequirement: 0,
		},
		{
			name:          "unknown variant",
			params:        &keytest.AsymmetricParameters{},
			idRequirement: 123,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := keygenregistry.CreateKey(tc.params, tc.idRequirement); err == nil {
				t.Errorf("keygenregistry.CreateKey(%v, %v) err = nil, want error", tc.params, tc.idRequirement)
			}
		})
	}
}

// TestPublicHandleFromPrivateKeys tests that [keyset.Handle.Public] turns a
// handle of [*keytest.PrivateKey]s into a handle of the corresponding
// [*keytest.PublicKey]s.
func TestPublicHandleFromPrivateKeys(t *testing.T) {
	primaryKey := mustCreatePrivateKey(t, keytest.VariantTink, 0x01020304, key128Bits)
	crunchyKey := mustCreatePrivateKey(t, keytest.VariantCrunchy, 0x05060708, otherKey128Bits)
	noPrefixKey := mustCreatePrivateKey(t, keytest.VariantNoPrefix, 0, key128Bits)

	manager := keyset.NewManager()
	primaryKeyID, err := manager.AddKey(primaryKey)
	if err != nil {
		t.Fatalf("manager.AddKey(primaryKey) err = %v, want nil", err)
	}
	if err := manager.SetPrimary(primaryKeyID); err != nil {
		t.Fatalf("manager.SetPrimary(%v) err = %v, want nil", primaryKeyID, err)
	}
	crunchyKeyID, err := manager.AddKey(crunchyKey)
	if err != nil {
		t.Fatalf("manager.AddKey(crunchyKey) err = %v, want nil", err)
	}
	if err := manager.Disable(crunchyKeyID); err != nil {
		t.Fatalf("manager.Disable(%v) err = %v, want nil", crunchyKeyID, err)
	}
	if _, err := manager.AddKey(noPrefixKey); err != nil {
		t.Fatalf("manager.AddKey(noPrefixKey) err = %v, want nil", err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}

	publicHandle, err := handle.Public()
	if err != nil {
		t.Fatalf("handle.Public() err = %v, want nil", err)
	}
	if got, want := publicHandle.Len(), handle.Len(); got != want {
		t.Fatalf("publicHandle.Len() = %v, want %v", got, want)
	}
	for i := 0; i < handle.Len(); i++ {
		entry, err := handle.Entry(i)
		if err != nil {
			t.Fatalf("handle.Entry(%v) err = %v, want nil", i, err)
		}
		privateKey, ok := entry.Key().(*keytest.PrivateKey)
		if !ok {
			t.Fatalf("handle.Entry(%v).Key() is of type %T, want %T", i, entry.Key(), (*keytest.PrivateKey)(nil))
		}
		publicEntry, err := publicHandle.Entry(i)
		if err != nil {
			t.Fatalf("publicHandle.Entry(%v) err = %v, want nil", i, err)
		}
		publicKey, ok := publicEntry.Key().(*keytest.PublicKey)
		if !ok {
			t.Fatalf("publicHandle.Entry(%v).Key() is of type %T, want %T", i, publicEntry.Key(), (*keytest.PublicKey)(nil))
		}
		if want := mustGetPublicKey(t, privateKey); !publicKey.Equal(want) {
			t.Errorf("publicHandle.Entry(%v).Key() = %v, want %v", i, publicKey, want)
		}
		if got, want := publicEntry.KeyID(), entry.KeyID(); got != want {
			t.Errorf("publicHandle.Entry(%v).KeyID() = %v, want %v", i, got, want)
		}
		if got, want := publicEntry.KeyStatus(), entry.KeyStatus(); got != want {
			t.Errorf("publicHandle.Entry(%v).KeyStatus() = %v, want %v", i, got, want)
		}
		if got, want := publicEntry.IsPrimary(), entry.IsPrimary(); got != want {
			t.Errorf("publicHandle.Entry(%v).IsPrimary() = %v, want %v", i, got, want)
		}
	}

	publicPrimaryEntry, err := publicHandle.Primary()
	if err != nil {
		t.Fatalf("publicHandle.Primary() err = %v, want nil", err)
	}
	if got, want := publicPrimaryEntry.KeyID(), uint32(0x01020304); got != want {
		t.Errorf("publicHandle.Primary().KeyID() = %v, want %v", got, want)
	}
	if want := mustCreatePublicKey(t, keytest.VariantTink, 0x01020304, reversedKey128Bits); !publicPrimaryEntry.Key().Equal(want) {
		t.Errorf("publicHandle.Primary().Key() = %v, want %v", publicPrimaryEntry.Key(), want)
	}

	// A handle of public keys has no public handle.
	if _, err := publicHandle.Public(); err == nil {
		t.Errorf("publicHandle.Public() err = nil, want error")
	}
}

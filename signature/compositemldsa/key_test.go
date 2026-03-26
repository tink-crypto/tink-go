// Copyright 2026 Google LLC
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
package compositemldsa_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/internal/outputprefix"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/signature/compositemldsa"
	"github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/signature/ed25519"
	"github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapss"
)

const (
	f4 = 65537
)

func generateMLDSAKeyPair(t *testing.T, instance compositemldsa.MLDSAInstance) (*mldsa.PrivateKey, *mldsa.PublicKey) {
	t.Helper()
	var params *mldsa.Parameters
	var err error
	switch instance {
	case compositemldsa.MLDSA65:
		params, err = mldsa.NewParameters(mldsa.MLDSA65, mldsa.VariantNoPrefix)
	case compositemldsa.MLDSA87:
		params, err = mldsa.NewParameters(mldsa.MLDSA87, mldsa.VariantNoPrefix)
	default:
		t.Fatalf("unsupported ML-DSA instance: %v", instance)
	}
	if err != nil {
		t.Fatalf("mldsa.NewParameters(%v, %v) err = %v, want nil", instance, mldsa.VariantNoPrefix, err)
	}
	priv, err := keygenregistry.CreateKey(params, 0)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey(%v, 0) err = %v, want nil", params, err)
	}
	mldsaPriv := priv.(*mldsa.PrivateKey)
	pub, err := mldsaPriv.PublicKey()
	if err != nil {
		t.Fatalf("mldsaPriv.PublicKey() err = %v, want nil", err)
	}
	return mldsaPriv, pub.(*mldsa.PublicKey)
}

func generateClassicalKeyPair(t *testing.T, classicalAlgorithm compositemldsa.ClassicalAlgorithm, params key.Parameters) (key.Key, key.Key) {
	t.Helper()
	priv, err := keygenregistry.CreateKey(params, 0)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey for %v err = %v, want nil", classicalAlgorithm, err)
	}

	var pub key.Key
	switch classicalAlgorithm {
	case compositemldsa.Ed25519:
		pub, err = priv.(*ed25519.PrivateKey).PublicKey()
	case compositemldsa.ECDSAP256, compositemldsa.ECDSAP384, compositemldsa.ECDSAP521:
		pub, err = priv.(*ecdsa.PrivateKey).PublicKey()
	case compositemldsa.RSA3072PSS, compositemldsa.RSA4096PSS:
		pub, err = priv.(*rsassapss.PrivateKey).PublicKey()
	case compositemldsa.RSA3072PKCS1, compositemldsa.RSA4096PKCS1:
		pub, err = priv.(*rsassapkcs1.PrivateKey).PublicKey()
	}
	if err != nil {
		t.Fatalf("PublicKey for %v err = %v, want nil", classicalAlgorithm, err)
	}
	return priv, pub
}

type testParameters struct {
	classicalAlgorithm compositemldsa.ClassicalAlgorithm
	instance           compositemldsa.MLDSAInstance
	variant            compositemldsa.Variant
	classicalParams    key.Parameters
}

func mustNewED25519Parameters(t *testing.T) key.Parameters {
	t.Helper()
	params, err := ed25519.NewParameters(ed25519.VariantNoPrefix)
	if err != nil {
		t.Fatalf("ed25519.NewParameters(ed25519.VariantNoPrefix) err = %v, want nil", err)
	}
	return &params
}

func mustNewECDSAParameters(t *testing.T, curve ecdsa.CurveType, hashType ecdsa.HashType) key.Parameters {
	t.Helper()
	params, err := ecdsa.NewParameters(curve, hashType, ecdsa.DER, ecdsa.VariantNoPrefix)
	if err != nil {
		t.Fatalf("ecdsa.NewParameters(%v, %v, ecdsa.DER, ecdsa.VariantNoPrefix) err = %v, want nil", curve, hashType, err)
	}
	return params
}

func mustNewRSAPSSParameters(t *testing.T, modulusSizeBits int, sigHashType rsassapss.HashType, mgf1HashType rsassapss.HashType, saltLengthBytes int) key.Parameters {
	t.Helper()
	params, err := rsassapss.NewParameters(rsassapss.ParametersValues{
		ModulusSizeBits: modulusSizeBits,
		SigHashType:     sigHashType,
		MGF1HashType:    mgf1HashType,
		PublicExponent:  f4,
		SaltLengthBytes: saltLengthBytes,
	}, rsassapss.VariantNoPrefix)
	if err != nil {
		t.Fatalf("rsassapss.NewParameters err = %v, want nil", err)
	}
	return params
}

func mustNewRSAPKCS1Parameters(t *testing.T, modulusSizeBits int, hashType rsassapkcs1.HashType) key.Parameters {
	t.Helper()
	params, err := rsassapkcs1.NewParameters(modulusSizeBits, hashType, f4, rsassapkcs1.VariantNoPrefix)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewParameters err = %v, want nil", err)
	}
	return params
}

func testCasesSupportedParameters(t *testing.T) []testParameters {
	return []testParameters{
		// MLDSA65
		{
			classicalAlgorithm: compositemldsa.Ed25519,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantTink,
			classicalParams:    mustNewED25519Parameters(t),
		},
		{
			classicalAlgorithm: compositemldsa.Ed25519,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantNoPrefix,
			classicalParams:    mustNewED25519Parameters(t),
		},
		{
			classicalAlgorithm: compositemldsa.ECDSAP256,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantTink,
			classicalParams:    mustNewECDSAParameters(t, ecdsa.NistP256, ecdsa.SHA256),
		},
		{
			classicalAlgorithm: compositemldsa.ECDSAP256,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantNoPrefix,
			classicalParams:    mustNewECDSAParameters(t, ecdsa.NistP256, ecdsa.SHA256),
		},
		{
			classicalAlgorithm: compositemldsa.ECDSAP384,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantTink,
			classicalParams:    mustNewECDSAParameters(t, ecdsa.NistP384, ecdsa.SHA384),
		},
		{
			classicalAlgorithm: compositemldsa.ECDSAP384,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantNoPrefix,
			classicalParams:    mustNewECDSAParameters(t, ecdsa.NistP384, ecdsa.SHA384),
		},
		{
			classicalAlgorithm: compositemldsa.RSA3072PSS,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantTink,
			classicalParams:    mustNewRSAPSSParameters(t, 3072, rsassapss.SHA256, rsassapss.SHA256, 32),
		},
		{
			classicalAlgorithm: compositemldsa.RSA3072PSS,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantNoPrefix,
			classicalParams:    mustNewRSAPSSParameters(t, 3072, rsassapss.SHA256, rsassapss.SHA256, 32),
		},
		{
			classicalAlgorithm: compositemldsa.RSA4096PSS,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantTink,
			classicalParams:    mustNewRSAPSSParameters(t, 4096, rsassapss.SHA384, rsassapss.SHA384, 48),
		},
		{
			classicalAlgorithm: compositemldsa.RSA4096PSS,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantNoPrefix,
			classicalParams:    mustNewRSAPSSParameters(t, 4096, rsassapss.SHA384, rsassapss.SHA384, 48),
		},
		{
			classicalAlgorithm: compositemldsa.RSA3072PKCS1,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantTink,
			classicalParams:    mustNewRSAPKCS1Parameters(t, 3072, rsassapkcs1.SHA256),
		},
		{
			classicalAlgorithm: compositemldsa.RSA3072PKCS1,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantNoPrefix,
			classicalParams:    mustNewRSAPKCS1Parameters(t, 3072, rsassapkcs1.SHA256),
		},
		{
			classicalAlgorithm: compositemldsa.RSA4096PKCS1,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantTink,
			classicalParams:    mustNewRSAPKCS1Parameters(t, 4096, rsassapkcs1.SHA384),
		},
		{
			classicalAlgorithm: compositemldsa.RSA4096PKCS1,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantNoPrefix,
			classicalParams:    mustNewRSAPKCS1Parameters(t, 4096, rsassapkcs1.SHA384),
		},
		// MLDSA87
		{
			classicalAlgorithm: compositemldsa.ECDSAP384,
			instance:           compositemldsa.MLDSA87,
			variant:            compositemldsa.VariantTink,
			classicalParams:    mustNewECDSAParameters(t, ecdsa.NistP384, ecdsa.SHA384),
		},
		{
			classicalAlgorithm: compositemldsa.ECDSAP384,
			instance:           compositemldsa.MLDSA87,
			variant:            compositemldsa.VariantNoPrefix,
			classicalParams:    mustNewECDSAParameters(t, ecdsa.NistP384, ecdsa.SHA384),
		},
		{
			classicalAlgorithm: compositemldsa.ECDSAP521,
			instance:           compositemldsa.MLDSA87,
			variant:            compositemldsa.VariantTink,
			classicalParams:    mustNewECDSAParameters(t, ecdsa.NistP521, ecdsa.SHA512),
		},
		{
			classicalAlgorithm: compositemldsa.ECDSAP521,
			instance:           compositemldsa.MLDSA87,
			variant:            compositemldsa.VariantNoPrefix,
			classicalParams:    mustNewECDSAParameters(t, ecdsa.NistP521, ecdsa.SHA512),
		},
		{
			classicalAlgorithm: compositemldsa.RSA3072PSS,
			instance:           compositemldsa.MLDSA87,
			variant:            compositemldsa.VariantTink,
			classicalParams:    mustNewRSAPSSParameters(t, 3072, rsassapss.SHA256, rsassapss.SHA256, 32),
		},
		{
			classicalAlgorithm: compositemldsa.RSA3072PSS,
			instance:           compositemldsa.MLDSA87,
			variant:            compositemldsa.VariantNoPrefix,
			classicalParams:    mustNewRSAPSSParameters(t, 3072, rsassapss.SHA256, rsassapss.SHA256, 32),
		},
		{
			classicalAlgorithm: compositemldsa.RSA4096PSS,
			instance:           compositemldsa.MLDSA87,
			variant:            compositemldsa.VariantTink,
			classicalParams:    mustNewRSAPSSParameters(t, 4096, rsassapss.SHA384, rsassapss.SHA384, 48),
		},
		{
			classicalAlgorithm: compositemldsa.RSA4096PSS,
			instance:           compositemldsa.MLDSA87,
			variant:            compositemldsa.VariantNoPrefix,
			classicalParams:    mustNewRSAPSSParameters(t, 4096, rsassapss.SHA384, rsassapss.SHA384, 48),
		},
	}
}

func TestNewParametersSupported(t *testing.T) {
	for _, tc := range testCasesSupportedParameters(t) {
		params, err := compositemldsa.NewParameters(tc.classicalAlgorithm, tc.instance, tc.variant)
		if err != nil {
			t.Errorf("compositemldsa.NewParameters(%v, %v, %v) err = %v, want nil", tc.classicalAlgorithm, tc.instance, tc.variant, err)
		}
		if got := params.ClassicalAlgorithm(); got != tc.classicalAlgorithm {
			t.Errorf("params.ClassicalAlgorithm() = %v, want %v", got, tc.classicalAlgorithm)
		}
		if got := params.MLDSAInstance(); got != tc.instance {
			t.Errorf("params.MlDsaInstance() = %v, want %v", got, tc.instance)
		}
		if got := params.Variant(); got != tc.variant {
			t.Errorf("params.Variant() = %v, want %v", got, tc.variant)
		}
	}
}

func TestNewParametersUnsupported(t *testing.T) {
	tests := []struct {
		classicalAlgorithm compositemldsa.ClassicalAlgorithm
		instance           compositemldsa.MLDSAInstance
		variant            compositemldsa.Variant
	}{
		// Unknown
		{compositemldsa.UnknownAlgorithm, compositemldsa.MLDSA65, compositemldsa.VariantTink},
		{compositemldsa.Ed25519, compositemldsa.UnknownInstance, compositemldsa.VariantTink},
		{compositemldsa.Ed25519, compositemldsa.MLDSA65, compositemldsa.VariantUnknown},
		// MLDSA65 unsupported
		{compositemldsa.ECDSAP521, compositemldsa.MLDSA65, compositemldsa.VariantTink},
		// MLDSA87 unsupported
		{compositemldsa.Ed25519, compositemldsa.MLDSA87, compositemldsa.VariantTink},
		{compositemldsa.ECDSAP256, compositemldsa.MLDSA87, compositemldsa.VariantTink},
		{compositemldsa.RSA3072PKCS1, compositemldsa.MLDSA87, compositemldsa.VariantTink},
		{compositemldsa.RSA4096PKCS1, compositemldsa.MLDSA87, compositemldsa.VariantTink},
	}
	for _, tc := range tests {
		_, err := compositemldsa.NewParameters(tc.classicalAlgorithm, tc.instance, tc.variant)
		if err == nil {
			t.Errorf("compositemldsa.NewParameters(%v, %v, %v) err = nil, want error", tc.classicalAlgorithm, tc.instance, tc.variant)
		}
	}
}

func TestParametersEqual(t *testing.T) {
	for _, classicalAlgorithm := range []compositemldsa.ClassicalAlgorithm{
		compositemldsa.RSA3072PSS,
		compositemldsa.ECDSAP384,
	} {
		for _, instance := range []compositemldsa.MLDSAInstance{
			compositemldsa.MLDSA65,
			compositemldsa.MLDSA87,
		} {
			t.Run(fmt.Sprintf("%v/%v", classicalAlgorithm, instance), func(t *testing.T) {
				tinkParams, err := compositemldsa.NewParameters(classicalAlgorithm, instance, compositemldsa.VariantTink)
				if err != nil {
					t.Fatalf("NewParameters(classicalAlgorithm, instance, compositemldsa.VariantTink) err = %v", err)
				}
				noPrefixParams, err := compositemldsa.NewParameters(classicalAlgorithm, instance, compositemldsa.VariantNoPrefix)
				if err != nil {
					t.Fatalf("NewParameters(classicalAlgorithm, instance, compositemldsa.VariantNoPrefix) err = %v", err)
				}
				if !tinkParams.Equal(tinkParams) {
					t.Errorf("tinkParams.Equal(tinkParams) = false, want true")
				}
				if !noPrefixParams.Equal(noPrefixParams) {
					t.Errorf("noPrefixParams.Equal(noPrefixParams) = false, want true")
				}
				if tinkParams.Equal(noPrefixParams) {
					t.Errorf("tinkParams.Equal(noPrefixParams) = true, want false")
				}
			})
		}
	}
	// Test inequality for different classical algorithms and instances.
	p1, err := compositemldsa.NewParameters(compositemldsa.Ed25519, compositemldsa.MLDSA65, compositemldsa.VariantTink)
	if err != nil {
		t.Fatalf("%v", err)
	}
	p2, err := compositemldsa.NewParameters(compositemldsa.ECDSAP384, compositemldsa.MLDSA65, compositemldsa.VariantTink)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if p1.Equal(p2) {
		t.Errorf("p1.Equal(p2) = true, want false")
	}
	p3, err := compositemldsa.NewParameters(compositemldsa.ECDSAP384, compositemldsa.MLDSA87, compositemldsa.VariantTink)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if p2.Equal(p3) {
		t.Errorf("p1.Equal(p3) = true, want false")
	}
}

func TestNewPublicKeySuccess(t *testing.T) {
	for _, tc := range testCasesSupportedParameters(t) {
		testName := fmt.Sprintf("%v-%v-%v", tc.classicalAlgorithm, tc.instance, tc.variant)
		t.Run(testName, func(t *testing.T) {
			params, err := compositemldsa.NewParameters(tc.classicalAlgorithm, tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("compositemldsa.NewParameters(%v, %v, %v) err = %v, want nil", tc.classicalAlgorithm, tc.instance, tc.variant, err)
			}
			_, mldsaPubKey := generateMLDSAKeyPair(t, tc.instance)
			_, classicalPubKey := generateClassicalKeyPair(t, tc.classicalAlgorithm, tc.classicalParams)
			const keyID = uint32(0x12345678)
			pubKey, err := compositemldsa.NewPublicKey(mldsaPubKey, classicalPubKey, keyID, params)
			if err != nil {
				t.Fatalf("compositemldsa.NewPublicKey(%v, %v, %v, %v) err = %v, want nil", mldsaPubKey, classicalPubKey, keyID, params, err)
			}
			if !pubKey.Parameters().Equal(params) {
				t.Errorf("pubKey.Parameters() = %v, want %v", pubKey.Parameters(), params)
			}
			if gotID, gotOK := pubKey.IDRequirement(); gotOK != params.HasIDRequirement() || (gotOK && gotID != keyID) {
				t.Errorf("pubKey.IDRequirement() = %v, %v, want %v, %v", gotID, gotOK, keyID, params.HasIDRequirement())
			}
			if !pubKey.ClassicalPublicKey().Equal(classicalPubKey) {
				t.Errorf("pubKey.ClassicalPublicKey() = %v, want %v", pubKey.ClassicalPublicKey(), classicalPubKey)
			}
			if !pubKey.MLDSAPublicKey().Equal(mldsaPubKey) {
				t.Errorf("pubKey.MLDSAPublicKey() = %v, want %v", pubKey.MLDSAPublicKey(), mldsaPubKey)
			}
			var expectedOutputPrefix []byte
			if params.Variant() == compositemldsa.VariantTink {
				expectedOutputPrefix = outputprefix.Tink(keyID)
			}
			if !bytes.Equal(pubKey.OutputPrefix(), expectedOutputPrefix) {
				t.Errorf("pubKey.OutputPrefix() = %v, want %v", pubKey.OutputPrefix(), expectedOutputPrefix)
			}
		})
	}
}

func TestNewPublicKeyEquals(t *testing.T) {
	for _, tc := range testCasesSupportedParameters(t) {
		testName := fmt.Sprintf("%v-%v-%v", tc.classicalAlgorithm, tc.instance, tc.variant)
		t.Run(testName, func(t *testing.T) {
			params, err := compositemldsa.NewParameters(tc.classicalAlgorithm, tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("compositemldsa.NewParameters(%v, %v, %v) err = %v, want nil", tc.classicalAlgorithm, tc.instance, tc.variant, err)
			}
			_, mldsaPubKey := generateMLDSAKeyPair(t, tc.instance)
			_, classicalPubKey := generateClassicalKeyPair(t, tc.classicalAlgorithm, tc.classicalParams)
			keyID := uint32(0x12345678)
			pubKey, err := compositemldsa.NewPublicKey(mldsaPubKey, classicalPubKey, keyID, params)
			if err != nil {
				t.Fatalf("compositemldsa.NewPublicKey(%v, %v, %v, %v) err = %v, want nil", mldsaPubKey, classicalPubKey, keyID, params, err)
			}
			if !pubKey.Equal(pubKey) {
				t.Errorf("pubKey.Equal(pubKey) = false, want true")
			}
		})
	}
}

func TestNewPublicKeyMismatchClassicalParameters(t *testing.T) {
	tests := []struct {
		name               string
		classicalAlgorithm compositemldsa.ClassicalAlgorithm
		instance           compositemldsa.MLDSAInstance
		variant            compositemldsa.Variant
		keyAlgorithm       compositemldsa.ClassicalAlgorithm
		classicalParams    key.Parameters
	}{
		{
			name:               "Ed25519 params with ECDSAP256 key",
			classicalAlgorithm: compositemldsa.Ed25519,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantTink,
			keyAlgorithm:       compositemldsa.ECDSAP256,
			classicalParams:    mustNewECDSAParameters(t, ecdsa.NistP256, ecdsa.SHA256),
		},
		{
			name:               "ECDSAP256 params with Ed25519 key",
			classicalAlgorithm: compositemldsa.ECDSAP256,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantTink,
			keyAlgorithm:       compositemldsa.Ed25519,
			classicalParams:    mustNewED25519Parameters(t),
		},
		{
			name:               "ECDSAP384 params with ECDSAP256 key",
			classicalAlgorithm: compositemldsa.ECDSAP384,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantTink,
			keyAlgorithm:       compositemldsa.ECDSAP256,
			classicalParams:    mustNewECDSAParameters(t, ecdsa.NistP256, ecdsa.SHA256),
		},
		{
			name:               "RSA3072PSS params with RSA3072PKCS1 key",
			classicalAlgorithm: compositemldsa.RSA3072PSS,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantTink,
			keyAlgorithm:       compositemldsa.RSA3072PKCS1,
			classicalParams:    mustNewRSAPKCS1Parameters(t, 3072, rsassapkcs1.SHA256),
		},
		{
			name:               "RSA3072PKCS1 params with RSA3072PSS key",
			classicalAlgorithm: compositemldsa.RSA3072PKCS1,
			instance:           compositemldsa.MLDSA65,
			variant:            compositemldsa.VariantTink,
			keyAlgorithm:       compositemldsa.RSA3072PSS,
			classicalParams:    mustNewRSAPSSParameters(t, 3072, rsassapss.SHA256, rsassapss.SHA256, 32),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params, err := compositemldsa.NewParameters(tc.classicalAlgorithm, tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("compositemldsa.NewParameters(%v, %v, %v) err = %v, want nil", tc.classicalAlgorithm, tc.instance, tc.variant, err)
			}
			_, mlDSAPubKey := generateMLDSAKeyPair(t, tc.instance)
			_, classicalPubKey := generateClassicalKeyPair(t, tc.keyAlgorithm, tc.classicalParams)
			keyID := uint32(0x12345678)
			_, err = compositemldsa.NewPublicKey(mlDSAPubKey, classicalPubKey, keyID, params)
			if err == nil {
				t.Errorf("compositemldsa.NewPublicKey(%v, %v, %v, %v) err = nil, want error", mlDSAPubKey, classicalPubKey, keyID, params)
			}
		})
	}
}

func TestNewPublicKeyRSAPSSInvalidPublicExponent(t *testing.T) {
	params, err := compositemldsa.NewParameters(compositemldsa.RSA3072PSS, compositemldsa.MLDSA65, compositemldsa.VariantTink)
	if err != nil {
		t.Fatalf("compositemldsa.NewParameters(compositemldsa.RSA3072PSS, compositemldsa.MLDSA65, compositemldsa.VariantTink) err = %v, want nil", err)
	}
	_, mldsaPubKey := generateMLDSAKeyPair(t, compositemldsa.MLDSA65)
	classicalPriv, _ := generateClassicalKeyPair(t, compositemldsa.RSA3072PSS, mustNewRSAPSSParameters(t, 3072, rsassapss.SHA256, rsassapss.SHA256, 32))

	// Create a new classical public key with an invalid public exponent.
	classicalPubKeyHandle, err := classicalPriv.(*rsassapss.PrivateKey).PublicKey()
	if err != nil {
		t.Fatalf("classicalPriv.PublicKey() err = %v, want nil", err)
	}
	classicalPubKey := classicalPubKeyHandle.(*rsassapss.PublicKey)
	classicalParams := classicalPubKey.Parameters().(*rsassapss.Parameters)
	newClassicalParams, err := rsassapss.NewParameters(rsassapss.ParametersValues{
		ModulusSizeBits: classicalParams.ModulusSizeBits(),
		SigHashType:     classicalParams.SigHashType(),
		MGF1HashType:    classicalParams.MGF1HashType(),
		PublicExponent:  f4 + 2, // Invalid public exponent.
		SaltLengthBytes: classicalParams.SaltLengthBytes(),
	}, classicalParams.Variant())
	if err != nil {
		t.Fatalf("rsassapss.NewParameters err = %v, want nil", err)
	}
	newClassicalPubKey, err := rsassapss.NewPublicKey(classicalPubKey.Modulus(), 0, newClassicalParams)
	if err != nil {
		t.Fatalf("rsassapss.NewPublicKey err = %v, want nil", err)
	}

	keyID := uint32(0x12345678)
	_, err = compositemldsa.NewPublicKey(mldsaPubKey, newClassicalPubKey, keyID, params)
	if err == nil {
		t.Errorf("compositemldsa.NewPublicKey(%v, %v, %v, %v) err = nil, want error", mldsaPubKey, newClassicalPubKey, keyID, params)
	}
}

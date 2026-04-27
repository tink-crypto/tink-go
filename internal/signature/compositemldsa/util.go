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

// Package compositemldsa provides internal utility functions for Composite ML-DSA.
package compositemldsa

import (
	"crypto/sha512"
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/signature/ed25519"
	"github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapss"
)

// MLDSAInstance is the instance type of the ML-DSA key.
type MLDSAInstance int

const (
	// UnknownInstance is the default value of MLDSAInstance.
	UnknownInstance MLDSAInstance = iota
	// MLDSA65 yields ML-DSA-65 parameters.
	MLDSA65
	// MLDSA87 yields ML-DSA-87 parameters.
	MLDSA87
)

// ClassicalAlgorithm is the description of the classical algorithm.
type ClassicalAlgorithm int

const (
	// UnknownAlgorithm is the default value of ClassicalAlgorithm.
	UnknownAlgorithm ClassicalAlgorithm = iota
	// Ed25519 is the Ed25519 algorithm.
	Ed25519
	// ECDSAP256 is the ECDSA-P256 algorithm.
	ECDSAP256
	// ECDSAP384 is the ECDSA-P384 algorithm.
	ECDSAP384
	// ECDSAP521 is the ECDSA-P521 algorithm.
	ECDSAP521
	// RSA3072PSS is the RSA-3072-PSS algorithm.
	RSA3072PSS
	// RSA4096PSS is the RSA-4096-PSS algorithm.
	RSA4096PSS
	// RSA3072PKCS1 is the RSA-3072-PKCS1 algorithm.
	RSA3072PKCS1
	// RSA4096PKCS1 is the RSA-4096-PKCS1 algorithm.
	RSA4096PKCS1
)

// Variant describes the output prefix mode.
type Variant int

const (
	// UnknownVariant is the default value of Variant.
	UnknownVariant Variant = iota
	// VariantTink describes keys with 5 bytes output prefix.
	VariantTink
	// VariantNoPrefix describes keys with no output prefix.
	VariantNoPrefix
)

// ComputeLabel returns the label for the given ML-DSA instance and classical algorithm.
func ComputeLabel(mlDSAInstance MLDSAInstance, classicalAlgorithm ClassicalAlgorithm) (string, error) {
	label := "COMPSIG-"
	switch mlDSAInstance {
	case MLDSA65:
		label += "MLDSA65"
	case MLDSA87:
		label += "MLDSA87"
	default:
		return "", fmt.Errorf("MLDSA instance is not supported: %v", mlDSAInstance)
	}
	label += "-"
	switch classicalAlgorithm {
	case Ed25519:
		label += "Ed25519"
	case ECDSAP256:
		label += "ECDSA-P256"
	case ECDSAP384:
		label += "ECDSA-P384"
	case ECDSAP521:
		label += "ECDSA-P521"
	case RSA3072PSS:
		label += "RSA3072-PSS"
	case RSA4096PSS:
		label += "RSA4096-PSS"
	case RSA3072PKCS1:
		label += "RSA3072-PKCS15"
	case RSA4096PKCS1:
		label += "RSA4096-PKCS15"
	default:
		return "", fmt.Errorf("classical algorithm is not supported: %v", classicalAlgorithm)
	}
	// All of the currently supported classical algorithms use SHA512 as pre-hash.
	label += "-SHA512"
	return label, nil
}

// ComputeMessagePrime computes the message prime for Composite ML-DSA.
func ComputeMessagePrime(label string, message []byte) []byte {
	// Context is fixed at \x00.
	// M' = Prefix || Label || len(ctx) || ctx || PH( M )
	prefix := []byte("CompositeAlgorithmSignatures2025")
	hash := sha512.Sum512(message)
	return slices.Concat(prefix, []byte(label), []byte{byte(0)}, hash[:])
}

// ParametersForClassicalAlgorithm returns the parameters for the given classical algorithm.
func ParametersForClassicalAlgorithm(classicalAlgorithm ClassicalAlgorithm) (key.Parameters, error) {
	switch classicalAlgorithm {
	case Ed25519:
		params, err := ed25519.NewParameters(ed25519.VariantNoPrefix)
		if err != nil {
			return nil, err
		}
		return &params, nil
	case ECDSAP256:
		return ecdsa.NewParameters(ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantNoPrefix)
	case ECDSAP384:
		return ecdsa.NewParameters(ecdsa.NistP384, ecdsa.SHA384, ecdsa.DER, ecdsa.VariantNoPrefix)
	case ECDSAP521:
		return ecdsa.NewParameters(ecdsa.NistP521, ecdsa.SHA512, ecdsa.DER, ecdsa.VariantNoPrefix)
	case RSA3072PSS:
		return rsassapss.NewParameters(rsassapss.ParametersValues{
			ModulusSizeBits: 3072,
			SigHashType:     rsassapss.SHA256,
			MGF1HashType:    rsassapss.SHA256,
			PublicExponent:  65537,
			SaltLengthBytes: 32,
		}, rsassapss.VariantNoPrefix)
	case RSA4096PSS:
		return rsassapss.NewParameters(rsassapss.ParametersValues{
			ModulusSizeBits: 4096,
			SigHashType:     rsassapss.SHA384,
			MGF1HashType:    rsassapss.SHA384,
			PublicExponent:  65537,
			SaltLengthBytes: 48,
		}, rsassapss.VariantNoPrefix)
	case RSA3072PKCS1:
		return rsassapkcs1.NewParameters(3072, rsassapkcs1.SHA256, 65537, rsassapkcs1.VariantNoPrefix)
	case RSA4096PKCS1:
		return rsassapkcs1.NewParameters(4096, rsassapkcs1.SHA384, 65537, rsassapkcs1.VariantNoPrefix)
	default:
		return nil, fmt.Errorf("unsupported classical algorithm: %v", classicalAlgorithm)
	}
}

// ParametersForMLDSA returns the parameters for the given ML-DSA instance.
func ParametersForMLDSA(mlDSAInstance MLDSAInstance) (*mldsa.Parameters, error) {
	switch mlDSAInstance {
	case MLDSA65:
		return mldsa.NewParameters(mldsa.MLDSA65, mldsa.VariantNoPrefix)
	case MLDSA87:
		return mldsa.NewParameters(mldsa.MLDSA87, mldsa.VariantNoPrefix)
	default:
		return nil, fmt.Errorf("unsupported ML-DSA instance: %v", mlDSAInstance)
	}
}

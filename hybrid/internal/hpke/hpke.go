// Copyright 2021 Google LLC
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

// Package hpke provides implementations of Hybrid Public Key Encryption.
package hpke

import (
	"encoding/binary"
	"errors"
	"fmt"

	hpkepb "github.com/tink-crypto/tink-go/v2/proto/hpke_go_proto"
)

const (
	// All identifier values are specified in
	// https://www.rfc-editor.org/rfc/rfc9180.html.
	// Mode identifiers.
	baseMode uint8 = 0x00

	// KEM algorithm identifiers.
	p256HKDFSHA256   uint16 = 0x0010
	p384HKDFSHA384   uint16 = 0x0011
	p521HKDFSHA512   uint16 = 0x0012
	x25519HKDFSHA256 uint16 = 0x0020

	// KDF algorithm identifiers.
	hkdfSHA256 uint16 = 0x0001
	hkdfSHA384 uint16 = 0x0002
	hkdfSHA512 uint16 = 0x0003

	// AEAD algorithm identifiers.
	aes128GCM        uint16 = 0x0001
	aes256GCM        uint16 = 0x0002
	chaCha20Poly1305 uint16 = 0x0003

	sha256 = "SHA256"
	sha384 = "SHA384"
	sha512 = "SHA512"
	hpkeV1 = "HPKE-v1"
)

var (
	// KEM lengths from https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1
	kemLengths = map[uint16]struct {
		nSecret, nEnc, nPK, nSK int
	}{
		p256HKDFSHA256:   {nSecret: 32, nEnc: 65, nPK: 65, nSK: 32},
		p384HKDFSHA384:   {nSecret: 48, nEnc: 97, nPK: 97, nSK: 48},
		p521HKDFSHA512:   {nSecret: 64, nEnc: 133, nPK: 133, nSK: 66},
		x25519HKDFSHA256: {nSecret: 32, nEnc: 32, nPK: 32, nSK: 32},
	}

	errInvalidHPKEParams           = errors.New("invalid HPKE parameters")
	errInvalidHPKEPrivateKeyLength = errors.New("invalid HPKE private key length")
	errInvalidHPKEPublicKeyLength  = errors.New("invalid HPKE public key length")

	emptySalt           = []byte{}
	emptyIKM            = []byte{}
	emptyAssociatedData = []byte{}
)

// kemSuiteID generates the KEM suite ID from kemID according to
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1-5.
func kemSuiteID(kemID uint16) []byte {
	return binary.BigEndian.AppendUint16([]byte("KEM"), kemID)
}

// hpkeSuiteID generates the HPKE suite ID according to
// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1-8.
func hpkeSuiteID(kemID, kdfID, aeadID uint16) []byte {
	// Allocate memory for the return value with the exact amount of bytes needed.
	res := make([]byte, 0, 4+2+2+2)
	res = append(res, "HPKE"...)
	res = binary.BigEndian.AppendUint16(res, kemID)
	res = binary.BigEndian.AppendUint16(res, kdfID)
	res = binary.BigEndian.AppendUint16(res, aeadID)
	return res
}

// keyScheduleContext creates the key_schedule_context defined at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1-10.
func keyScheduleContext(mode uint8, pskIDHash, infoHash []byte) []byte {
	// Allocate memory for the return value with the exact amount of bytes needed.
	res := make([]byte, 0, 1+len(pskIDHash)+len(infoHash))
	res = append(res, mode)
	res = append(res, pskIDHash...)
	res = append(res, infoHash...)
	return res
}

// labelIKM returns a labeled IKM according to LabeledExtract() defined at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4.
func labelIKM(label string, ikm, suiteID []byte) []byte {
	// Allocate memory for the return value with the exact amount of bytes needed.
	res := make([]byte, 0, len(hpkeV1)+len(suiteID)+len(label)+len(ikm))
	res = append(res, hpkeV1...)
	res = append(res, suiteID...)
	res = append(res, label...)
	res = append(res, ikm...)
	return res
}

// labelInfo returns a labeled info according to LabeledExpand() defined at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4.
func labelInfo(label string, info, suiteID []byte, length int) ([]byte, error) {
	length16 := uint16(length)
	if int(length16) != length {
		return nil, fmt.Errorf("length %d must be a valid uint16 value", length)
	}

	// Allocate memory for the return value with the exact amount of bytes needed.
	res := make([]byte, 0, 2+len(hpkeV1)+len(suiteID)+len(label)+len(info))
	res = binary.BigEndian.AppendUint16(res, length16)
	res = append(res, hpkeV1...)
	res = append(res, suiteID...)
	res = append(res, label...)
	res = append(res, info...)
	return res, nil
}

// ValidatePrivateKeyLength validates the length of the private key.
func ValidatePrivateKeyLength(key *hpkepb.HpkePrivateKey) error {
	kemID, err := kemIDFromProto(key.GetPublicKey().GetParams().GetKem())
	if err != nil {
		return err
	}
	lengths, ok := kemLengths[kemID]
	if !ok {
		return errInvalidHPKEParams
	}
	if lengths.nSK != len(key.GetPrivateKey()) {
		return errInvalidHPKEPrivateKeyLength
	}
	return nil
}

// ValidatePublicKeyLength validates the length of the public key.
func ValidatePublicKeyLength(key *hpkepb.HpkePublicKey) error {
	kemID, err := kemIDFromProto(key.GetParams().GetKem())
	if err != nil {
		return err
	}
	lengths, ok := kemLengths[kemID]
	if !ok {
		return errInvalidHPKEParams
	}
	if lengths.nPK != len(key.GetPublicKey()) {
		return errInvalidHPKEPublicKeyLength
	}
	return nil
}

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

package hpke

import (
	"fmt"

	"crypto/mlkem"
)

// mlKEM implements interface kem for ML-KEM.
type mlKEM struct {
	// HPKE KEM algorithm identifier.
	kemID KEMID
}

var _ kem = (*mlKEM)(nil)

func newMLKEM(kemID KEMID) (*mlKEM, error) {
	switch kemID {
	case MLKEM768:
		return &mlKEM{kemID: MLKEM768}, nil
	case MLKEM1024:
		return &mlKEM{kemID: MLKEM1024}, nil
	default:
		return nil, fmt.Errorf("KEM ID %d is not supported", kemID)
	}
}

func (m *mlKEM) encapsulate(recipientPubKey []byte) (sharedSecret, senderPubKey []byte, err error) {
	switch m.kemID {
	case MLKEM768:
		ek, err := mlkem.NewEncapsulationKey768(recipientPubKey)
		if err != nil {
			return nil, nil, err
		}
		sharedSecret, ciphertext := ek.Encapsulate()
		return sharedSecret, ciphertext, nil
	case MLKEM1024:
		ek, err := mlkem.NewEncapsulationKey1024(recipientPubKey)
		if err != nil {
			return nil, nil, err
		}
		sharedSecret, ciphertext := ek.Encapsulate()
		return sharedSecret, ciphertext, nil
	default:
		return nil, nil, fmt.Errorf("KEM ID %d is not supported", m.kemID)
	}
}

func (m *mlKEM) decapsulate(encapsulatedKey, recipientPrivKey []byte) ([]byte, error) {
	switch m.kemID {
	case MLKEM768:
		dk, err := mlkem.NewDecapsulationKey768(recipientPrivKey)
		if err != nil {
			return nil, err
		}
		return dk.Decapsulate(encapsulatedKey)
	case MLKEM1024:
		dk, err := mlkem.NewDecapsulationKey1024(recipientPrivKey)
		if err != nil {
			return nil, err
		}
		return dk.Decapsulate(encapsulatedKey)
	default:
		return nil, fmt.Errorf("KEM ID %d is not supported", m.kemID)
	}
}

func (m *mlKEM) id() KEMID { return m.kemID }

func (m *mlKEM) encapsulatedKeyLength() int { return kemLengths[m.kemID].nEnc }

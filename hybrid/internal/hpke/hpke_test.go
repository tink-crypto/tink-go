// Copyright 2022 Google LLC
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
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/tink-crypto/tink-go/v2/testutil"
	hpkepb "github.com/tink-crypto/tink-go/v2/proto/hpke_go_proto"
)

// TODO: b/201070904 - Separate tests into internal_test package.

// aeadIDs are specified at
// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3.
var aeadIDs = []struct {
	name      string
	aeadID    uint16
	keyLength int
}{
	{"AES128GCM", aes128GCM, 16},
	{"AES256GCM", aes256GCM, 32},
	{"ChaCha20Poly1305", chaCha20Poly1305, 32},
}

type hpkeID struct {
	id     int
	mode   uint8
	kemID  uint16
	kdfID  uint16
	aeadID uint16
}

type vector struct {
	info                   []byte
	senderPubKey           []byte
	senderPrivKey          []byte
	recipientPubKey        []byte
	recipientPrivKey       []byte
	encapsulatedKey        []byte
	sharedSecret           []byte
	keyScheduleCtx         []byte
	secret                 []byte
	key                    []byte
	baseNonce              []byte
	consecutiveEncryptions []encryptionVector
	otherEncryptions       []encryptionVector
}

type encryptionVector struct {
	key            []byte
	plaintext      []byte
	associatedData []byte
	nonce          []byte
	ciphertext     []byte
	sequenceNumber *big.Int
}

type encryptionString struct {
	sequenceNumber uint64
	plaintext      string
	associatedData string
	nonce          string
	ciphertext     string
}

type hpkeRFCTestVector struct {
	mode                                                                                    uint8
	kemID, kdfID, aeadID                                                                    uint16
	info, pkEm, skEm, pkRm, skRm, enc, sharedSecret, keyScheduleCtx, secret, key, baseNonce string
	consecutiveEncryptions, otherEncryptions                                                []encryptionString
}

// TODO: b/201070904 - Include all Tink-supported RFC vectors.
func rfcVectorA1(t *testing.T) (hpkeID, vector) {
	// Test vector from HPKE RFC
	// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1.
	v := hpkeRFCTestVector{
		mode:           0,
		kemID:          32,
		kdfID:          1,
		aeadID:         1,
		info:           "4f6465206f6e2061204772656369616e2055726e",
		pkEm:           "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
		skEm:           "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
		pkRm:           "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
		skRm:           "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
		enc:            "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
		sharedSecret:   "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
		keyScheduleCtx: "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449",
		secret:         "12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397",
		key:            "4531685d41d65f03dc48f6b8302c05b0",
		baseNonce:      "56d890e5accaaf011cff4b7d",
		consecutiveEncryptions: []encryptionString{
			{
				sequenceNumber: 0,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d30",
				nonce:          "56d890e5accaaf011cff4b7d",
				ciphertext:     "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
			},
			{
				sequenceNumber: 1,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d31",
				nonce:          "56d890e5accaaf011cff4b7c",
				ciphertext:     "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
			},
			{
				sequenceNumber: 2,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d32",
				nonce:          "56d890e5accaaf011cff4b7f",
				ciphertext:     "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180",
			},
		},
		otherEncryptions: []encryptionString{
			{
				sequenceNumber: 4,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d34",
				nonce:          "56d890e5accaaf011cff4b79",
				ciphertext:     "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d",
			},
			{
				sequenceNumber: 255,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d323535",
				nonce:          "56d890e5accaaf011cff4b82",
				ciphertext:     "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a",
			},
			{
				sequenceNumber: 256,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d323536",
				nonce:          "56d890e5accaaf011cff4a7d",
				ciphertext:     "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2",
			},
		},
	}

	return rfcVector(t, v)
}

func rfcVectorA3(t *testing.T) (hpkeID, vector) {
	// Test vector from HPKE RFC
	// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.3.1.
	v := hpkeRFCTestVector{
		mode:           0,
		kemID:          16,
		kdfID:          1,
		aeadID:         1,
		info:           "4f6465206f6e2061204772656369616e2055726e",
		pkEm:           "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
		skEm:           "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
		pkRm:           "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
		skRm:           "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
		enc:            "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
		sharedSecret:   "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8",
		keyScheduleCtx: "00b88d4e6d91759e65e87c470e8b9141113e9ad5f0c8ceefc1e088c82e6980500798e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85",
		secret:         "2eb7b6bf138f6b5aff857414a058a3f1750054a9ba1f72c2cf0684a6f20b10e1",
		key:            "868c066ef58aae6dc589b6cfdd18f97e",
		baseNonce:      "4e0bc5018beba4bf004cca59",
		consecutiveEncryptions: []encryptionString{
			{
				sequenceNumber: 0,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d30",
				nonce:          "4e0bc5018beba4bf004cca59",
				ciphertext:     "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434",
			},
			{
				sequenceNumber: 1,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d31",
				nonce:          "4e0bc5018beba4bf004cca58",
				ciphertext:     "fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82",
			},
			{
				sequenceNumber: 2,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d32",
				nonce:          "4e0bc5018beba4bf004cca5b",
				ciphertext:     "895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb55fed7a7fec",
			},
		},
		otherEncryptions: []encryptionString{
			{
				sequenceNumber: 4,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d34",
				nonce:          "4e0bc5018beba4bf004cca5d",
				ciphertext:     "8787491ee8df99bc99a246c4b3216d3d57ab5076e18fa27133f520703bc70ec999dd36ce042e44f0c3169a6a8f",
			},
			{
				sequenceNumber: 255,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d323535",
				nonce:          "4e0bc5018beba4bf004ccaa6",
				ciphertext:     "2ad71c85bf3f45c6eca301426289854b31448bcf8a8ccb1deef3ebd87f60848aa53c538c30a4dac71d619ee2cd",
			},
			{
				sequenceNumber: 256,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d323536",
				nonce:          "4e0bc5018beba4bf004ccb59",
				ciphertext:     "10f179686aa2caec1758c8e554513f16472bd0a11e2a907dde0b212cbe87d74f367f8ffe5e41cd3e9962a6afb2",
			},
		},
	}

	return rfcVector(t, v)
}

func rfcVectorA6(t *testing.T) (hpkeID, vector) {
	// Test vector from HPKE RFC
	// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.6.1.
	v := hpkeRFCTestVector{
		mode:           0,
		kemID:          18,
		kdfID:          3,
		aeadID:         2,
		info:           "4f6465206f6e2061204772656369616e2055726e",
		pkEm:           "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0",
		skEm:           "014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d535415a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b",
		pkRm:           "0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464b57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64",
		skRm:           "01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847",
		enc:            "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0",
		sharedSecret:   "776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1d5e43653336fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46d30e818",
		keyScheduleCtx: "0083a27c5b2358ab4dae1b2f5d8f57f10ccccc822a473326f543f239a70aee46347324e84e02d7651a10d08fb3dda739d22d50c53fbfa8122baacd0f9ae5913072ef45baa1f3a4b169e141feb957e48d03f28c837d8904c3d6775308c3d3faa75dd64adfa44e1a1141edf9349959b8f8e5291cbdc56f62b0ed6527d692e85b09a4",
		secret:         "49fd9f53b0f93732555b2054edfdc0e3101000d75df714b98ce5aa295a37f1b18dfa86a1c37286d805d3ea09a20b72f93c21e83955a1f01eb7c5eead563d21e7",
		key:            "751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70",
		baseNonce:      "55ff7a7d739c69f44b25447b",
		consecutiveEncryptions: []encryptionString{
			{
				sequenceNumber: 0,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d30",
				nonce:          "55ff7a7d739c69f44b25447b",
				ciphertext:     "170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a",
			},
			{
				sequenceNumber: 1,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d31",
				nonce:          "55ff7a7d739c69f44b25447a",
				ciphertext:     "d9ee248e220ca24ac00bbbe7e221a832e4f7fa64c4fbab3945b6f3af0c5ecd5e16815b328be4954a05fd352256",
			},
			{
				sequenceNumber: 2,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d32",
				nonce:          "55ff7a7d739c69f44b254479",
				ciphertext:     "142cf1e02d1f58d9285f2af7dcfa44f7c3f2d15c73d460c48c6e0e506a3144bae35284e7e221105b61d24e1c7a",
			},
		},
		otherEncryptions: []encryptionString{
			{
				sequenceNumber: 4,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d34",
				nonce:          "55ff7a7d739c69f44b25447f",
				ciphertext:     "3bb3a5a07100e5a12805327bf3b152df728b1c1be75a9fd2cb2bf5eac0cca1fb80addb37eb2a32938c7268e3e5",
			},
			{
				sequenceNumber: 255,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d323535",
				nonce:          "55ff7a7d739c69f44b254484",
				ciphertext:     "4f268d0930f8d50b8fd9d0f26657ba25b5cb08b308c92e33382f369c768b558e113ac95a4c70dd60909ad1adc7",
			},
			{
				sequenceNumber: 256,
				plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
				associatedData: "436f756e742d323536",
				nonce:          "55ff7a7d739c69f44b25457b",
				ciphertext:     "dbbfc44ae037864e75f136e8b4b4123351d480e6619ae0e0ae437f036f2f8f1ef677686323977a1ccbb4b4f16a",
			},
		},
	}

	return rfcVector(t, v)
}

func rfcVector(t *testing.T, v hpkeRFCTestVector) (hpkeID, vector) {
	t.Helper()

	var info, senderPubKey, senderPrivKey, recipientPubKey, recipientPrivKey, encapsulatedKey, sharedSecret, keyScheduleCtx, secret, key, baseNonce []byte
	var err error
	if info, err = hex.DecodeString(v.info); err != nil {
		t.Fatalf("hex.DecodeString(info): err %q", err)
	}
	if senderPubKey, err = hex.DecodeString(v.pkEm); err != nil {
		t.Fatalf("hex.DecodeString(pkEm): err %q", err)
	}
	if senderPrivKey, err = hex.DecodeString(v.skEm); err != nil {
		t.Fatalf("hex.DecodeString(skEm): err %q", err)
	}
	if recipientPubKey, err = hex.DecodeString(v.pkRm); err != nil {
		t.Fatalf("hex.DecodeString(pkRm): err %q", err)
	}
	if recipientPrivKey, err = hex.DecodeString(v.skRm); err != nil {
		t.Fatalf("hex.DecodeString(skRm): err %q", err)
	}
	if encapsulatedKey, err = hex.DecodeString(v.enc); err != nil {
		t.Fatalf("hex.DecodeString(enc): err %q", err)
	}
	if sharedSecret, err = hex.DecodeString(v.sharedSecret); err != nil {
		t.Fatalf("hex.DecodeString(sharedSecret): err %q", err)
	}
	if keyScheduleCtx, err = hex.DecodeString(v.keyScheduleCtx); err != nil {
		t.Fatalf("hex.DecodeString(keyScheduleCtx): err %q", err)
	}
	if secret, err = hex.DecodeString(v.secret); err != nil {
		t.Fatalf("hex.DecodeString(secret): err %q", err)
	}
	if key, err = hex.DecodeString(v.key); err != nil {
		t.Fatalf("hex.DecodeString(key): err %q", err)
	}
	if baseNonce, err = hex.DecodeString(v.baseNonce); err != nil {
		t.Fatalf("hex.DecodeString(baseNonce): err %q", err)
	}

	return hpkeID{0 /*=id */, v.mode, v.kemID, v.kdfID, v.aeadID},
		vector{
			info:                   info,
			senderPubKey:           senderPubKey,
			senderPrivKey:          senderPrivKey,
			recipientPubKey:        recipientPubKey,
			recipientPrivKey:       recipientPrivKey,
			encapsulatedKey:        encapsulatedKey,
			sharedSecret:           sharedSecret,
			keyScheduleCtx:         keyScheduleCtx,
			secret:                 secret,
			key:                    key,
			baseNonce:              baseNonce,
			consecutiveEncryptions: parseEncryptions(t, v.consecutiveEncryptions),
			otherEncryptions:       parseEncryptions(t, v.otherEncryptions),
		}
}

func parseEncryptions(t *testing.T, encs []encryptionString) []encryptionVector {
	t.Helper()

	var res []encryptionVector
	for _, e := range encs {
		var plaintext, associatedData, nonce, ciphertext []byte
		var err error
		if plaintext, err = hex.DecodeString(e.plaintext); err != nil {
			t.Fatalf("hex.DecodeString(plaintext): err %q", err)
		}
		if associatedData, err = hex.DecodeString(e.associatedData); err != nil {
			t.Fatalf("hex.DecodeString(associatedData): err %q", err)
		}
		if nonce, err = hex.DecodeString(e.nonce); err != nil {
			t.Fatalf("hex.DecodeString(nonce): err %q", err)
		}
		if ciphertext, err = hex.DecodeString(e.ciphertext); err != nil {
			t.Fatalf("hex.DecodeString(ciphertext): err %q", err)
		}

		res = append(res, encryptionVector{
			plaintext:      plaintext,
			associatedData: associatedData,
			nonce:          nonce,
			ciphertext:     ciphertext,
			sequenceNumber: big.NewInt(int64(e.sequenceNumber)),
		})
	}

	return res
}

// aeadRFCVectors returns RFC test vectors for AEAD IDs aes128GCM, aes256GCM,
// and chaCha20Poly1305.
func aeadRFCVectors(t *testing.T) map[hpkeID]encryptionVector {
	t.Helper()

	vecs := []struct {
		mode                                              uint8
		kemID, kdfID, aeadID                              uint16
		key, plaintext, associatedData, nonce, ciphertext string
	}{
		// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1.1
		{
			mode:           0,
			kemID:          32,
			kdfID:          1,
			aeadID:         1,
			key:            "4531685d41d65f03dc48f6b8302c05b0",
			plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
			associatedData: "436f756e742d30",
			nonce:          "56d890e5accaaf011cff4b7d",
			ciphertext:     "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
		},
		{
			mode:           0,
			kemID:          32,
			kdfID:          1,
			aeadID:         1,
			key:            "4531685d41d65f03dc48f6b8302c05b0",
			plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
			associatedData: "436f756e742d31",
			nonce:          "56d890e5accaaf011cff4b7c",
			ciphertext:     "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
		},
		// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.6.1.1
		{
			mode:           0,
			kemID:          18,
			kdfID:          3,
			aeadID:         2,
			key:            "751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70",
			plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
			associatedData: "436f756e742d30",
			nonce:          "55ff7a7d739c69f44b25447b",
			ciphertext:     "170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a",
		},
		{
			mode:           0,
			kemID:          18,
			kdfID:          3,
			aeadID:         2,
			key:            "751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70",
			plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
			associatedData: "436f756e742d31",
			nonce:          "55ff7a7d739c69f44b25447a",
			ciphertext:     "d9ee248e220ca24ac00bbbe7e221a832e4f7fa64c4fbab3945b6f3af0c5ecd5e16815b328be4954a05fd352256",
		},
		// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.2.1.1
		{
			mode:           0,
			kemID:          32,
			kdfID:          1,
			aeadID:         3,
			key:            "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
			plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
			associatedData: "436f756e742d30",
			nonce:          "5c4d98150661b848853b547f",
			ciphertext:     "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
		},
		{
			mode:           0,
			kemID:          32,
			kdfID:          1,
			aeadID:         3,
			key:            "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
			plaintext:      "4265617574792069732074727574682c20747275746820626561757479",
			associatedData: "436f756e742d31",
			nonce:          "5c4d98150661b848853b547e",
			ciphertext:     "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c",
		},
	}

	m := make(map[hpkeID]encryptionVector)
	for i, v := range vecs {
		var key, plaintext, associatedData, nonce, ciphertext []byte
		var err error
		if key, err = hex.DecodeString(v.key); err != nil {
			t.Fatalf("hex.DecodeString(key): err %q", err)
		}
		if plaintext, err = hex.DecodeString(v.plaintext); err != nil {
			t.Fatalf("hex.DecodeString(plaintext): err %q", err)
		}
		if associatedData, err = hex.DecodeString(v.associatedData); err != nil {
			t.Fatalf("hex.DecodeString(associatedData): err %q", err)
		}
		if nonce, err = hex.DecodeString(v.nonce); err != nil {
			t.Fatalf("hex.DecodeString(nonce): err %q", err)
		}
		if ciphertext, err = hex.DecodeString(v.ciphertext); err != nil {
			t.Fatalf("hex.DecodeString(ciphertext): err %q", err)
		}

		id := hpkeID{i, v.mode, v.kemID, v.kdfID, v.aeadID}
		m[id] = encryptionVector{
			key:            key,
			plaintext:      plaintext,
			associatedData: associatedData,
			nonce:          nonce,
			ciphertext:     ciphertext,
		}
	}

	return m
}

const testVectorsDir = "testdata/testvectors"

// hpke_boringssl.json contains 128 test vectors.
// There are 4 KEMs with 32 vectors each: P-256, P-521, X25519, X448.
// There are no test vectors for P-384.
func getTestVectorsFilePath(t *testing.T) string {
	t.Helper()
	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if ok {
		workspaceDir, ok := os.LookupEnv("TEST_WORKSPACE")
		if !ok {
			t.Fatal("TEST_WORKSPACE not found")
		}
		return filepath.Join(srcDir, workspaceDir, testVectorsDir, "hpke_boringssl.json")
	}
	return filepath.Join("../../../", testVectorsDir, "hpke_boringssl.json")
}

// hpkeBaseModeVectors returns BoringSSL test vectors for HPKE base mode.
func hpkeBaseModeVectors(t *testing.T) map[hpkeID]vector {
	t.Helper()

	f, err := os.Open(getTestVectorsFilePath(t))
	if err != nil {
		t.Fatal(err)
	}

	var vecs []struct {
		Mode             uint8             `json:"mode"`
		KEMID            uint16            `json:"kem_id"`
		KDFID            uint16            `json:"kdf_id"`
		AEADID           uint16            `json:"aead_id"`
		Info             testutil.HexBytes `json:"info"`
		SenderPubKey     testutil.HexBytes `json:"pkEm"`
		SenderPrivKey    testutil.HexBytes `json:"skEm"`
		RecipientPubKey  testutil.HexBytes `json:"pkRm"`
		RecipientPrivKey testutil.HexBytes `json:"skRm"`
		EncapsulatedKey  testutil.HexBytes `json:"enc"`
		SharedSecret     testutil.HexBytes `json:"shared_secret"`
		KeyScheduleCtx   testutil.HexBytes `json:"key_schedule_context"`
		Secret           testutil.HexBytes `json:"secret"`
		Key              testutil.HexBytes `json:"key"`
		BaseNonce        testutil.HexBytes `json:"base_nonce"`
	}
	parser := json.NewDecoder(f)
	if err := parser.Decode(&vecs); err != nil {
		t.Fatal(err)
	}

	m := make(map[hpkeID]vector)
	for i, v := range vecs {
		if v.Mode != baseMode {
			continue
		}

		id := hpkeID{i, v.Mode, v.KEMID, v.KDFID, v.AEADID}
		m[id] = vector{
			info:             v.Info,
			senderPubKey:     v.SenderPubKey,
			senderPrivKey:    v.SenderPrivKey,
			recipientPubKey:  v.RecipientPubKey,
			recipientPrivKey: v.RecipientPrivKey,
			encapsulatedKey:  v.EncapsulatedKey,
			sharedSecret:     v.SharedSecret,
			keyScheduleCtx:   v.KeyScheduleCtx,
			secret:           v.Secret,
			key:              v.Key,
			baseNonce:        v.BaseNonce,
		}
	}

	return m
}

func TestHpkeSuiteIDMemoryAllocatedIsExact(t *testing.T) {
	suiteID := hpkeSuiteID(1, 2, 3)
	if len(suiteID) != cap(suiteID) {
		t.Errorf("want len(suiteID) == cap(suiteID), got %d != %d", len(suiteID), cap(suiteID))
	}
}

func TestKeyScheduleContextMemoryAllocatedIsExact(t *testing.T) {
	context := keyScheduleContext(1, []byte{1, 2, 3}, []byte{1, 2, 3, 4, 5})
	if len(context) != cap(context) {
		t.Errorf("want len(context) == cap(context), got %d != %d", len(context), cap(context))
	}
}

func TestLabelIKMMemoryAllocatedIsExact(t *testing.T) {
	ikm := labelIKM("abcde", []byte{1, 2, 3}, []byte{1, 2, 3, 4, 5})
	if len(ikm) != cap(ikm) {
		t.Errorf("want len(ikm) == cap(ikm), got %d != %d", len(ikm), cap(ikm))
	}
}

func TestLabelInfoMemoryAllocatedIsExact(t *testing.T) {
	info, err := labelInfo("abcde", []byte{1, 2, 3}, []byte{1, 2, 3, 4, 5}, 42)
	if err != nil {
		t.Errorf("labelInfo() err = %v, want nil", err)
	}
	if len(info) != cap(info) {
		t.Errorf("want len(info) == cap(info), got %d != %d", len(info), cap(info))
	}
}

func TestValidatePrivateKeyLength(t *testing.T) {
	tests := []struct {
		name string
		key  *hpkepb.HpkePrivateKey
	}{
		{
			name: "DHKEM_P256_HKDF_SHA256",
			key: &hpkepb.HpkePrivateKey{
				PublicKey: &hpkepb.HpkePublicKey{
					Params: &hpkepb.HpkeParams{
						Kem: hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256,
					},
				},
				PrivateKey: make([]byte, kemLengths[p256HKDFSHA256].nSK),
			},
		},
		{
			name: "DHKEM_P384_HKDF_SHA384",
			key: &hpkepb.HpkePrivateKey{
				PublicKey: &hpkepb.HpkePublicKey{
					Params: &hpkepb.HpkeParams{
						Kem: hpkepb.HpkeKem_DHKEM_P384_HKDF_SHA384,
					},
				},
				PrivateKey: make([]byte, kemLengths[p384HKDFSHA384].nSK),
			},
		},
		{
			name: "DHKEM_P521_HKDF_SHA512",
			key: &hpkepb.HpkePrivateKey{
				PublicKey: &hpkepb.HpkePublicKey{
					Params: &hpkepb.HpkeParams{
						Kem: hpkepb.HpkeKem_DHKEM_P521_HKDF_SHA512,
					},
				},
				PrivateKey: make([]byte, kemLengths[p521HKDFSHA512].nSK),
			},
		},
		{
			name: "DHKEM_X25519_HKDF_SHA256",
			key: &hpkepb.HpkePrivateKey{
				PublicKey: &hpkepb.HpkePublicKey{
					Params: &hpkepb.HpkeParams{
						Kem: hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
					},
				},
				PrivateKey: make([]byte, kemLengths[x25519HKDFSHA256].nSK),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidatePrivateKeyLength(test.key); err != nil {
				t.Errorf("ValidatePrivateKeyLength(): got %v, want nil", err)
			}
		})
	}
}

func TestValidatePrivateKeyLengthErrors(t *testing.T) {
	tests := []struct {
		name string
		key  *hpkepb.HpkePrivateKey
	}{
		{
			name: "Missing private key",
			key: &hpkepb.HpkePrivateKey{
				PublicKey: &hpkepb.HpkePublicKey{
					Params: &hpkepb.HpkeParams{
						Kem: hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
					},
				},
			},
		},
		{
			name: "Missing public key",
			key: &hpkepb.HpkePrivateKey{
				PrivateKey: []byte{},
			},
		},
		{
			name: "Zero length private key",
			key: &hpkepb.HpkePrivateKey{
				PublicKey: &hpkepb.HpkePublicKey{
					Params: &hpkepb.HpkeParams{
						Kem: hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
					},
				},
				PrivateKey: []byte{},
			},
		},
		{
			name: "Wrong length private key",
			key: &hpkepb.HpkePrivateKey{
				PublicKey: &hpkepb.HpkePublicKey{
					Params: &hpkepb.HpkeParams{
						Kem: hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
					},
				},
				PrivateKey: make([]byte, kemLengths[x25519HKDFSHA256].nSK+1),
			},
		},
		{
			name: "Invalid KEM",
			key: &hpkepb.HpkePrivateKey{
				PublicKey: &hpkepb.HpkePublicKey{
					Params: &hpkepb.HpkeParams{
						Kem: hpkepb.HpkeKem_KEM_UNKNOWN,
					},
				},
				PrivateKey: make([]byte, kemLengths[x25519HKDFSHA256].nSK),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidatePrivateKeyLength(test.key); err == nil {
				t.Errorf("ValidatePrivateKeyLength(): got nil, want error")
			}
		})
	}
}

func TestValidatePublicKeyLength(t *testing.T) {
	tests := []struct {
		name string
		key  *hpkepb.HpkePublicKey
	}{
		{
			name: "DHKEM_P256_HKDF_SHA256",
			key: &hpkepb.HpkePublicKey{
				Params: &hpkepb.HpkeParams{
					Kem: hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256,
				},
				PublicKey: make([]byte, kemLengths[p256HKDFSHA256].nPK),
			},
		},
		{
			name: "DHKEM_P384_HKDF_SHA384",
			key: &hpkepb.HpkePublicKey{
				Params: &hpkepb.HpkeParams{
					Kem: hpkepb.HpkeKem_DHKEM_P384_HKDF_SHA384,
				},
				PublicKey: make([]byte, kemLengths[p384HKDFSHA384].nPK),
			},
		},
		{
			name: "DHKEM_P521_HKDF_SHA512",
			key: &hpkepb.HpkePublicKey{
				Params: &hpkepb.HpkeParams{
					Kem: hpkepb.HpkeKem_DHKEM_P521_HKDF_SHA512,
				},
				PublicKey: make([]byte, kemLengths[p521HKDFSHA512].nPK),
			},
		},
		{
			name: "DHKEM_X25519_HKDF_SHA256",
			key: &hpkepb.HpkePublicKey{
				Params: &hpkepb.HpkeParams{
					Kem: hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
				},
				PublicKey: make([]byte, kemLengths[x25519HKDFSHA256].nPK),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidatePublicKeyLength(test.key); err != nil {
				t.Errorf("ValidatePublicKeyLength(): got %v, want nil", err)
			}
		})
	}
}

func TestValidatePublicKeyLengthErrors(t *testing.T) {
	tests := []struct {
		name string
		key  *hpkepb.HpkePublicKey
	}{
		{
			name: "Missing public key",
			key: &hpkepb.HpkePublicKey{
				Params: &hpkepb.HpkeParams{
					Kem: hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
				},
			},
		},
		{
			name: "Zero length public key",
			key: &hpkepb.HpkePublicKey{
				Params: &hpkepb.HpkeParams{
					Kem: hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
				},
				PublicKey: []byte{},
			},
		},
		{
			name: "Wrong length public key",
			key: &hpkepb.HpkePublicKey{
				Params: &hpkepb.HpkeParams{
					Kem: hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
				},
				PublicKey: make([]byte, kemLengths[x25519HKDFSHA256].nPK+1),
			},
		},
		{
			name: "Invalid KEM",
			key: &hpkepb.HpkePublicKey{
				Params: &hpkepb.HpkeParams{
					Kem: hpkepb.HpkeKem_KEM_UNKNOWN,
				},
				PublicKey: make([]byte, kemLengths[x25519HKDFSHA256].nPK),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidatePublicKeyLength(test.key); err == nil {
				t.Errorf("ValidatePublicKeyLength(): got nil, want error")
			}
		})
	}
}

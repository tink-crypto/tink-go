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

package streamingprf

import (
	"errors"
	"fmt"
	"io"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// New generates a new instance of the Streaming PRF primitive.
func New(h *keyset.Handle) (StreamingPRF, error) {
	ps, err := keyset.PrimitivesWithKeyManager[StreamingPRF](h, new(HKDFStreamingPRFKeyManager), internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("streaming_prf_factory: cannot obtain primitive set: %v", err)
	}
	return newWrappedStreamingPRF(ps)
}

// wrappedStreamingPRF is a Streaming PRF implementation that uses the underlying primitive set for Streaming PRF.
type wrappedStreamingPRF struct {
	ps *primitiveset.PrimitiveSet[StreamingPRF]
}

// Asserts that wrappedStreamingPRF implements the StreamingPRF interface.
var _ StreamingPRF = (*wrappedStreamingPRF)(nil)

func newWrappedStreamingPRF(ps *primitiveset.PrimitiveSet[StreamingPRF]) (*wrappedStreamingPRF, error) {
	if rawEntries, err := ps.RawEntries(); err != nil || len(rawEntries) != 1 {
		return nil, errors.New("streaming_prf_factory: only accepts keysets with 1 RAW key")
	}
	// ps.Entries is a map of prefix type -> []*Entry.
	if len(ps.Entries) != 1 {
		return nil, errors.New("streaming_prf_factory: only accepts keys with prefix type RAW")
	}
	if ps.Primary.PrefixType != tinkpb.OutputPrefixType_RAW {
		return nil, errors.New("streaming_prf_factory: primary key prefix type is not RAW")
	}
	if ps.Primary.Status != tinkpb.KeyStatusType_ENABLED {
		return nil, errors.New("streaming_prf_factory: primary key is not ENABLED")
	}
	return &wrappedStreamingPRF{ps: ps}, nil
}

func (w *wrappedStreamingPRF) Compute(input []byte) (io.Reader, error) {
	return w.ps.Primary.Primitive.Compute(input)
}

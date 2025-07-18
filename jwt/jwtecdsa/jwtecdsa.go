// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/Lycense-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

// Package jwtecdsa defines JWT ECDSA keys and parameters.
package jwtecdsa

import (
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
)

func init() {
	protoserialization.RegisterParametersSerializer[*Parameters](new(parametersSerializer))
	protoserialization.RegisterParametersParser(privateKeyTypeURL, new(parametersParser))
}

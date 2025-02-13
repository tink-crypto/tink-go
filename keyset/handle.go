// Copyright 2019 Google LLC
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

package keyset

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/tink"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var errInvalidKeyset = fmt.Errorf("keyset.Handle: invalid keyset")

// Handle provides access to a keyset to limit the exposure of the internal
// keyset representation, which may hold sensitive key material.
type Handle struct {
	entries          []*Entry
	annotations      map[string]string
	keysetHasSecrets bool // Whether the keyset contains secret key material.
	primaryKeyEntry  *Entry
}

// KeyStatus is the key status.
type KeyStatus int

const (
	// Unknown is the default invalid value.
	Unknown KeyStatus = iota
	// Enabled means the key is enabled.
	Enabled
	// Disabled means the key is disabled.
	Disabled
	// Destroyed means the key is marked for destruction.
	Destroyed
)

// String implements fmt.Stringer.
func (ks KeyStatus) String() string {
	switch ks {
	case Enabled:
		return "Enabled"
	case Disabled:
		return "Disabled"
	case Destroyed:
		return "Destroyed"
	default:
		return "Unknown"
	}
}

// Entry represents an entry in a keyset.
type Entry struct {
	// Object that represents a full Tink key, i.e., key material, parameters and algorithm.
	key       key.Key
	isPrimary bool
	keyID     uint32
	status    KeyStatus
}

// Key returns the key.
func (e *Entry) Key() key.Key {
	return e.key
}

// IsPrimary returns true if the key is the primary key.
func (e *Entry) IsPrimary() bool {
	return e.isPrimary
}

// KeyID returns the key ID.
func (e *Entry) KeyID() uint32 {
	return e.keyID
}

// KeyStatus returns the key status.
func (e *Entry) KeyStatus() KeyStatus {
	return e.status
}

func keyStatusFromProto(status tinkpb.KeyStatusType) (KeyStatus, error) {
	switch status {
	case tinkpb.KeyStatusType_ENABLED:
		return Enabled, nil
	case tinkpb.KeyStatusType_DISABLED:
		return Disabled, nil
	case tinkpb.KeyStatusType_DESTROYED:
		return Destroyed, nil
	default:
		return Unknown, fmt.Errorf("unknown key status: %v", status)
	}
}

func keyStatusToProto(status KeyStatus) (tinkpb.KeyStatusType, error) {
	switch status {
	case Enabled:
		return tinkpb.KeyStatusType_ENABLED, nil
	case Disabled:
		return tinkpb.KeyStatusType_DISABLED, nil
	case Destroyed:
		return tinkpb.KeyStatusType_DESTROYED, nil
	default:
		return tinkpb.KeyStatusType_UNKNOWN_STATUS, fmt.Errorf("unknown key status: %v", status)
	}
}

// entryToProtoKey converts an Entry to a tinkpb.Keyset_Key. Assumes entry is not nil.
func entryToProtoKey(entry *Entry) (*tinkpb.Keyset_Key, error) {
	protoKeyStatus, err := keyStatusToProto(entry.KeyStatus())
	if err != nil {
		return nil, err
	}
	protoKeySerialization, err := protoserialization.SerializeKey(entry.Key())
	if err != nil {
		return nil, err
	}
	return &tinkpb.Keyset_Key{
		KeyId:            entry.KeyID(),
		Status:           protoKeyStatus,
		OutputPrefixType: protoKeySerialization.OutputPrefixType(),
		KeyData:          protoKeySerialization.KeyData(),
	}, nil
}

func entriesToProtoKeyset(entries []*Entry) (*tinkpb.Keyset, error) {
	if entries == nil {
		return nil, fmt.Errorf("entriesToProtoKeyset called with nil")
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("entries is empty")
	}
	protoKeyset := &tinkpb.Keyset{}
	for _, entry := range entries {
		protoKey, err := entryToProtoKey(entry)
		if err != nil {
			return nil, err
		}
		protoKeyset.Key = append(protoKeyset.Key, protoKey)
		if entry.IsPrimary() {
			protoKeyset.PrimaryKeyId = entry.KeyID()
		}
	}
	return protoKeyset, nil
}

func newWithOptions(ks *tinkpb.Keyset, opts ...Option) (*Handle, error) {
	if err := Validate(ks); err != nil {
		return nil, fmt.Errorf("invalid keyset: %v", err)
	}
	entries := make([]*Entry, len(ks.GetKey()))
	var primaryKeyEntry *Entry = nil
	for i, protoKey := range ks.GetKey() {
		protoKeyData := protoKey.GetKeyData()
		keyID := protoKey.GetKeyId()
		if protoKey.GetOutputPrefixType() == tinkpb.OutputPrefixType_RAW {
			keyID = 0
		}
		protoKeySerialization, err := protoserialization.NewKeySerialization(protoKeyData, protoKey.GetOutputPrefixType(), keyID)
		if err != nil {
			return nil, err
		}
		key, err := protoserialization.ParseKey(protoKeySerialization)
		if err != nil {
			return nil, err
		}
		keyStatus, err := keyStatusFromProto(protoKey.GetStatus())
		if err != nil {
			return nil, err
		}
		entries[i] = &Entry{
			key:       key,
			isPrimary: protoKey.GetKeyId() == ks.GetPrimaryKeyId(),
			keyID:     protoKey.GetKeyId(),
			status:    keyStatus,
		}
		if protoKey.GetKeyId() == ks.GetPrimaryKeyId() {
			primaryKeyEntry = entries[i]
		}
	}
	h := &Handle{
		entries:          entries,
		keysetHasSecrets: hasSecrets(ks),
		primaryKeyEntry:  primaryKeyEntry,
	}
	if err := applyOptions(h, opts...); err != nil {
		return nil, err
	}
	return h, nil
}

// NewHandle creates a keyset handle that contains a single fresh key generated according
// to the given KeyTemplate.
func NewHandle(kt *tinkpb.KeyTemplate) (*Handle, error) {
	manager := NewManager()
	keyID, err := manager.Add(kt)
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: cannot generate new keyset: %s", err)
	}
	err = manager.SetPrimary(keyID)
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: cannot set primary: %s", err)
	}
	handle, err := manager.Handle()
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: cannot get keyset handle: %s", err)
	}
	return handle, nil
}

// NewHandleWithNoSecrets creates a new instance of KeysetHandle from the
// the given keyset which does not contain any secret key material.
func NewHandleWithNoSecrets(ks *tinkpb.Keyset) (*Handle, error) {
	handle, err := newWithOptions(ks)
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: cannot generate new keyset: %s", err)
	}
	if handle.keysetHasSecrets {
		// If you need to do this, you have to use func insecurecleartextkeyset.Read() instead.
		return nil, errors.New("keyset.Handle: importing unencrypted secret key material is forbidden")
	}
	return handle, nil
}

// Read tries to create a Handle from an encrypted keyset obtained via reader.
func Read(reader Reader, masterKey tink.AEAD) (*Handle, error) {
	return ReadWithAssociatedData(reader, masterKey, []byte{})
}

// ReadWithAssociatedData tries to create a Handle from an encrypted keyset obtained via reader using the provided associated data.
func ReadWithAssociatedData(reader Reader, masterKey tink.AEAD, associatedData []byte) (*Handle, error) {
	encryptedKeyset, err := reader.ReadEncrypted()
	if err != nil {
		return nil, err
	}
	protoKeyset, err := decrypt(encryptedKeyset, masterKey, associatedData)
	if err != nil {
		return nil, err
	}
	return newWithOptions(protoKeyset)
}

// ReadWithContext creates a keyset.Handle from an encrypted keyset obtained via
// reader using the provided AEADWithContext.
func ReadWithContext(ctx context.Context, reader Reader, keyEncryptionAEAD tink.AEADWithContext, associatedData []byte) (*Handle, error) {
	encryptedKeyset, err := reader.ReadEncrypted()
	if err != nil {
		return nil, err
	}
	protoKeyset, err := decryptWithContext(ctx, encryptedKeyset, keyEncryptionAEAD, associatedData)
	if err != nil {
		return nil, err
	}
	return newWithOptions(protoKeyset)
}

// ReadWithNoSecrets tries to create a keyset.Handle from a keyset obtained via reader.
func ReadWithNoSecrets(reader Reader) (*Handle, error) {
	protoKeyset, err := reader.Read()
	if err != nil {
		return nil, err
	}
	return NewHandleWithNoSecrets(protoKeyset)
}

// Primary returns the primary key of the keyset.
func (h *Handle) Primary() (*Entry, error) {
	if h == nil {
		return nil, fmt.Errorf("keyset.Handle: nil handle")
	}
	if h.primaryKeyEntry == nil {
		return nil, fmt.Errorf("keyset.Handle: no primary key")
	}
	return h.primaryKeyEntry, nil
}

// Entry returns the key at index i from the keyset.
// i must be within the range [0, Handle.Len()).
func (h *Handle) Entry(i int) (*Entry, error) {
	if h == nil {
		return nil, fmt.Errorf("keyset.Handle: nil handle")
	}
	if i < 0 || i >= h.Len() {
		return nil, fmt.Errorf("keyset.Handle: index %d out of range", i)
	}
	return h.entries[i], nil
}

// privateKey represents a key with a public key.
type privateKey interface {
	PublicKey() (key.Key, error)
}

// Public returns a Handle of the public keys if the managed keyset contains private keys.
func (h *Handle) Public() (*Handle, error) {
	if h == nil {
		return nil, fmt.Errorf("keyset.Handle: nil handle")
	}
	if h.Len() == 0 {
		return nil, fmt.Errorf("keyset.Handle: entries list is empty or nil")
	}
	entries := make([]*Entry, h.Len())
	var primaryKeyEntry *Entry = nil
	for i, entry := range h.entries {
		privateKey, ok := entry.Key().(privateKey)
		if !ok {
			return nil, fmt.Errorf("keyset.Handle: keyset contains a non-private key")
		}
		publicKey, err := privateKey.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("keyset.Handle: %v", err)
		}
		entries[i] = &Entry{
			key:       publicKey,
			isPrimary: entry.isPrimary,
			keyID:     entry.keyID,
			status:    entry.status,
		}
		if entry.isPrimary {
			primaryKeyEntry = entries[i]
		}
	}
	return &Handle{
		entries:          entries,
		keysetHasSecrets: false,
		primaryKeyEntry:  primaryKeyEntry,
	}, nil
}

// String returns a string representation of the managed keyset.
// The result does not contain any sensitive key material.
func (h *Handle) String() string {
	c, err := prototext.MarshalOptions{}.Marshal(h.KeysetInfo())
	if err != nil {
		return ""
	}
	return string(c)
}

// Len returns the number of keys in the keyset.
func (h *Handle) Len() int {
	if h == nil {
		return 0
	}
	return len(h.entries)
}

// KeysetInfo returns KeysetInfo representation of the managed keyset.
// The result does not contain any sensitive key material.
func (h *Handle) KeysetInfo() *tinkpb.KeysetInfo {
	return getKeysetInfo(keysetMaterial(h))
}

// Write encrypts and writes the enclosing keyset.
func (h *Handle) Write(writer Writer, masterKey tink.AEAD) error {
	if h == nil {
		return fmt.Errorf("keyset.Handle: nil handle")
	}
	return h.WriteWithAssociatedData(writer, masterKey, []byte{})
}

// WriteWithAssociatedData encrypts and writes the enclosing keyset using the provided associated data.
func (h *Handle) WriteWithAssociatedData(writer Writer, masterKey tink.AEAD, associatedData []byte) error {
	if h == nil {
		return fmt.Errorf("keyset.Handle: nil handle")
	}
	protoKeyset, err := entriesToProtoKeyset(h.entries)
	if err != nil {
		return err
	}
	encrypted, err := encrypt(protoKeyset, masterKey, associatedData)
	if err != nil {
		return err
	}
	return writer.WriteEncrypted(encrypted)
}

// WriteWithContext encrypts and writes the keyset using the provided AEADWithContext.
func (h *Handle) WriteWithContext(ctx context.Context, writer Writer, keyEncryptionAEAD tink.AEADWithContext, associatedData []byte) error {
	if h == nil {
		return fmt.Errorf("keyset.Handle: nil handle")
	}
	protoKeyset, err := entriesToProtoKeyset(h.entries)
	if err != nil {
		return fmt.Errorf("keyset.Handle: %v", err)
	}
	encrypted, err := encryptWithContext(ctx, protoKeyset, keyEncryptionAEAD, associatedData)
	if err != nil {
		return fmt.Errorf("keyset.Handle: %v", err)
	}
	return writer.WriteEncrypted(encrypted)
}

// WriteWithNoSecrets exports the keyset in h to the given Writer w returning an error if the keyset
// contains secret key material.
func (h *Handle) WriteWithNoSecrets(w Writer) error {
	if h == nil {
		return fmt.Errorf("keyset.Handle: nil handle")
	}
	if h.keysetHasSecrets {
		return errors.New("keyset.Handle: exporting unencrypted secret key material is forbidden")
	}
	protoKeyset, err := entriesToProtoKeyset(h.entries)
	if err != nil {
		return err
	}
	return w.Write(protoKeyset)
}

// Config defines methods in the config.Config concrete type that are used by keyset.Handle.
// The config.Config concrete type is not used directly due to circular dependencies.
type Config interface {
	PrimitiveFromKeyData(keyData *tinkpb.KeyData, _ internalapi.Token) (any, error)
	// PrimitiveFromKey creates a primitive from a [key.Key].
	PrimitiveFromKey(key key.Key, _ internalapi.Token) (any, error)
}

type primitiveOptions struct {
	config Config
}

// PrimitivesOption is used to configure Primitives(...).
type PrimitivesOption func(*primitiveOptions) error

// WithConfig sets the configuration used to create primitives via Primitives().
// If this option is omitted, default to using the global registry.
func WithConfig(c Config) PrimitivesOption {
	return func(args *primitiveOptions) error {
		if args.config != nil {
			return fmt.Errorf("configuration has already been set")
		}
		args.config = c
		return nil
	}
}

// Primitives creates a set of primitives corresponding to the keys with
// status=ENABLED in the keyset of the given keyset handle. It uses the
// key managers that are present in the global Registry or in the Config,
// should it be provided. It assumes that all the needed key managers are
// present. Keys with status!=ENABLED are skipped.
//
// An example usage where a custom config is provided:
//
//	ps, err := h.Primitives(WithConfig(config.V0()))
//
// The returned set is usually later "wrapped" into a class that implements
// the corresponding Primitive-interface.
//
// NOTE: This is an internal API.
func Primitives[T any](h *Handle, _ internalapi.Token, opts ...PrimitivesOption) (*primitiveset.PrimitiveSet[T], error) {
	p, err := primitives[T](h, nil, opts...)
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: %v", err)
	}
	return p, nil
}

// PrimitivesWithKeyManager creates a set of primitives corresponding to
// the keys with status=ENABLED in the keyset of the given keysetHandle, using
// the given key manager (instead of registered key managers) for keys supported
// by it.  Keys not supported by the key manager are handled by matching registered
// key managers (if present), and keys with status!=ENABLED are skipped.
//
// This enables custom treatment of keys, for example providing extra context
// (e.g. credentials for accessing keys managed by a KMS), or gathering custom
// monitoring/profiling information.
//
// The returned set is usually later "wrapped" into a class that implements
// the corresponding Primitive-interface.
//
// NOTE: This is an internal API.
func PrimitivesWithKeyManager[T any](h *Handle, km registry.KeyManager, _ internalapi.Token) (*primitiveset.PrimitiveSet[T], error) {
	p, err := primitives[T](h, km)
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: %v", err)
	}
	return p, nil
}

func addToPrimitiveSet[T any](primitiveSet *primitiveset.PrimitiveSet[T], entry *Entry, km registry.KeyManager, config Config) (*primitiveset.Entry[T], error) {
	protoKey, err := entryToProtoKey(entry)
	if err != nil {
		return nil, err
	}
	var primitive any
	isFullPrimitive := false
	if km != nil && km.DoesSupport(protoKey.GetKeyData().GetTypeUrl()) {
		primitive, err = km.Primitive(protoKey.GetKeyData().GetValue())
		if err != nil {
			return nil, fmt.Errorf("cannot get primitive from key: %v", err)
		}
	} else {
		primitive, err = config.PrimitiveFromKey(entry.Key(), internalapi.Token{})
		if err == nil {
			isFullPrimitive = true
		} else {
			primitive, err = config.PrimitiveFromKeyData(protoKey.GetKeyData(), internalapi.Token{})
			if err != nil {
				return nil, fmt.Errorf("cannot get primitive from key data: %v", err)
			}
		}
	}
	actualPrimitive, ok := primitive.(T)
	if !ok {
		return nil, fmt.Errorf("primitive is of type %T, want %T", primitive, (*T)(nil))
	}
	if isFullPrimitive {
		return primitiveSet.AddFullPrimitive(actualPrimitive, protoKey)
	}
	return primitiveSet.Add(actualPrimitive, protoKey)
}

func primitives[T any](h *Handle, km registry.KeyManager, opts ...PrimitivesOption) (*primitiveset.PrimitiveSet[T], error) {
	if h == nil {
		return nil, fmt.Errorf("nil handle")
	}
	if h.Len() == 0 {
		return nil, fmt.Errorf("empty keyset")
	}
	args := new(primitiveOptions)
	for _, opt := range opts {
		if err := opt(args); err != nil {
			return nil, fmt.Errorf("failed to process primitiveOptions: %v", err)
		}
	}
	config := args.config
	if config == nil {
		config = &registryconfig.RegistryConfig{}
	}
	primitiveSet := primitiveset.New[T]()
	primitiveSet.Annotations = h.annotations
	for _, entry := range h.entries {
		if entry.KeyStatus() != Enabled {
			continue
		}
		primitiveSetEntry, err := addToPrimitiveSet(primitiveSet, entry, km, config)
		if err != nil {
			return nil, fmt.Errorf("cannot add primitive: %v", err)
		}
		if entry.IsPrimary() {
			primitiveSet.Primary = primitiveSetEntry
		}
	}
	return primitiveSet, nil
}

// hasSecrets tells whether the keyset contains key material considered secret.
//
// This includes symmetric keys, private keys of asymmetric crypto systems,
// and keys of an unknown type.
func hasSecrets(ks *tinkpb.Keyset) bool {
	for _, k := range ks.GetKey() {
		if k.GetKeyData() == nil {
			continue
		}
		switch k.GetKeyData().GetKeyMaterialType() {
		case tinkpb.KeyData_UNKNOWN_KEYMATERIAL, tinkpb.KeyData_ASYMMETRIC_PRIVATE, tinkpb.KeyData_SYMMETRIC:
			return true
		}
	}
	return false
}

func decrypt(encryptedKeyset *tinkpb.EncryptedKeyset, keyEncryptionAEAD tink.AEAD, associatedData []byte) (*tinkpb.Keyset, error) {
	if encryptedKeyset == nil || keyEncryptionAEAD == nil {
		return nil, fmt.Errorf("keyset.Handle: invalid encrypted keyset")
	}
	decrypted, err := keyEncryptionAEAD.Decrypt(encryptedKeyset.GetEncryptedKeyset(), associatedData)
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: decryption failed: %v", err)
	}
	keyset := new(tinkpb.Keyset)
	if err := proto.Unmarshal(decrypted, keyset); err != nil {
		return nil, errInvalidKeyset
	}
	return keyset, nil
}

// decryptWithContext does the same as decrypt, but uses an AEADWithContext instead of an AEAD.
func decryptWithContext(ctx context.Context, encryptedKeyset *tinkpb.EncryptedKeyset, keyEncryptionAEAD tink.AEADWithContext, associatedData []byte) (*tinkpb.Keyset, error) {
	if encryptedKeyset == nil || keyEncryptionAEAD == nil {
		return nil, fmt.Errorf("keyset.Handle: invalid encrypted keyset")
	}
	decrypted, err := keyEncryptionAEAD.DecryptWithContext(ctx, encryptedKeyset.GetEncryptedKeyset(), associatedData)
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: decryption failed: %v", err)
	}
	keyset := new(tinkpb.Keyset)
	if err := proto.Unmarshal(decrypted, keyset); err != nil {
		return nil, errInvalidKeyset
	}
	return keyset, nil
}

func encrypt(keyset *tinkpb.Keyset, keyEncryptionAEAD tink.AEAD, associatedData []byte) (*tinkpb.EncryptedKeyset, error) {
	serializedKeyset, err := proto.Marshal(keyset)
	if err != nil {
		return nil, errInvalidKeyset
	}
	encrypted, err := keyEncryptionAEAD.Encrypt(serializedKeyset, associatedData)
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: encryption failed: %v", err)
	}
	// get keyset info
	encryptedKeyset := &tinkpb.EncryptedKeyset{
		EncryptedKeyset: encrypted,
		KeysetInfo:      getKeysetInfo(keyset),
	}
	return encryptedKeyset, nil
}

// encryptWithContext does the same as encrypt, but uses an AEADWithContext instead of an AEAD.
func encryptWithContext(ctx context.Context, keyset *tinkpb.Keyset, keyEncryptionAEAD tink.AEADWithContext, associatedData []byte) (*tinkpb.EncryptedKeyset, error) {
	serializedKeyset, err := proto.Marshal(keyset)
	if err != nil {
		return nil, errInvalidKeyset
	}
	encrypted, err := keyEncryptionAEAD.EncryptWithContext(ctx, serializedKeyset, associatedData)
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: encryption failed: %v", err)
	}
	// get keyset info
	encryptedKeyset := &tinkpb.EncryptedKeyset{
		EncryptedKeyset: encrypted,
		KeysetInfo:      getKeysetInfo(keyset),
	}
	return encryptedKeyset, nil
}

// getKeysetInfo returns a KeysetInfo from a Keyset protobuf.
func getKeysetInfo(keyset *tinkpb.Keyset) *tinkpb.KeysetInfo {
	if keyset == nil {
		panic("keyset.Handle: keyset must be non nil")
	}
	keyInfos := make([]*tinkpb.KeysetInfo_KeyInfo, len(keyset.GetKey()))
	for i, key := range keyset.GetKey() {
		keyInfos[i] = getKeyInfo(key)
	}
	return &tinkpb.KeysetInfo{
		PrimaryKeyId: keyset.PrimaryKeyId,
		KeyInfo:      keyInfos,
	}
}

// getKeyInfo returns a KeyInfo from a Key protobuf.
func getKeyInfo(key *tinkpb.Keyset_Key) *tinkpb.KeysetInfo_KeyInfo {
	return &tinkpb.KeysetInfo_KeyInfo{
		TypeUrl:          key.KeyData.TypeUrl,
		Status:           key.Status,
		KeyId:            key.KeyId,
		OutputPrefixType: key.OutputPrefixType,
	}
}

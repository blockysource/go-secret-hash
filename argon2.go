// Copyright 2023 The Blocky Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package secrethash

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Argon2Mode is the argon2 mode.
type Argon2Mode int

func (a Argon2Mode) writeFormat(buf *bytes.Buffer) {
	switch a {
	case Argon2ModeID:
		buf.WriteString("argon2id")
	case Argon2ModeI:
		buf.WriteString("argon2i")
	case Argon2ModeD:
		buf.WriteString("argon2d")
	}
}

const (
	Argon2ModeID Argon2Mode = iota
	Argon2ModeI
	Argon2ModeD
)

// Argon2HashingAlgorithm is the argon2 hashing algorithm.
type Argon2HashingAlgorithm struct {
	SaltLength  int
	Iterations  uint32
	Memory      uint32
	Parallelism uint8
	KeyLength   uint32
	Mode        Argon2Mode
}

// DefaultArgon2HashingAlgorith returns the default argon2 hashing algorithm.
func DefaultArgon2HashingAlgorith() Argon2HashingAlgorithm {
	return Argon2HashingAlgorithm{
		SaltLength:  16,
		Iterations:  3,
		Memory:      64 * 1024,
		Parallelism: 2,
		KeyLength:   32,
		Mode:        Argon2ModeID,
	}
}

// CompareFormat checks whether the format of the secret hash matches this
// hashing algorithm.
func (a Argon2HashingAlgorithm) CompareFormat(secretHash []byte) bool {
	if len(secretHash) < 8 {
		return false
	}
	var key Argon2KeyComposed

	// Check if the mode of this algorithm matches the mode of the secret
	// algorithm is supported by this algorithm.
	n, err := key.decodeMode(secretHash)
	if err != nil {
		return false
	}

	if key.Params.Mode == Argon2ModeD {
		return false
	}

	secretHash = secretHash[n:]
	n, err = key.decodeVersion(secretHash)
	if err != nil {
		return false
	}

	// This is potentially a valid secret hash.
	// Return true, the parsing will be checked later.
	return true
}

// Type implements HashingAlgorithm interface.
func (a Argon2HashingAlgorithm) Type() HashingAlgorithmType {
	return HashingAlgorithmTypeArgon2
}

// GenerateSecretHash generates a hash from the secret.
func (a Argon2HashingAlgorithm) GenerateSecretHash(secret []byte) (SecretHash, error) {
	// Generate salt.
	salt := make([]byte, a.SaltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	var hash []byte
	switch a.Mode {
	case Argon2ModeID:
		hash = argon2.IDKey(secret, salt, a.Iterations, a.Memory, a.Parallelism, a.KeyLength)
	case Argon2ModeI:
		hash = argon2.Key(secret, salt, a.Iterations, a.Memory, a.Parallelism, a.KeyLength)
	case Argon2ModeD:
		return nil, errors.New("argon2d is not supported")
	}

	return &Argon2KeyComposed{
		Params: Argon2Params{
			Memory:      a.Memory,
			Iterations:  a.Iterations,
			Parallelism: a.Parallelism,
			Mode:        a.Mode,
		},
		Salt: salt,
		Key:  hash,
	}, nil
}

// Parse a formatted string representation of the key.
func (a Argon2HashingAlgorithm) Parse(secretHash []byte) (SecretHash, error) {
	p := new(Argon2KeyComposed)
	err := p.Parse(secretHash)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Argon2Params contains Argon2 parameters.
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	Mode        Argon2Mode
}

// Argon2KeyComposed is a structure that contains Argon2 parameters, salt and key.
type Argon2KeyComposed struct {
	Params Argon2Params
	Salt   []byte
	Key    []byte
}

// Format returns a formatted string representation of the key.
// The format is: $argon2id$v=<version>$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<key>
func (a *Argon2KeyComposed) Format() []byte {
	// $argon2id$v=19$m=65536,t=3,p=2$e3NzaC1yc2E$e3NzaC1yc2E=
	var buf bytes.Buffer
	buf.WriteRune('$')
	a.Params.Mode.writeFormat(&buf)
	fmt.Fprintf(&buf, "$v=%d$m=%d,t=%d,p=%d", argon2.Version, a.Params.Memory, a.Params.Iterations, a.Params.Parallelism)
	buf.WriteRune('$')
	tmp := make([]byte, base64.RawStdEncoding.EncodedLen(len(a.Salt)))
	base64.RawStdEncoding.Encode(tmp, a.Salt)
	buf.Write(tmp)

	tmp = make([]byte, base64.RawStdEncoding.EncodedLen(len(a.Key)))
	base64.RawStdEncoding.Encode(tmp, a.Key)
	buf.WriteRune('$')
	buf.Write(tmp)
	return buf.Bytes()
}

// Parse parses a formatted string representation of the key.
func (a *Argon2KeyComposed) Parse(secretHash []byte) error {
	if len(secretHash) < 8 {
		return ErrInvalidHash
	}

	n, err := a.decodeMode(secretHash)
	if err != nil {
		return err
	}

	secretHash = secretHash[n:]

	n, err = a.decodeVersion(secretHash)
	if err != nil {
		return err
	}

	secretHash = secretHash[n:]

	n, err = a.decodeParams(secretHash)
	if err != nil {
		return err
	}

	secretHash = secretHash[n:]

	n, err = a.decodeSalt(secretHash)
	if err != nil {
		return err
	}

	secretHash = secretHash[n:]

	n, err = a.decodeKey(secretHash)
	if err != nil {
		return err
	}

	n, err = a.decodeKey(secretHash)
	if err != nil {
		return err
	}

	return nil
}

var argon2Prefix = []byte("$argon2")

func (a *Argon2KeyComposed) decodeMode(sbytes []byte) (int, error) {
	// Verify argon2 prefix.
	if len(sbytes) < 8 {
		return -1, ErrInvalidHash
	}

	var n int
	if !bytes.Equal(sbytes[:7], argon2Prefix) {
		return -1, ErrInvalidHash
	}

	n += 7
	// Verify version (id, i, or d).
	switch sbytes[7] {
	case 'd':
		a.Params.Mode = Argon2ModeD
		n++
	case 'i':
		a.Params.Mode = Argon2ModeI
		n++
		if sbytes[8] == 'd' {
			a.Params.Mode = Argon2ModeID
			n++
		}
	default:
		return -1, ErrInvalidHash
	}
	return n, nil
}

// CompareSecret compares the secret with the parsed
func (a *Argon2KeyComposed) CompareSecret(secret []byte) error {
	var key []byte
	switch a.Params.Mode {
	case Argon2ModeID:
		key = argon2.IDKey(secret, a.Salt, a.Params.Iterations, a.Params.Memory, a.Params.Parallelism, uint32(len(a.Key)))
	case Argon2ModeI:
		key = argon2.Key(secret, a.Salt, a.Params.Iterations, a.Params.Memory, a.Params.Parallelism, uint32(len(a.Key)))
	case Argon2ModeD:
		return errors.New("argon2d is not supported")
	}
	if !bytes.Equal(key, a.Key) {
		return ErrInvalidSecret
	}
	return nil
}

func (a *Argon2KeyComposed) decodeVersion(hash []byte) (int, error) {
	if len(hash) < 4 {
		return -1, ErrInvalidHash
	}
	if hash[0] != '$' {
		return -1, ErrInvalidHash
	}

	if hash[1] != 'v' {
		return -1, ErrInvalidHash
	}

	n := 2

	var version int
	for ; n < len(hash); n++ {
		if hash[n] == '$' {
			break
		}
		if hash[n] < '0' || hash[n] > '9' {
			return -1, ErrInvalidHash
		}
		// Convert the version to an integer.
		version = version*10 + int(hash[n]-'0')
	}

	if version != argon2.Version {
		return -1, ErrInvalidHash
	}

	return n, nil
}

func (a *Argon2KeyComposed) decodeParams(hash []byte) (int, error) {
	var c byte
	if hash[0] != '$' {
		return -1, ErrInvalidHash
	}

	n := 1
	i := n
	for ; n < len(hash); n++ {
		if hash[n] == '$' {
			return n, nil
		}

		switch ch := hash[n]; ch {
		case 'm', 't', 'p':
			c = ch
		case '=':
			i = n + 1
		case ',', '$':
			// Parse context.
			switch c {
			case 'm':
				// Parse memory.
				var memory int
				for ; i < n; i++ {
					if hash[i] < '0' || hash[i] > '9' {
						return -1, ErrInvalidHash
					}
					memory = memory*10 + int(hash[i]-'0')
				}
				a.Params.Memory = uint32(memory)
			case 't':
				// Parse iterations.
				var iterations int
				for ; i < n; i++ {
					if hash[i] < '0' || hash[i] > '9' {
						return -1, ErrInvalidHash
					}
					iterations = iterations*10 + int(hash[i]-'0')
				}
				a.Params.Iterations = uint32(iterations)
			case 'p':
				// Parse parallelism.
				var parallelism int
				for ; i < n; i++ {
					if hash[i] < '0' || hash[i] > '9' {
						return -1, ErrInvalidHash
					}
					parallelism = parallelism*10 + int(hash[i]-'0')
				}
				a.Params.Parallelism = uint8(parallelism)
			default:
				return -1, ErrInvalidHash
			}
			c = 0
			if ch == '$' {
				return n, nil
			}
		}
	}
	return -1, ErrInvalidHash
}

func (a *Argon2KeyComposed) decodeSalt(hash []byte) (n int, err error) {
	if hash[0] != '$' {
		return -1, ErrInvalidHash
	}

	n = 1
	for ; n < len(hash); n++ {
		if hash[n] == '$' {
			break
		}
	}

	_, err = base64.RawStdEncoding.Strict().Decode(a.Salt, hash[:n])
	if err != nil {
		return -1, ErrInvalidHash
	}

	return n, nil
}

func (a *Argon2KeyComposed) decodeKey(hash []byte) (n int, err error) {
	if hash[0] != '$' {
		return -1, ErrInvalidHash
	}

	n, err = base64.RawStdEncoding.Strict().Decode(a.Key, hash)
	if err != nil {
		return -1, ErrInvalidHash
	}

	return n, nil
}

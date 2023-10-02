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
	"errors"
)

// HashingAlgorithm is the hashing algorithm used to hash the client secret.
type HashingAlgorithm interface {
	// GenerateSecretHash generates a hash from the secret.
	GenerateSecretHash(secret []byte) (SecretHash, error)

	// Parse parses a formatted representation of the key.
	Parse(secretHash []byte) (SecretHash, error)

	// CompareFormat checks whether the format of the secret hash matches this
	// hashing algorithm.
	CompareFormat(secretHash []byte) bool

	// Type returns the hashing algorithm type.
	Type() HashingAlgorithmType
}

// SecretHash is the secret key.
type SecretHash interface {
	// CompareSecret compares the secret with the parsed
	CompareSecret(secret []byte) error

	// Parse parses a formatted string representation of the key.
	Parse(secretHash []byte) error

	// Format returns the secret hash.
	Format() []byte
}

var (
	ErrInvalidHash              = errors.New("invalid hash")
	ErrInvalidSecret            = errors.New("invalid secret")
	ErrUnsupportedHashAlgorithm = errors.New("not supported hash algorithm")
)

// Hasher is the parser of the secret hash.
type Hasher struct {
	// algorithms is the algorithms of the parser.
	algorithms []HashingAlgorithm
}

// NewHasher creates a new algorithms container..
func NewHasher(algorithms ...HashingAlgorithm) (*Hasher, error) {
	if len(algorithms) == 0 {
		return nil, errors.New("no algorithms provided")
	}
	return &Hasher{
		algorithms: algorithms,
	}, nil
}

// GenerateSecretHashOptions is the options for generating a secret hash.
type GenerateSecretHashOptions struct {
	Algorithm HashingAlgorithmType
}

// GenerateSecretHash generates a hash from the secret.
func (p Hasher) GenerateSecretHash(secret []byte, opts *GenerateSecretHashOptions) (SecretHash, error) {
	if len(p.algorithms) == 0 {
		return nil, errors.New("no algorithms provided")
	}
	if opts.Algorithm.IsEmpty() {
		// Get the first algorithm from the list.
		return p.algorithms[0].GenerateSecretHash(secret)
	}

	// Find the algorithm.
	for _, algorithm := range p.algorithms {
		if algorithm.Type() == opts.Algorithm {
			// The algorithm is found.
			return algorithm.GenerateSecretHash(secret)
		}
	}

	return nil, ErrUnsupportedHashAlgorithm
}

// ParseHashOptions is the options for parsing a secret hash.
type ParseHashOptions struct {
	// ExpectedAlgorithm is the expected algorithm of the secret hash.
	ExpectAlgorithm HashingAlgorithmType
}

// Parse parses the secret hash from given input.
func (p Hasher) Parse(secretHash []byte, opts *ParseHashOptions) (SecretHash, error) {
	// Compare the prefix of the hash to create the hashing algorithm.
	if len(secretHash) == 0 {
		return nil, ErrInvalidHash
	}

	// Argon2 has a prefix of $argon2id$, $argon2i$, or $argon2d$, bcrypt has a prefix of $2a$, $2b$, or $2y$, and scrypt has a prefix of $s0$.
	//
	if secretHash[0] != '$' {
		return nil, ErrInvalidHash
	}

	if opts != nil && !opts.ExpectAlgorithm.IsEmpty() {
		for _, alg := range p.algorithms {
			if alg.Type() == opts.ExpectAlgorithm {
				if !alg.CompareFormat(secretHash) {
					continue
				}
				// The algorithm is found.
				return alg.Parse(secretHash)
			}
		}
		return nil, ErrUnsupportedHashAlgorithm
	}

	// Find the algorithm.
	for _, alg := range p.algorithms {
		if !alg.CompareFormat(secretHash) {
			continue
		}
		// The algorithm is found.
		return alg.Parse(secretHash)
	}

	return nil, ErrInvalidHash
}

// Gene

// HashingAlgorithmType is the hashing algorithm used to hash the client secret.
type HashingAlgorithmType string

const (
	// HashingAlgorithmTypeBCrypt is the bcrypt hashing algorithm.
	// It is quite simple algorithm to implement, but it does not allow secrets longer than 72 bytes.
	HashingAlgorithmTypeBCrypt = HashingAlgorithmType("bcrypt")

	// HashingAlgorithmTypeArgon2 is the argon2 hashing algorithm.
	HashingAlgorithmTypeArgon2 = HashingAlgorithmType("argon2")
)

func (h HashingAlgorithmType) IsEmpty() bool {
	return h == ""
}

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

// This file contains golang.org/x/crypto/bcrypt with some code modifications so that it
// can be used within this package.

package secrethash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"

	"golang.org/x/crypto/blowfish"
)

const (
	BCryptMinCost     int = 4  // the minimum allowable cost as passed in to GenerateFromPassword
	BCryptMaxCost     int = 31 // the maximum allowable cost as passed in to GenerateFromPassword
	BCryptDefaultCost int = 10 // the cost that will actually be set if a cost below BCryptMinCost is passed into GenerateFromPassword
)

var _ HashingAlgorithm = BCryptHashingAlgorithm{}

// BCryptHashingAlgorithm is the bcrypt hashing algorithm.
type BCryptHashingAlgorithm struct {
	// Cost is the cost of the bcrypt algorithm.
	Cost int
}

// GenerateSecretHash generates a hash from the secret.
// The maximum secret length is 72 bytes.
func (a BCryptHashingAlgorithm) GenerateSecretHash(secret []byte) (SecretHash, error) {
	if len(secret) > 72 {
		return nil, ErrInvalidSecret
	}
	return newFromPassword(secret, a.Cost)
}

func (BCryptHashingAlgorithm) Type() HashingAlgorithmType {
	return HashingAlgorithmTypeBCrypt
}

// CompareFormat checks whether the format of the secret hash matches this
// hashing algorithm.
func (a BCryptHashingAlgorithm) CompareFormat(secretHash []byte) bool {
	if len(secretHash) < minHashSize {
		return false
	}

	if secretHash[0] != '$' {
		return false
	}

	if secretHash[1] != '2' {
		return false
	}

	if secretHash[2] != 'a' {
		return false
	}

	return true
}

// Parse parses a formatted representation of the key.
func (a BCryptHashingAlgorithm) Parse(secretHash []byte) (SecretHash, error) {
	p := new(BCryptSecretHash)
	err := p.Parse(secretHash)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// BCryptSecretHash is the bcrypt secret hash.
type BCryptSecretHash struct {
	// Hash is the hash of the secret.
	Hash []byte
	// Salt is the salt of the secret.
	Salt []byte
	// Cost is the cost of the bcrypt algorithm.
	// allowed range is BCryptMinCost to BCryptMaxCost
	Cost int
	// Major is the major version of the bcrypt algorithm.
	Major byte
	// Minor is the minor version of the bcrypt algorithm.
	Minor byte
}

// Parse parses a formatted string representation of the key.
// The standard bcrypt format is $2a$[cost]$[22 character salt][31 character hash].
func (b *BCryptSecretHash) Parse(hashedSecret []byte) error {
	if len(hashedSecret) < minHashSize {
		return ErrInvalidHash
	}
	n, err := b.decodeVersion(hashedSecret)
	if err != nil {
		return err
	}
	hashedSecret = hashedSecret[n:]
	n, err = b.decodeCost(hashedSecret)
	if err != nil {
		return err
	}
	hashedSecret = hashedSecret[n:]

	// The "+2" is here because we'll have to append at most 2 '=' to the salt
	// when base64 decoding it in expensiveBlowfishSetup().
	b.Salt = make([]byte, encodedSaltSize, encodedSaltSize+2)
	copy(b.Salt, hashedSecret[:encodedSaltSize])

	hashedSecret = hashedSecret[encodedSaltSize:]
	b.Hash = make([]byte, len(hashedSecret))
	copy(b.Hash, hashedSecret)

	return nil
}

// Format returns a formatted string representation of the bcrypt hashed secret.
// The format is: $2a$[cost]$[22 character salt][31 character hash].
func (b *BCryptSecretHash) Format() []byte {
	arr := make([]byte, 60)
	arr[0] = '$'
	arr[1] = b.Major
	n := 2
	if b.Minor != 0 {
		arr[2] = b.Minor
		n = 3
	}
	arr[n] = '$'
	n++
	copy(arr[n:], []byte(fmt.Sprintf("%02d", b.Cost)))
	n += 2
	arr[n] = '$'
	n++
	copy(arr[n:], b.Salt)
	n += encodedSaltSize
	copy(arr[n:], b.Hash)
	n += encodedHashSize
	return arr[:n]
}

// CompareSecret compares the secret with the parsed secret hash.
func (b *BCryptSecretHash) CompareSecret(secret []byte) error {
	if len(secret) > 72 {
		return ErrInvalidSecret
	}
	// Hash the secret with the same parameters as the parsed secret hash.
	comparedHash, err := bcryptHash(secret, b.Cost, b.Salt)
	if err != nil {
		return err
	}

	otherP := BCryptSecretHash{Hash: comparedHash, Salt: b.Salt, Cost: b.Cost, Major: b.Major, Minor: b.Minor}
	if subtle.ConstantTimeCompare(b.Format(), otherP.Format()) == 1 {
		return nil
	}

	return ErrInvalidSecret
}

const (
	majorVersion       = '2'
	minorVersion       = 'a'
	maxSaltSize        = 16
	maxCryptedHashSize = 23
	encodedSaltSize    = 22
	encodedHashSize    = 31
	minHashSize        = 59
)

// magicCipherData is an IV for the 64 Blowfish encryption calls in
// bcrypt(). It's the string "OrpheanBeholderScryDoubt" in big-endian bytes.
var magicCipherData = []byte{
	0x4f, 0x72, 0x70, 0x68,
	0x65, 0x61, 0x6e, 0x42,
	0x65, 0x68, 0x6f, 0x6c,
	0x64, 0x65, 0x72, 0x53,
	0x63, 0x72, 0x79, 0x44,
	0x6f, 0x75, 0x62, 0x74,
}

func newFromPassword(password []byte, cost int) (*BCryptSecretHash, error) {
	if cost < BCryptMinCost {
		cost = BCryptDefaultCost
	}
	p := new(BCryptSecretHash)
	p.Major = majorVersion
	p.Minor = minorVersion

	err := checkCost(cost)
	if err != nil {
		return nil, err
	}
	p.Cost = cost

	unencodedSalt := make([]byte, maxSaltSize)
	_, err = io.ReadFull(rand.Reader, unencodedSalt)
	if err != nil {
		return nil, err
	}

	p.Salt = base64Encode(unencodedSalt)
	hash, err := bcryptHash(password, p.Cost, p.Salt)
	if err != nil {
		return nil, err
	}
	p.Hash = hash
	return p, err
}

func bcryptHash(password []byte, cost int, salt []byte) ([]byte, error) {
	cipherData := make([]byte, len(magicCipherData))
	copy(cipherData, magicCipherData)

	c, err := expensiveBlowfishSetup(password, uint32(cost), salt)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 24; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(cipherData[i:i+8], cipherData[i:i+8])
		}
	}

	// Bug compatibility with C bcrypt implementations. We only encode 23 of
	// the 24 bytes encrypted.
	hsh := base64Encode(cipherData[:maxCryptedHashSize])
	return hsh, nil
}

func expensiveBlowfishSetup(key []byte, cost uint32, salt []byte) (*blowfish.Cipher, error) {
	csalt, err := base64Decode(salt)
	if err != nil {
		return nil, err
	}

	// Bug compatibility with C bcrypt implementations. They use the trailing
	// NULL in the key string during expansion.
	// We copy the key to prevent changing the underlying array.
	ckey := append(key[:len(key):len(key)], 0)

	c, err := blowfish.NewSaltedCipher(ckey, csalt)
	if err != nil {
		return nil, err
	}

	var i, rounds uint64
	rounds = 1 << cost
	for i = 0; i < rounds; i++ {
		blowfish.ExpandKey(ckey, c)
		blowfish.ExpandKey(csalt, c)
	}

	return c, nil
}

func (b *BCryptSecretHash) decodeVersion(sbytes []byte) (int, error) {
	if sbytes[0] != '$' {
		return -1, ErrInvalidHash
	}
	if sbytes[1] > majorVersion {
		return -1, ErrInvalidHash
	}
	b.Major = sbytes[1]
	n := 3
	if sbytes[2] != '$' {
		b.Minor = sbytes[2]
		n++
	}
	return n, nil
}

// sbytes should begin where decodeVersion left off.
func (b *BCryptSecretHash) decodeCost(sbytes []byte) (int, error) {
	cost, err := strconv.Atoi(string(sbytes[0:2]))
	if err != nil {
		return -1, ErrInvalidHash
	}
	err = checkCost(cost)
	if err != nil {
		return -1, err
	}
	b.Cost = cost
	return 3, nil
}

func (b *BCryptSecretHash) String() string {
	return fmt.Sprintf("&{hash: %#v, salt: %#v, cost: %d, major: %c, minor: %c}", string(b.Hash), b.Salt, b.Cost, b.Major, b.Minor)
}

func checkCost(cost int) error {
	if cost < BCryptMinCost || cost > BCryptMaxCost {
		return ErrInvalidHash
	}
	return nil
}

const alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var bcEncoding = base64.NewEncoding(alphabet)

func base64Encode(src []byte) []byte {
	n := bcEncoding.EncodedLen(len(src))
	dst := make([]byte, n)
	bcEncoding.Encode(dst, src)
	for dst[n-1] == '=' {
		n--
	}
	return dst[:n]
}

func base64Decode(src []byte) ([]byte, error) {
	numOfEquals := 4 - (len(src) % 4)
	for i := 0; i < numOfEquals; i++ {
		src = append(src, '=')
	}

	dst := make([]byte, bcEncoding.DecodedLen(len(src)))
	n, err := bcEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

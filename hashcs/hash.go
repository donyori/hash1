// hash1.  A tool to calculate the hash checksum of one local file.
// Copyright (C) 2023  Yuan Gao
//
// This file is part of hash1.
//
// hash1 is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package hashcs

import (
	"crypto"
	_ "crypto/md5"    // link crypto.MD5 to the binary
	_ "crypto/sha1"   // link crypto.SHA1 to the binary
	_ "crypto/sha256" // link crypto.224 and crypto.SHA256 to the binary
	_ "crypto/sha512" // link crypto.384, crypto.512, crypto.SHA512_224, and crypto.SHA512_256 to the binary
	"hash"
	"sort"

	"github.com/donyori/gogo/errors"
	"github.com/donyori/gogo/filesys/local"
	_ "golang.org/x/crypto/blake2b"   // link crypto.BLAKE2b_256, crypto.BLAKE2b_384, and crypto.BLAKE2b_512 to the binary
	_ "golang.org/x/crypto/blake2s"   // link crypto.BLAKE2s_256 to the binary
	_ "golang.org/x/crypto/md4"       // link crypto.MD4 to the binary
	_ "golang.org/x/crypto/ripemd160" // link crypto.RIPEMD160 to the binary
	_ "golang.org/x/crypto/sha3"      // link crypto.SHA3_224, crypto.SHA3_256, crypto.SHA3_384, and crypto.SHA3_512 to the binary
)

// NumHash is the number of supported hash algorithms.
const NumHash int = 18

// Hashes are the supported hash algorithms.
//
// All its items are available (i.e., have been linked to the binary).
var Hashes = [NumHash]crypto.Hash{
	crypto.MD4,
	crypto.MD5,
	crypto.SHA1,
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
	crypto.SHA512_224,
	crypto.SHA512_256,
	crypto.RIPEMD160,
	crypto.SHA3_224,
	crypto.SHA3_256,
	crypto.SHA3_384,
	crypto.SHA3_512,
	crypto.BLAKE2s_256,
	crypto.BLAKE2b_256,
	crypto.BLAKE2b_384,
	crypto.BLAKE2b_512,
}

// Names are the names and aliases of the supported hash algorithms.
//
// Each item (of type []string) starts with the hash algorithm name,
// followed by its aliases.
// The hash algorithm name is the lowercase of the name returned by
// the method String of the corresponding crypto.Hash.
var Names = [NumHash][]string{
	{"md4"},
	{"md5", "m"},
	{"sha-1", "sha_1", "sha1"},
	{"sha-224", "sha_224", "sha224"},
	{"sha-256", "sha_256", "sha256", "s"},
	{"sha-384", "sha_384", "sha384"},
	{"sha-512", "sha_512", "sha512"},
	{
		"sha-512/224", "sha-512_224", "sha-512224",
		"sha_512/224", "sha_512_224", "sha_512224",
		"sha512/224", "sha512_224", "sha512224",
	},
	{
		"sha-512/256", "sha-512_256", "sha-512256",
		"sha_512/256", "sha_512_256", "sha_512256",
		"sha512/256", "sha512_256", "sha512256",
	},
	{"ripemd-160", "ripemd_160", "ripemd160"},
	{"sha3-224", "sha3_224", "sha3224"},
	{"sha3-256", "sha3_256", "sha3256"},
	{"sha3-384", "sha3_384", "sha3384"},
	{"sha3-512", "sha3_512", "sha3512"},
	{"blake2s-256", "blake2s_256", "blake2s256"},
	{"blake2b-256", "blake2b_256", "blake2b256"},
	{"blake2b-384", "blake2b_384", "blake2b384"},
	{"blake2b-512", "blake2b_512", "blake2b512"},
}

// hashRankMap is a map from crypto.Hash values to
// their ranks in Hashes.
// The rank is the index plus one.
var hashRankMap = make(map[crypto.Hash]int, NumHash)

// nameRankMap is a map from hash algorithm names and their aliases
// to their ranks in Names.
// The rank is the index plus one.
var nameRankMap = make(map[string]int)

func init() {
	// ATTENTION!
	// Make nameRankMap and hashRankMap in their declaration rather than
	// in function init to facilitate exporting them for testing.
	for i := range Hashes {
		hashRankMap[Hashes[i]] = i + 1
	}
	for i := range Names {
		for _, name := range Names[i] {
			nameRankMap[name] = i + 1
		}
	}
}

// HashChecksum consists of the hash algorithm name and
// the hexadecimal representation of the checksum.
type HashChecksum struct {
	// HashName is the name of the hash algorithm.
	//
	// HashName is not guaranteed in Names and
	// should only be used for display.
	HashName string `json:"hashName"`

	// Checksum is the hexadecimal representation of the hash checksum.
	Checksum string `json:"checksum"`
}

// CalculateChecksum calculates the hash checksum of the specified file.
//
// If the file is a directory, CalculateChecksum reports
// github.com/donyori/gogo/filesys.ErrIsDir and returns nil checksums.
// (To test whether err is github.com/donyori/gogo/filesys.ErrIsDir,
// use function errors.Is.)
//
// upper indicates whether to use uppercase in hexadecimal representation.
//
// hashNames are the names (or aliases) of the hash algorithms.
// Each name must be in the list Names.
// Otherwise, CalculateChecksum reports a *UnknownHashAlgorithmError.
// (To test whether err is *UnknownHashAlgorithmError,
// use function errors.As.)
// Duplicate algorithms are ignored. (For example,
// if the argument hashNames is []string{"sha-256", "sha256", "s"},
// the returned checksums contain only one item corresponding to
// the hash algorithm SHA-256.)
// If there are no items in hashNames,
// CalculateChecksum calculates the SHA-256 checksum.
//
// The returned checksums are sorted in the order of
// their names displayed in Names.
//
// For each item in the returned checksums,
// the field HashName is the name returned by the method String
// of the corresponding crypto.Hash.
func CalculateChecksum(filename string, upper bool, hashNames []string) (
	checksums []HashChecksum, err error) {
	if len(hashNames) == 0 {
		hashNames = []string{"sha-256"}
	}
	hashSet := make(map[crypto.Hash]struct{}, len(hashNames))
	for _, name := range hashNames {
		rank := nameRankMap[name]
		if rank == 0 {
			return nil, errors.AutoWrap(NewUnknownHashAlgorithmError(name))
		}
		hashSet[Hashes[rank-1]] = struct{}{}
	}
	hs := make([]crypto.Hash, 0, len(hashSet))
	for h := range hashSet {
		hs = append(hs, h)
	}
	n := len(hs)
	sort.Slice(hs, func(i, j int) bool {
		return hashRankMap[hs[i]] < hashRankMap[hs[j]]
	})
	newHashes := make([]func() hash.Hash, n)
	for i := 0; i < n; i++ {
		newHashes[i] = hs[i].New
	}
	cs, err := local.Checksum(filename, upper, newHashes...)
	if err != nil {
		return nil, errors.AutoWrap(err)
	} else if len(cs) > 0 {
		checksums = make([]HashChecksum, n)
		for i := 0; i < n; i++ {
			checksums[i].HashName = hs[i].String()
			checksums[i].Checksum = cs[i]
		}
	}
	return
}

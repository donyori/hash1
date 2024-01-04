// hash1.  A tool to calculate the hash checksum of one local file.
// Copyright (C) 2023-2024  Yuan Gao
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

package hashcs_test

import (
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/donyori/gogo/errors"

	"github.com/donyori/hash1/hashcs"
)

const (
	TestDataDir          = "../testdata"
	ChecksumJSONFilename = "checksum.json"
)

var (
	testFilenameHashChecksumMap                 map[string]map[crypto.Hash]string
	lazyLoadTestFilenameHashChecksumMapOnceAtom atomic.Pointer[sync.Once]
)

func init() {
	lazyLoadTestFilenameHashChecksumMapOnceAtom.Store(new(sync.Once))
}

type FileChecksums struct {
	Filename  string                `json:"filename"`
	Checksums []hashcs.HashChecksum `json:"checksums"`
}

// LazyLoadTestFilenameHashChecksumMap loads the checksum information of files
// in the test data directory, stores it in the map testFilenameHashChecksumMap,
// and returns that map.
//
// The checksum information is loaded only once.
// All modifications to the files in the directory after
// the first loading cannot take effect on this function.
//
// It panics when encountering an error.
func LazyLoadTestFilenameHashChecksumMap() map[string]map[crypto.Hash]string {
	for {
		var err error
		once := lazyLoadTestFilenameHashChecksumMapOnceAtom.Load()
		once.Do(func() {
			defer func() {
				if err != nil {
					testFilenameHashChecksumMap = nil
					lazyLoadTestFilenameHashChecksumMapOnceAtom.Store(
						new(sync.Once))
				}
			}()
			defer func() {
				e := recover()
				if e != nil {
					if v, ok := e.(error); ok {
						err = errors.Combine(err, v)
					} else {
						err = errors.Combine(err, fmt.Errorf("%v", e))
					}
				}
			}()
			var f *os.File
			f, err = os.Open(filepath.Join(TestDataDir, ChecksumJSONFilename))
			if err != nil {
				return
			}
			defer func(f *os.File) {
				_ = f.Close() // ignore error
			}(f)
			dec := json.NewDecoder(f)
			dec.DisallowUnknownFields()
			var fileChecksums []FileChecksums
			err = dec.Decode(&fileChecksums)
			if err != nil {
				return
			}
			testFilenameHashChecksumMap = make(
				map[string]map[crypto.Hash]string,
				len(fileChecksums),
			)
			for i := range fileChecksums {
				checksums := fileChecksums[i].Checksums
				m := make(map[crypto.Hash]string, len(checksums))
				for j := range checksums {
					index := hashcs.NameRankMap[strings.ToLower(checksums[j].HashName)] - 1
					if index >= 0 {
						m[hashcs.Hashes[index]] = checksums[j].Checksum
					}
				}
				testFilenameHashChecksumMap[fileChecksums[i].Filename] = m
			}
		})
		if err != nil {
			panic(errors.AutoWrap(err))
		} else if testFilenameHashChecksumMap != nil {
			return testFilenameHashChecksumMap
		}
	}
}

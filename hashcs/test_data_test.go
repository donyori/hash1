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

package hashcs_test

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"math/bits"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/donyori/gogo/algorithm/mathalgo"
	"github.com/donyori/gogo/errors"

	"github.com/donyori/hash1/hashcs"
)

const TestDataDir = "testdata"

var (
	testFileEntries                 []fs.DirEntry
	lazyLoadTestFileEntriesOnceAtom atomic.Pointer[sync.Once]

	testFilenameHashChecksumMap                 map[string]map[crypto.Hash]string
	lazyLoadTestFilenameHashChecksumMapOnceAtom atomic.Pointer[sync.Once]
)

func init() {
	lazyLoadTestFileEntriesOnceAtom.Store(new(sync.Once))
	lazyLoadTestFilenameHashChecksumMapOnceAtom.Store(new(sync.Once))
}

// LazyLoadTestFileEntries loads the file entries in the test data directory.
//
// It stores the result in the memory the first time reading the directory.
// Subsequent reads get the file entries from the memory instead of
// reading the directory again.
// Therefore, all modifications to the files in the directory after
// the first read cannot take effect on this function.
//
// It panics when encountering an error.
func LazyLoadTestFileEntries() []fs.DirEntry {
	for {
		var err error
		once := lazyLoadTestFileEntriesOnceAtom.Load()
		once.Do(func() {
			defer func() {
				if err != nil {
					testFileEntries = nil
					lazyLoadTestFileEntriesOnceAtom.Store(new(sync.Once))
				}
			}()
			defer func() {
				e := recover()
				if err == nil && e != nil {
					if v, ok := e.(error); ok {
						err = v
					} else {
						err = fmt.Errorf("%v", e)
					}
				}
			}()
			var entries []fs.DirEntry
			entries, err = os.ReadDir(TestDataDir)
			if err != nil {
				return
			}
			testFileEntries = make([]fs.DirEntry, 0, len(entries))
			for _, entry := range entries {
				if entry != nil && !entry.IsDir() {
					testFileEntries = append(testFileEntries, entry)
				}
			}
		})
		if err != nil {
			panic(errors.AutoWrap(err))
		} else if testFileEntries != nil {
			return testFileEntries
		}
	}
}

// LazyLoadTestFilenameHashChecksumMap loads the files
// in the test data directory, calculates their hash checksums,
// stores the result in the map testFilenameHashChecksumMap,
// and returns that map.
//
// The checksums are calculated only once.
// All modifications to the files in the directory after the first calculation
// of the checksums cannot take effect on this function.
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
					lazyLoadTestFilenameHashChecksumMapOnceAtom.Store(new(sync.Once))
				}
			}()
			defer func() {
				e := recover()
				if err == nil && e != nil {
					if v, ok := e.(error); ok {
						err = v
					} else {
						err = fmt.Errorf("%v", e)
					}
				}
			}()
			fileEntries := LazyLoadTestFileEntries()
			testFilenameHashChecksumMap = make(map[string]map[crypto.Hash]string, len(fileEntries))
			n := len(hashcs.Hashes)
			hs := make([]hash.Hash, n)
			ws := make([]io.Writer, n)
			bs := make([]uint, n)
			for i := 0; i < n; i++ {
				hs[i] = hashcs.Hashes[i].New()
				ws[i] = hs[i]
				bs[i] = uint(hs[i].BlockSize())
			}
			w := io.MultiWriter(ws...)
			bufSize := mathalgo.LCM(bs...) // make the buffer size a multiple of the block sizes
			if bufSize == 0 {
				// Act as a safeguard for the hash.Hash
				// whose BlockSize returns 0.
				bufSize = 5120 // = (2^10) * 5
			} else if shift := 13 - bits.Len(bufSize); shift > 0 {
				bufSize <<= shift // make the buffer size at least 4096
			}
			buf := make([]byte, bufSize)
			for _, entry := range fileEntries {
				_, err = loadFileTo(entry, w, buf)
				if err != nil {
					return
				}
				m := make(map[crypto.Hash]string, n)
				testFilenameHashChecksumMap[entry.Name()] = m
				for i := 0; i < n; i++ {
					m[hashcs.Hashes[i]] = hex.EncodeToString(hs[i].Sum(nil))
					hs[i].Reset()
				}
			}
		})
		if err != nil {
			panic(errors.AutoWrap(err))
		} else if testFilenameHashChecksumMap != nil {
			return testFilenameHashChecksumMap
		}
	}
}

// loadFileTo copies the content of the file entry to the writer w
// using the specified buffer buf.
//
// It returns the number of bytes copied and any error encountered.
//
// If entry is nil or represents a directory, or w is nil,
// loadFileTo returns (0, nil).
func loadFileTo(entry fs.DirEntry, w io.Writer, buf []byte) (written int64, err error) {
	if entry == nil || entry.IsDir() || w == nil {
		return
	}
	file, err := os.Open(filepath.Join(TestDataDir, entry.Name()))
	if err != nil {
		return 0, errors.AutoWrap(err)
	}
	defer func(file *os.File) {
		_ = file.Close() // ignore error
	}(file)
	written, err = io.CopyBuffer(w, file, buf)
	return written, errors.AutoWrap(err)
}

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

package cmd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/donyori/hash1/hashcs"
)

const (
	TestDataDir          = "../testdata"
	ChecksumJSONFilename = "checksum.json"
)

type FileChecksums struct {
	Filename  string                `json:"filename"`
	Checksums []hashcs.HashChecksum `json:"checksums"`
}

var (
	testFileChecksums   []FileChecksums
	testFilenameRankMap map[string]int
	hashNameRankMaps    []map[string]int
)

func init() {
	f, err := os.Open(filepath.Join(TestDataDir, ChecksumJSONFilename))
	if err != nil {
		panic(err)
	}
	defer func(f *os.File) {
		_ = f.Close() // ignore error
	}(f)
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	err = dec.Decode(&testFileChecksums)
	if err != nil {
		panic(err)
	}

	testFilenameRankMap = make(map[string]int, len(testFileChecksums))
	for i := range testFileChecksums {
		testFilenameRankMap[testFileChecksums[i].Filename] = i + 1
	}

	hashNameRankMaps = make([]map[string]int, len(testFileChecksums))
	for i := range testFileChecksums {
		checksums := testFileChecksums[i].Checksums
		m := make(map[string]int, len(checksums))
		for j := range checksums {
			name := strings.ToLower(checksums[j].HashName)
			m[name] = j + 1
			for k := range hashcs.Names {
				if hashcs.Names[k][0] == name {
					for aliasIdx := 1; aliasIdx < len(hashcs.Names[k]); aliasIdx++ {
						m[hashcs.Names[k][aliasIdx]] = j + 1
					}
					break
				}
			}
		}
		hashNameRankMaps[i] = m
	}
}

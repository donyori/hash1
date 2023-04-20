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
	"errors"
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donyori/gogo/filesys"
	"github.com/donyori/gogo/fmtcoll"
	"github.com/donyori/gogo/function/compare"

	"github.com/donyori/hash1/hashcs"
)

func TestNamesAndHashesConsistent(t *testing.T) {
	nameSet := make(map[string]bool, len(hashcs.NameRankMap))
	for i, group := range hashcs.Names {
		for j, name := range group {
			if nameSet[name] {
				t.Errorf("%s (Group %d, Item %d) is duplicate", name, i, j)
			}
			nameSet[name] = true
		}
	}
	hashSet := make(map[crypto.Hash]bool, len(hashcs.HashRankMap))
	for i, h := range hashcs.Hashes {
		if hashSet[h] {
			t.Errorf("%v (Item %d) is duplicate", h, i)
		}
		hashSet[h] = true
	}

	n := len(hashcs.Names)
	if len(hashcs.Hashes) != n { // keep this test for accidental modifications to hashcs.Names and hashcs.Hashes
		t.Fatalf("len(hashcs.Names) is %d; len(hashcs.Hashes) is %d", n, len(hashcs.Hashes))
	}
	for i := 0; i < n; i++ {
		if hashcs.Names[i][0] != strings.ToLower(hashcs.Hashes[i].String()) {
			t.Errorf("hashcs.Names[%d][0] is %s; hashcs.Hashes[%[1]d] is %[3]v; mismatch",
				i, hashcs.Names[i][0], hashcs.Hashes[i])
		}
	}
}

func TestHashesAvailable(t *testing.T) {
	for _, h := range hashcs.Hashes {
		if !h.Available() {
			t.Errorf("%v is unavailable", h)
		} else if x := h.New(); x == nil {
			t.Errorf("%v - New() returned nil", h)
		}
	}
}

func TestCalculateChecksum(t *testing.T) {
	checksumMap := LazyLoadTestFilenameHashChecksumMap()
	hashNames := make([]string, 0, len(hashcs.NameRankMap)*2)
	for _, group := range hashcs.Names {
		for _, name := range group {
			hashNames = append(hashNames, name, name) // duplicate each name
		}
	}
	rand.New(rand.NewSource(10)).Shuffle(len(hashNames), func(i, j int) {
		hashNames[i], hashNames[j] = hashNames[j], hashNames[i]
	})
	for _, entry := range LazyLoadTestFileEntries() {
		entryName := entry.Name()
		t.Run(fmt.Sprintf("file=%+q", entryName), func(t *testing.T) {
			filename := filepath.Join(TestDataDir, entryName)
			m := checksumMap[entryName]
			for _, upper := range []bool{false, true} {
				n := len(hashcs.Hashes)
				want := make([]hashcs.HashChecksum, n)
				for i := 0; i < n; i++ {
					s := m[hashcs.Hashes[i]]
					if upper {
						s = strings.ToUpper(s)
					} else {
						s = strings.ToLower(s)
					}
					want[i] = hashcs.HashChecksum{
						HashName: hashcs.Hashes[i].String(),
						Checksum: s,
					}
				}

				t.Run(fmt.Sprintf("upper=%t", upper), func(t *testing.T) {
					got, err := hashcs.CalculateChecksum(filename, upper, hashNames)
					if err != nil {
						t.Error("CalculateChecksum -", err)
					} else if !compare.ComparableSliceEqual(got, want) {
						t.Errorf("got %+v\nwant %+v", got, want)
					}
				})
			}
		})
	}
}

func TestCalculateChecksum_NoHashNames(t *testing.T) {
	checksumMap := LazyLoadTestFilenameHashChecksumMap()
	for _, entry := range LazyLoadTestFileEntries() {
		entryName := entry.Name()
		t.Run(fmt.Sprintf("file=%+q", entryName), func(t *testing.T) {
			filename := filepath.Join(TestDataDir, entryName)
			checksum := checksumMap[entryName][crypto.SHA256]
			for _, upper := range []bool{false, true} {
				want := []hashcs.HashChecksum{{HashName: crypto.SHA256.String()}}
				s := checksum
				if upper {
					s = strings.ToUpper(s)
				} else {
					s = strings.ToLower(s)
				}
				want[0].Checksum = s

				for _, hashNames := range [][]string{nil, {}} {
					hashNamesDisplay := "<nil>"
					if hashNames != nil {
						hashNamesDisplay = "[]"
					}
					t.Run(fmt.Sprintf("upper=%t&hashNames=%s", upper, hashNamesDisplay), func(t *testing.T) {
						got, err := hashcs.CalculateChecksum(filename, upper, hashNames)
						if err != nil {
							t.Error("CalculateChecksum -", err)
						} else if !compare.ComparableSliceEqual(got, want) {
							t.Errorf("got %+v\nwant %+v", got, want)
						}
					})
				}
			}
		})
	}
}

func TestCalculateChecksum_Dir(t *testing.T) {
	allNames := make([]string, 0, len(hashcs.NameRankMap))
	for _, group := range hashcs.Names {
		for _, name := range group {
			allNames = append(allNames, name)
		}
	}
	got, err := hashcs.CalculateChecksum(TestDataDir, false, allNames)
	if !errors.Is(err, filesys.ErrIsDir) {
		t.Errorf("got error %#v; want %#v", err, filesys.ErrIsDir)
	}
	if got != nil {
		t.Errorf("got checksums %+v; want nil", got)
	}
}

func TestCalculateChecksum_UnknownHashName(t *testing.T) {
	for _, entry := range LazyLoadTestFileEntries() {
		entryName := entry.Name()
		t.Run(fmt.Sprintf("file=%+q", entryName), func(t *testing.T) {
			filename := filepath.Join(TestDataDir, entryName)
			for _, upper := range []bool{false, true} {
				for _, hashNames := range [][]string{
					{""}, {"unknown"}, {"SHA-256"}, {"Sha256"},
					{"unknown", "SHA-256"}, {hashcs.Names[0][0], ""},
				} {
					hashNamesDisplay := fmtcoll.MustFormatSliceToString(
						hashNames,
						&fmtcoll.SequenceFormat[string]{
							CommonFormat: fmtcoll.CommonFormat{Separator: ","},
							FormatItemFn: fmtcoll.FprintfToFormatFunc[string]("%+q"),
						},
					)
					t.Run(fmt.Sprintf("upper=%t&hashNames=%s", upper, hashNamesDisplay), func(t *testing.T) {
						got, err := hashcs.CalculateChecksum(filename, upper, hashNames)
						var target *hashcs.UnknownHashAlgorithmError
						if !errors.As(err, &target) {
							t.Errorf("got error %#v; want a *hashcs.UnknownHashAlgorithmError", err)
						}
						if got != nil {
							t.Errorf("got checksums %+v; want nil", got)
						}
					})
				}
			}
		})
	}
}

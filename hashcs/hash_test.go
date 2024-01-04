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
	hashSet := make(map[crypto.Hash]struct{}, len(hashcs.HashRankMap))
	for i, h := range hashcs.Hashes {
		if h == 0 {
			t.Errorf("Item %d of hashcs.Hashes is 0", i)
		} else if _, ok := hashSet[h]; ok {
			t.Errorf("%v (Item %d of hashcs.Hashes) is duplicate", h, i)
		} else {
			hashSet[h] = struct{}{}
		}
	}

	nameSet := make(map[string]struct{}, len(hashcs.NameRankMap))
	for i, group := range hashcs.Names {
		if len(group) == 0 {
			t.Errorf("Group %d of hashcs.Names is empty", i)
		}
		for j, name := range group {
			if name == "" {
				t.Errorf("Group %d, Item %d of hashcs.Names is empty", i, j)
			} else if _, ok := nameSet[name]; ok {
				t.Errorf("%s (Group %d, Item %d of hashcs.Names) is duplicate",
					name, i, j)
			} else {
				nameSet[name] = struct{}{}
			}
		}
	}

	if t.Failed() {
		return
	}
	for i := 0; i < hashcs.NumHash; i++ {
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
	hashNames := make([]string, 0, len(hashcs.NameRankMap)*2)
	for _, group := range hashcs.Names {
		for _, name := range group {
			hashNames = append(hashNames, name, name) // duplicate each name
		}
	}
	rand.New(rand.NewSource(10)).Shuffle(len(hashNames), func(i, j int) {
		hashNames[i], hashNames[j] = hashNames[j], hashNames[i]
	})
	for entryName, m := range LazyLoadTestFilenameHashChecksumMap() {
		t.Run(fmt.Sprintf("file=%+q", entryName), func(t *testing.T) {
			filename := filepath.Join(TestDataDir, entryName)
			for _, upper := range []bool{false, true} {
				want := make([]hashcs.HashChecksum, hashcs.NumHash)
				for i := 0; i < hashcs.NumHash; i++ {
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
					got, err := hashcs.CalculateChecksum(
						filename, upper, hashNames)
					if err != nil {
						t.Error("CalculateChecksum -", err)
					} else if !compare.SliceEqual(got, want) {
						t.Errorf("got %+v\nwant %+v", got, want)
					}
				})
			}
		})
	}
}

func TestCalculateChecksum_NoHashNames(t *testing.T) {
	for entryName, m := range LazyLoadTestFilenameHashChecksumMap() {
		t.Run(fmt.Sprintf("file=%+q", entryName), func(t *testing.T) {
			filename := filepath.Join(TestDataDir, entryName)
			checksum := m[crypto.SHA256]
			for _, upper := range []bool{false, true} {
				want := []hashcs.HashChecksum{
					{HashName: crypto.SHA256.String()},
				}
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
					t.Run(
						fmt.Sprintf("upper=%t&hashNames=%s",
							upper, hashNamesDisplay),
						func(t *testing.T) {
							got, err := hashcs.CalculateChecksum(
								filename, upper, hashNames)
							if err != nil {
								t.Error("CalculateChecksum -", err)
							} else if !compare.SliceEqual(got, want) {
								t.Errorf("got %+v\nwant %+v", got, want)
							}
						},
					)
				}
			}
		})
	}
}

func TestCalculateChecksum_Dir(t *testing.T) {
	allNames := make([]string, 0, len(hashcs.NameRankMap))
	for _, group := range hashcs.Names {
		allNames = append(allNames, group...)
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
	for entryName := range LazyLoadTestFilenameHashChecksumMap() {
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
							FormatItemFn: fmtcoll.FprintfToFormatFunc[string](
								"%+q"),
						},
					)
					t.Run(
						fmt.Sprintf("upper=%t&hashNames=%s",
							upper, hashNamesDisplay),
						func(t *testing.T) {
							got, err := hashcs.CalculateChecksum(
								filename, upper, hashNames)
							var target *hashcs.UnknownHashAlgorithmError
							if !errors.As(err, &target) {
								t.Errorf("got error %#v; want a *hashcs.UnknownHashAlgorithmError",
									err)
							}
							if got != nil {
								t.Errorf("got checksums %+v; want nil", got)
							}
						},
					)
				}
			}
		})
	}
}

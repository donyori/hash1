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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/donyori/hash1/cmd"
	"github.com/donyori/hash1/hashcs"
)

func TestPrintChecksum(t *testing.T) {
	stdout, stderr := os.Stdout, os.Stderr // backup stdout and stderr

	tmpDir := t.TempDir()
	outputList := []string{"", "STDERR", filepath.Join(tmpDir, "output.dat")}
	inputList := make([]string, len(testFileChecksums))
	for i := range testFileChecksums {
		inputList[i] = filepath.Join(TestDataDir, testFileChecksums[i].Filename)
	}

	allHashNames := make([]string, hashcs.NumHash)
	for i := 0; i < hashcs.NumHash; i++ {
		allHashNames[i] = hashcs.Names[i][0]
	}
	hashNamesList := [][]string{
		nil,
		{},
		{"md5"},
		allHashNames,
		{"s", "m", "sha256"},
	}

	testCases := make([]struct {
		output, input string
		upper, inJSON bool
		hashNames     []string
		want          []byte
	}, len(outputList)*len(inputList)*2*2*len(hashNamesList))
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "    ")
	var idx int
	for _, output := range outputList {
		for _, input := range inputList {
			for _, upper := range []bool{false, true} {
				for _, inJSON := range []bool{false, true} {
					for _, hashNames := range hashNamesList {
						testCases[idx].output = output
						testCases[idx].input = input
						testCases[idx].upper = upper
						testCases[idx].inJSON = inJSON
						testCases[idx].hashNames = hashNames

						fileRank := testFilenameRankMap[filepath.Base(input)]
						if fileRank <= 0 {
							t.Fatalf("file rank of %q is %d, not positive",
								input, fileRank)
						}
						checksums := testFileChecksums[fileRank-1].Checksums
						hashNameRankMap := hashNameRankMaps[fileRank-1]
						if len(hashNames) == 0 {
							hashNames = []string{"sha-256"}
						}
						cs := make([]hashcs.HashChecksum, 0, len(hashNames))
						hashRankSet := make(map[int]bool, len(hashNames))
						for i := range hashNames {
							hashRank := hashNameRankMap[hashNames[i]]
							if hashRank <= 0 {
								t.Fatalf("hash rank of %q for file %q is %d, not positive",
									hashNames[i], input, hashRank)
							}
							if hashRankSet[hashRank] {
								continue
							}
							hashRankSet[hashRank] = true
							var checksum string
							if upper {
								checksum = strings.ToUpper(checksums[hashRank-1].Checksum)
							} else {
								checksum = strings.ToLower(checksums[hashRank-1].Checksum)
							}
							cs = append(cs, hashcs.HashChecksum{
								HashName: checksums[hashRank-1].HashName,
								Checksum: checksum,
							})
						}
						sort.Slice(cs, func(i, j int) bool {
							return hashNameRankMap[strings.ToLower(cs[i].HashName)] <
								hashNameRankMap[strings.ToLower(cs[j].HashName)]
						})
						buf.Reset()
						if inJSON {
							err := enc.Encode(cs)
							if err != nil {
								t.Fatal("encode JSON -", err)
							}
						} else {
							for i := range cs {
								// Ignore error as it is always nil for bytes.Buffer.
								_, _ = fmt.Fprintf(&buf, "%s: %s\n",
									cs[i].HashName, cs[i].Checksum)
							}
						}
						testCases[idx].want = make([]byte, buf.Len())
						copy(testCases[idx].want, buf.Bytes())

						idx++
					}
				}
			}
		}
	}

	for _, tc := range testCases {
		var outputName string
		if tc.output != "" {
			outputName = filepath.Base(tc.output)
		}
		outputName = strconv.QuoteToASCII(outputName)
		hashNamesName := "<nil>"
		if tc.hashNames != nil {
			hashNamesName = strconv.QuoteToASCII(strings.Join(tc.hashNames, ","))
		}
		t.Run(
			fmt.Sprintf(
				"output=%s&input=%+q&upper=%t&inJSON=%t&hashNames=%s",
				outputName,
				filepath.Base(tc.input),
				tc.upper,
				tc.inJSON,
				hashNamesName,
			),
			func(t *testing.T) {
				// Capture stdout or stderr as needed.
				var r io.Reader
				var c io.Closer
				if tc.output == "" {
					pipeR, pipeW, err := os.Pipe()
					if err != nil {
						t.Fatal("create pipe -", err)
					}
					t.Cleanup(func() {
						os.Stdout = stdout
					})
					r, c, os.Stdout = pipeR, pipeW, pipeW
				} else if tc.output == "STDERR" {
					pipeR, pipeW, err := os.Pipe()
					if err != nil {
						t.Fatal("create pipe -", err)
					}
					t.Cleanup(func() {
						os.Stderr = stderr
					})
					r, c, os.Stderr = pipeR, pipeW, pipeW
				}

				err := cmd.PrintChecksum(tc.output, tc.input,
					tc.upper, tc.inJSON, tc.hashNames)
				// Restore stdout and stderr,
				// regardless of whether they have been replaced.
				os.Stdout, os.Stderr = stdout, stderr
				if err != nil {
					t.Fatal("PrintChecksum -", err)
				}

				var got []byte
				if r != nil {
					err = c.Close()
					if err != nil {
						t.Fatal("close c -", err)
					}
					got, err = io.ReadAll(r)
				} else {
					got, err = os.ReadFile(tc.output)
				}

				if err != nil {
					t.Error("read output -", err)
				} else if !bytes.Equal(got, tc.want) {
					t.Errorf("got %s\nwant %s", got, tc.want)
				}
			},
		)
	}
}

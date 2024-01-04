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

package cmd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/donyori/gogo/filesys/local"

	"github.com/donyori/hash1/cmd"
	"github.com/donyori/hash1/hashcs"
)

type printChecksumTestCase struct {
	output    string
	input     string
	upper     bool
	inJSON    bool
	hashNames []string
	want      string
}

func TestPrintChecksum(t *testing.T) {
	for _, tc := range getTestCasesForPrintChecksum(t) {
		var outputName string
		if tc.output != "" {
			outputName = filepath.Base(tc.output)
		}
		outputName = strconv.QuoteToASCII(outputName)
		hashNamesName := "<nil>"
		if tc.hashNames != nil {
			hashNamesName = strconv.QuoteToASCII(
				strings.Join(tc.hashNames, ","))
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
				var f local.CaptureToStringFunc
				if tc.output == "" {
					var err error
					f, err = local.CaptureStdoutToString()
					if err != nil {
						t.Fatal("capture stdout -", err)
					}
				} else if tc.output == "STDERR" {
					var err error
					f, err = local.CaptureStderrToString()
					if err != nil {
						t.Fatal("capture stderr -", err)
					}
				}

				err := cmd.PrintChecksum(
					tc.output,
					tc.input,
					tc.upper,
					tc.inJSON,
					tc.hashNames,
				)
				// Restore stdout and stderr via f before checking err.
				var got string
				if f != nil {
					var e error
					got, e, _ = f()
					if e != nil {
						if err != nil {
							t.Error("PrintChecksum -", err)
						}
						t.Fatal("f (local.CaptureToStringFunc) -", err)
					}
				}
				if err != nil {
					t.Fatal("PrintChecksum -", err)
				} else if f == nil {
					var gotBytes []byte
					gotBytes, err = os.ReadFile(tc.output)
					if err != nil {
						t.Fatal("read output -", err)
					}
					got = string(gotBytes)
				}

				if got != tc.want {
					t.Errorf("got %s\nwant %s", got, tc.want)
				}
			},
		)
	}
}

// getTestCasesForPrintChecksum returns test cases for TestPrintChecksum.
//
// It uses t.Fatal and t.Fatalf to stop the test if something is wrong.
func getTestCasesForPrintChecksum(t *testing.T) []printChecksumTestCase {
	outputList := []string{
		"",
		"STDERR",
		filepath.Join(t.TempDir(), "output.dat"),
	}
	inputList := make([]string, len(testFileChecksums))
	for i := range testFileChecksums {
		inputList[i] = filepath.Join(
			TestDataDir, testFileChecksums[i].Filename)
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

	testCases := make([]printChecksumTestCase,
		len(outputList)*len(inputList)*2*2*len(hashNamesList))
	var b strings.Builder
	enc := json.NewEncoder(&b)
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
						testCases[idx].want = getWantForPrintChecksum(
							t, &b, enc, input, upper, inJSON, hashNames)
						idx++
					}
				}
			}
		}
	}
	if idx != len(testCases) {
		t.Fatal("excessive test cases, please update")
	}
	return testCases
}

// getWantForPrintChecksum returns the expected print content
// for TestPrintChecksum.
//
// It uses t.Fatal and t.Fatalf to stop the test if something is wrong.
func getWantForPrintChecksum(
	t *testing.T,
	b *strings.Builder,
	enc *json.Encoder,
	input string,
	upper bool,
	inJSON bool,
	hashNames []string,
) string {
	fileRank := testFilenameRankMap[filepath.Base(input)]
	if fileRank <= 0 {
		t.Fatalf("file rank of %q is %d, not positive", input, fileRank)
	}
	checksums := testFileChecksums[fileRank-1].Checksums
	hashNameRankMap := hashNameRankMaps[fileRank-1]
	if len(hashNames) == 0 {
		hashNames = []string{"sha-256"}
	}
	cs := make([]hashcs.HashChecksum, 0, len(hashNames))
	hashRankSet := make(map[int]struct{}, len(hashNames))
	for i := range hashNames {
		hashRank := hashNameRankMap[hashNames[i]]
		if hashRank <= 0 {
			t.Fatalf("hash rank of %q for file %q is %d, not positive",
				hashNames[i], input, hashRank)
		}
		if _, ok := hashRankSet[hashRank]; ok {
			continue
		}
		hashRankSet[hashRank] = struct{}{}
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
	slices.SortFunc(cs, func(a, b hashcs.HashChecksum) int {
		ra := hashNameRankMap[strings.ToLower(a.HashName)]
		rb := hashNameRankMap[strings.ToLower(b.HashName)]
		if ra < rb {
			return -1
		} else if ra > rb {
			return 1
		}
		return 0
	})

	b.Reset()
	if inJSON {
		err := enc.Encode(cs)
		if err != nil {
			t.Fatal("encode JSON -", err)
		}
	} else {
		for i := range cs {
			b.WriteString(cs[i].HashName)
			b.WriteString(": ")
			b.WriteString(cs[i].Checksum)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

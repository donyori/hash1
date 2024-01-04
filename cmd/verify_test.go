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
	"crypto"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/donyori/gogo/errors"

	"github.com/donyori/hash1/cmd"
	"github.com/donyori/hash1/hashcs"
)

func TestVerifyFlagNamesHashChecksumValidAndConsistent(t *testing.T) {
	not0_9a_zPattern, err := regexp.Compile("[^0-9a-z]+")
	if err != nil {
		t.Fatal("compile regexp -", err)
	}
	for i := 0; i < hashcs.NumHash; i++ {
		name := cmd.VerifyFlagNamesHashChecksum[i][0]
		shorthand := cmd.VerifyFlagNamesHashChecksum[i][1]
		if len(shorthand) > 1 {
			t.Errorf("shorthand of Item %d is %q, more than one ASCII character",
				i, shorthand)
		}
		name0_9a_z := not0_9a_zPattern.ReplaceAllLiteralString(name, "")
		if name0_9a_z != not0_9a_zPattern.ReplaceAllLiteralString(
			hashcs.Names[i][0], "",
		) {
			t.Errorf("name of Item %d is %q; does not match %q",
				i, name, hashcs.Names[i][0])
		}
		var wantShorthand string
		switch name0_9a_z {
		case "md5":
			wantShorthand = "m"
		case "sha256":
			wantShorthand = "s"
		}
		if shorthand != wantShorthand {
			t.Errorf("shorthand of %q (Item %d) is %q; want %q",
				name, i, shorthand, wantShorthand)
		}
	}
}

type verifyChecksumSHA256OKAndFail struct {
	filename  string
	flagValue string
	flagName  string
}

func TestVerifyChecksum_SHA256_OK(t *testing.T) {
	sha256FlagIndex := getFlagIndex(t, "sha256")
	for _, tc := range getTestCasesForVerifyChecksumSHA256OK(t) {
		t.Run(
			fmt.Sprintf("filename=%+q&flag=%s", tc.filename, tc.flagName),
			func(t *testing.T) {
				var flags [hashcs.NumHash]string
				flags[sha256FlagIndex] = tc.flagValue
				mismatch, err, isIllegalUseError := cmd.VerifyChecksum(
					filepath.Join(TestDataDir, tc.filename), &flags)
				if err != nil {
					t.Error("got error", err)
				}
				if mismatch != nil {
					t.Errorf("got mismatch %+v", mismatch)
				}
				if isIllegalUseError {
					t.Errorf("got isIllegalUseError %t; want false",
						isIllegalUseError)
				}
			},
		)
	}
}

// getTestCasesForVerifyChecksumSHA256OK returns test cases
// for TestVerifyChecksum_SHA256_OK.
//
// It uses t.Fatal and t.Fatalf to stop the test if something is wrong.
func getTestCasesForVerifyChecksumSHA256OK(
	t *testing.T,
) []verifyChecksumSHA256OKAndFail {
	flagNames := []string{
		"entire",
		"prefix",
		"suffix",
		"prefix+suffix",
		`entire+"..."`,
		`prefix+"..."`,
		`"..."`,
	}
	testCases := make([]verifyChecksumSHA256OKAndFail,
		len(testFileChecksums)*len(flagNames))
	var idx int
	for i := range testFileChecksums {
		sha256Rank := hashNameRankMaps[i]["sha-256"]
		if sha256Rank <= 0 {
			t.Fatalf("cannot obtain SHA-256 hash checksum of file %q",
				testFileChecksums[i].Filename)
		}
		checksum := testFileChecksums[i].Checksums[sha256Rank-1].Checksum
		for j := range flagNames {
			testCases[idx].filename = testFileChecksums[i].Filename
			testCases[idx].flagName = flagNames[j]
			switch j {
			case 0:
				testCases[idx].flagValue = checksum
			case 1:
				testCases[idx].flagValue = checksum[:7]
			case 2:
				testCases[idx].flagValue = "..." + checksum[len(checksum)-7:]
			case 3:
				testCases[idx].flagValue = checksum[:7] +
					"..." + checksum[len(checksum)-7:]
			case 4:
				testCases[idx].flagValue = checksum + "..."
			case 5:
				testCases[idx].flagValue = checksum[:7] + "..."
			case 6:
				testCases[idx].flagValue = "..."
			default:
				// This should never happen,
				// but will act as a safeguard for later,
				// as a default value doesn't make sense here.
				t.Fatal("undefined case", j)
			}
			idx++
		}
	}
	if idx != len(testCases) {
		t.Fatal("excessive test cases, please update")
	}
	return testCases
}

func TestVerifyChecksum_SHA256_Fail(t *testing.T) {
	sha256FlagIndex := getFlagIndex(t, "sha256")
	for _, tc := range getTestCasesForVerifyChecksumSHA256Fail(t) {
		t.Run(
			fmt.Sprintf("filename=%+q&flag=%s", tc.filename, tc.flagName),
			func(t *testing.T) {
				var flags [hashcs.NumHash]string
				flags[sha256FlagIndex] = tc.flagValue
				mismatch, err, isIllegalUseError := cmd.VerifyChecksum(
					filepath.Join(TestDataDir, tc.filename), &flags)
				if err != nil {
					t.Error("got error", err)
				}
				if len(mismatch) != 1 ||
					mismatch[0].HashName != crypto.SHA256.String() {
					t.Errorf("got mismatch %+v", mismatch)
				}
				if isIllegalUseError {
					t.Errorf("got isIllegalUseError %t; want false",
						isIllegalUseError)
				}
			},
		)
	}
}

// getTestCasesForVerifyChecksumSHA256Fail returns test cases
// for TestVerifyChecksum_SHA256_Fail.
//
// It uses t.Fatal and t.Fatalf to stop the test if something is wrong.
func getTestCasesForVerifyChecksumSHA256Fail(
	t *testing.T,
) []verifyChecksumSHA256OKAndFail {
	flagNames := []string{
		"entire",
		"prefix",
		"suffix",
		"prefix(wrong)+suffix",
		"prefix+suffix(wrong)",
		`entire+"..."`,
		`prefix+"..."`,
	}
	replaceIndexes := []int{-1, 3, 6, 3, 13, -1, 3}
	testCases := make([]verifyChecksumSHA256OKAndFail,
		len(testFileChecksums)*len(flagNames))
	var idx int
	for i := range testFileChecksums {
		sha256Rank := hashNameRankMaps[i]["sha-256"]
		if sha256Rank <= 0 {
			t.Fatalf("cannot obtain SHA-256 hash checksum of file %q",
				testFileChecksums[i].Filename)
		}
		checksum := testFileChecksums[i].Checksums[sha256Rank-1].Checksum
		for j := range flagNames {
			testCases[idx].filename = testFileChecksums[i].Filename
			testCases[idx].flagName = flagNames[j]
			switch j {
			case 0:
				testCases[idx].flagValue = checksum
			case 1:
				testCases[idx].flagValue = checksum[:7]
			case 2:
				testCases[idx].flagValue = "..." + checksum[len(checksum)-7:]
			case 3, 4:
				testCases[idx].flagValue = checksum[:7] +
					"..." + checksum[len(checksum)-7:]
			case 5:
				testCases[idx].flagValue = checksum + "..."
			case 6:
				testCases[idx].flagValue = checksum[:7] + "..."
			default:
				// This should never happen,
				// but will act as a safeguard for later,
				// as a default value doesn't make sense here.
				t.Fatal("undefined case", j)
			}
			replIdx := replaceIndexes[j]
			if replIdx < 0 {
				replIdx = len(checksum) / 2
			}
			testCases[idx].flagValue = makeWrongChecksum(
				testCases[idx].flagValue, replIdx)
			idx++
		}
	}
	if idx != len(testCases) {
		t.Fatal("excessive test cases, please update")
	}
	return testCases
}

func TestVerifyChecksum_SHA256_InvalidHex(t *testing.T) {
	sha256FlagIndex := getFlagIndex(t, "sha256")
	isInvalidPrefixList := []bool{true, true, true, false, false, false, true}
	flagsList := make([][hashcs.NumHash]string, len(isInvalidPrefixList))
	flagsList[0][sha256FlagIndex] = "3x12"
	flagsList[1][sha256FlagIndex] = "..1234"
	flagsList[2][sha256FlagIndex] = "3_12"
	flagsList[3][sha256FlagIndex] = "...3x12"
	flagsList[4][sha256FlagIndex] = "...5678...9abc"
	flagsList[5][sha256FlagIndex] = "3A2B...9_bc"
	flagsList[6][sha256FlagIndex] = "3_12...9_bc"
	testCases := make([]struct {
		filename        string
		flags           [hashcs.NumHash]string
		isInvalidPrefix bool
	}, len(testFileChecksums)*len(flagsList))
	var idx int
	for i := range testFileChecksums {
		for j := range flagsList {
			testCases[idx].filename = testFileChecksums[i].Filename
			testCases[idx].flags = flagsList[j]
			testCases[idx].isInvalidPrefix = isInvalidPrefixList[j]
			idx++
		}
	}
	if idx != len(testCases) {
		t.Fatal("excessive test cases, please update")
	}

	const WantErrorSuffix = " is not a valid hexadecimal representation"
	for _, tc := range testCases {
		wantErrorSnippet := "invalid flag --sha256: hash checksum "
		if tc.isInvalidPrefix {
			wantErrorSnippet += "prefix "
		} else {
			wantErrorSnippet += "suffix "
		}
		t.Run(
			fmt.Sprintf(
				"filename=%+q&flag=%+q",
				tc.filename,
				tc.flags[sha256FlagIndex],
			),
			func(t *testing.T) {
				mismatch, err, isIllegalUseError := cmd.VerifyChecksum(
					filepath.Join(TestDataDir, tc.filename), &tc.flags)
				if err == nil ||
					!strings.Contains(err.Error(), wantErrorSnippet) ||
					!strings.HasSuffix(err.Error(), WantErrorSuffix) {
					t.Errorf("got error %v; want one containing %q and with suffix %q",
						err, wantErrorSnippet, WantErrorSuffix)
				}
				if mismatch != nil {
					t.Errorf("got mismatch %+v", mismatch)
				}
				if !isIllegalUseError {
					t.Errorf("got isIllegalUseError %t; want true",
						isIllegalUseError)
				}
			},
		)
	}
}

type verifyChecksumAllHashesOKAndFail struct {
	filename  string
	flags     [hashcs.NumHash]string
	flagsName string
}

func TestVerifyChecksum_AllHashes_OK(t *testing.T) {
	for _, tc := range getTestCasesForVerifyChecksumAllHashesOK(t) {
		t.Run(
			fmt.Sprintf("filename=%+q&flags=%s", tc.filename, tc.flagsName),
			func(t *testing.T) {
				mismatch, err, isIllegalUseError := cmd.VerifyChecksum(
					filepath.Join(TestDataDir, tc.filename), &tc.flags)
				if err != nil {
					t.Error("got error", err)
				}
				if mismatch != nil {
					t.Errorf("got mismatch %+v", mismatch)
				}
				if isIllegalUseError {
					t.Errorf("got isIllegalUseError %t; want false",
						isIllegalUseError)
				}
			},
		)
	}
}

// getTestCasesForVerifyChecksumAllHashesOK returns test cases
// for TestVerifyChecksum_AllHashes_OK.
//
// It uses t.Fatal and t.Fatalf to stop the test if something is wrong.
func getTestCasesForVerifyChecksumAllHashesOK(
	t *testing.T,
) []verifyChecksumAllHashesOKAndFail {
	flagsNames := []string{
		"entire",
		"prefix",
		"suffix",
		"prefix+suffix",
		`entire+"..."`,
		`prefix+"..."`,
		`"..."`,
	}
	testCases := make([]verifyChecksumAllHashesOKAndFail,
		len(testFileChecksums)*len(flagsNames))
	var idx int
	for i := range testFileChecksums {
		var checksums [hashcs.NumHash]string
		for _, cs := range testFileChecksums[i].Checksums {
			checksums[hashNameRankMaps[i][strings.ToLower(cs.HashName)]-1] = cs.Checksum
		}
		for j := range checksums {
			if checksums[j] == "" {
				t.Fatalf("checksums[%d] of file %q is empty",
					j, testFileChecksums[i].Filename)
			}
		}
		for j := range flagsNames {
			testCases[idx].filename = testFileChecksums[i].Filename
			testCases[idx].flagsName = flagsNames[j]
			for k := 0; k < hashcs.NumHash; k++ {
				switch j {
				case 0:
					testCases[idx].flags[k] = checksums[k]
				case 1:
					testCases[idx].flags[k] = checksums[k][:7]
				case 2:
					testCases[idx].flags[k] = "..." +
						checksums[k][len(checksums[k])-7:]
				case 3:
					testCases[idx].flags[k] = checksums[k][:7] +
						"..." + checksums[k][len(checksums[k])-7:]
				case 4:
					testCases[idx].flags[k] = checksums[k] + "..."
				case 5:
					testCases[idx].flags[k] = checksums[k][:7] + "..."
				case 6:
					testCases[idx].flags[k] = "..."
				default:
					// This should never happen,
					// but will act as a safeguard for later,
					// as a default value doesn't make sense here.
					t.Fatal("undefined case", j)
				}
			}
			idx++
		}
	}
	if idx != len(testCases) {
		t.Fatal("excessive test cases, please update")
	}
	return testCases
}

func TestVerifyChecksum_AllHashes_MD5AndSHA256Fail(t *testing.T) {
	testCases := getTestCasesForVerifyChecksumAllHashesMD5AndSHA256Fail(t)
	for _, tc := range testCases {
		t.Run(
			fmt.Sprintf("filename=%+q&flags=%s", tc.filename, tc.flagsName),
			func(t *testing.T) {
				mismatch, err, isIllegalUseError := cmd.VerifyChecksum(
					filepath.Join(TestDataDir, tc.filename), &tc.flags)
				if err != nil {
					t.Error("got error", err)
				}
				if len(mismatch) != 2 ||
					mismatch[0].HashName != crypto.MD5.String() ||
					mismatch[1].HashName != crypto.SHA256.String() {
					t.Errorf("got mismatch %+v", mismatch)
				}
				if isIllegalUseError {
					t.Errorf("got isIllegalUseError %t; want false",
						isIllegalUseError)
				}
			},
		)
	}
}

// getTestCasesForVerifyChecksumAllHashesMD5AndSHA256Fail returns test cases
// for TestVerifyChecksum_AllHashes_MD5AndSHA256Fail.
//
// It uses t.Fatal and t.Fatalf to stop the test if something is wrong.
func getTestCasesForVerifyChecksumAllHashesMD5AndSHA256Fail(
	t *testing.T,
) []verifyChecksumAllHashesOKAndFail {
	md5FlagIndex := getFlagIndex(t, "md5")
	sha256FlagIndex := getFlagIndex(t, "sha256")
	flagsNames := []string{
		"entire",
		"prefix",
		"suffix",
		"prefix(wrong)+suffix",
		"prefix+suffix(wrong)",
		`entire+"..."`,
		`prefix+"..."`,
	}
	replaceIndexes := []int{-1, 3, 6, 3, 13, -1, 3}
	testCases := make([]verifyChecksumAllHashesOKAndFail,
		len(testFileChecksums)*len(flagsNames))
	var idx int
	for i := range testFileChecksums {
		var checksums [hashcs.NumHash]string
		for _, cs := range testFileChecksums[i].Checksums {
			checksums[hashNameRankMaps[i][strings.ToLower(cs.HashName)]-1] = cs.Checksum
		}
		for j := range checksums {
			if checksums[j] == "" {
				t.Fatalf("checksums[%d] of file %q is empty",
					j, testFileChecksums[i].Filename)
			}
		}
		for j := range flagsNames {
			testCases[idx].filename = testFileChecksums[i].Filename
			testCases[idx].flagsName = flagsNames[j]
			for k := 0; k < hashcs.NumHash; k++ {
				testCases[idx].flags[k] = getFlagForVerifyChecksumAllHashesMD5AndSHA256Fail(
					t,
					j,
					checksums[k],
					k,
					md5FlagIndex,
					sha256FlagIndex,
					replaceIndexes,
				)
			}
			idx++
		}
	}
	if idx != len(testCases) {
		t.Fatal("excessive test cases, please update")
	}
	return testCases
}

// getFlagForVerifyChecksumAllHashesMD5AndSHA256Fail returns the flag value
// for TestVerifyChecksum_AllHashes_MD5AndSHA256Fail.
//
// It uses t.Fatal to stop the test if the case index is out of range [0, 6].
func getFlagForVerifyChecksumAllHashesMD5AndSHA256Fail(
	t *testing.T,
	caseIndex int,
	checksum string,
	flagIndex int,
	md5FlagIndex int,
	sha256FlagIndex int,
	replaceIndexes []int,
) string {
	var flag string
	switch caseIndex {
	case 0:
		flag = checksum
	case 1:
		flag = checksum[:7]
	case 2:
		flag = "..." + checksum[len(checksum)-7:]
	case 3, 4:
		flag = checksum[:7] + "..." + checksum[len(checksum)-7:]
	case 5:
		flag = checksum + "..."
	case 6:
		flag = checksum[:7] + "..."
	default:
		// This should never happen, but will act as a safeguard for later,
		// as a default value doesn't make sense here.
		t.Fatal("undefined case", caseIndex)
	}
	if flagIndex == md5FlagIndex || flagIndex == sha256FlagIndex {
		replIdx := replaceIndexes[caseIndex]
		if replIdx < 0 {
			replIdx = len(checksum) / 2
		}
		flag = makeWrongChecksum(flag, replIdx)
	}
	return flag
}

func TestVerifyChecksum_AllHashes_SHA256InvalidHex(t *testing.T) {
	sha256FlagIndex := getFlagIndex(t, "sha256")
	isInvalidPrefixList := []bool{true, true, true, false, false, false, true}
	flagsList := make([][hashcs.NumHash]string, len(isInvalidPrefixList))
	flagsList[0][sha256FlagIndex] = "3x12"
	flagsList[1][sha256FlagIndex] = "..1234"
	flagsList[2][sha256FlagIndex] = "3_12"
	flagsList[3][sha256FlagIndex] = "...3x12"
	flagsList[4][sha256FlagIndex] = "...5678...9abc"
	flagsList[5][sha256FlagIndex] = "3A2B...9_bc"
	flagsList[6][sha256FlagIndex] = "3_12...9_bc"
	testCases := make([]struct {
		filename        string
		flags           [hashcs.NumHash]string
		isInvalidPrefix bool
	}, len(testFileChecksums)*len(flagsList))
	var idx int
	for i := range testFileChecksums {
		var checksums [hashcs.NumHash]string
		for _, cs := range testFileChecksums[i].Checksums {
			checksums[hashNameRankMaps[i][strings.ToLower(cs.HashName)]-1] = cs.Checksum
		}
		for j := range checksums {
			if checksums[j] == "" {
				t.Fatalf("checksums[%d] of file %q is empty",
					j, testFileChecksums[i].Filename)
			}
		}
		for j := range flagsList {
			testCases[idx].filename = testFileChecksums[i].Filename
			testCases[idx].flags = checksums
			testCases[idx].flags[sha256FlagIndex] = flagsList[j][sha256FlagIndex]
			testCases[idx].isInvalidPrefix = isInvalidPrefixList[j]
			idx++
		}
	}
	if idx != len(testCases) {
		t.Fatal("excessive test cases, please update")
	}

	const WantErrorSuffix = " is not a valid hexadecimal representation"
	for _, tc := range testCases {
		wantErrorSnippet := "invalid flag --sha256: hash checksum "
		if tc.isInvalidPrefix {
			wantErrorSnippet += "prefix "
		} else {
			wantErrorSnippet += "suffix "
		}
		t.Run(
			fmt.Sprintf(
				"filename=%+q&flag=%+q",
				tc.filename,
				tc.flags[sha256FlagIndex],
			),
			func(t *testing.T) {
				mismatch, err, isIllegalUseError := cmd.VerifyChecksum(
					filepath.Join(TestDataDir, tc.filename), &tc.flags)
				if err == nil ||
					!strings.Contains(err.Error(), wantErrorSnippet) ||
					!strings.HasSuffix(err.Error(), WantErrorSuffix) {
					t.Errorf("got error %v; want one containing %q and with suffix %q",
						err, wantErrorSnippet, WantErrorSuffix)
				}
				if mismatch != nil {
					t.Errorf("got mismatch %+v", mismatch)
				}
				if !isIllegalUseError {
					t.Errorf("got isIllegalUseError %t; want true",
						isIllegalUseError)
				}
			},
		)
	}
}

func TestVerifyChecksum_NoHash(t *testing.T) {
	const WantErrorSuffix = "hash checksum not specified"
	for i := range testFileChecksums {
		filename := testFileChecksums[i].Filename
		t.Run(fmt.Sprintf("filename=%+q", filename), func(t *testing.T) {
			var flags [hashcs.NumHash]string
			mismatch, err, isIllegalUseError := cmd.VerifyChecksum(
				filepath.Join(TestDataDir, filename), &flags)
			if err == nil || !strings.HasSuffix(err.Error(), WantErrorSuffix) {
				t.Errorf("got error %v; want one with suffix %q",
					err, WantErrorSuffix)
			}
			if mismatch != nil {
				t.Errorf("got mismatch %+v", mismatch)
			}
			if !isIllegalUseError {
				t.Errorf("got isIllegalUseError %t; want true",
					isIllegalUseError)
			}
		})
	}
}

// getFlagIndex returns the index of the specified flag
// in cmd.VerifyFlagNamesHashChecksum.
//
// It uses t.Fatalf to stop the test if it cannot find the specified flag.
func getFlagIndex(t *testing.T, flagName string) int {
	for i := 0; i < hashcs.NumHash; i++ {
		if cmd.VerifyFlagNamesHashChecksum[i][0] == flagName {
			return i
		}
	}
	t.Fatalf("cannot find index of flag %q", flagName)
	return -1
}

// makeWrongChecksum replaces s[i] with another character in {'0', '1'}.
//
// It panics if i is out of range.
func makeWrongChecksum(s string, i int) string {
	if i < 0 || i >= len(s) {
		panic(errors.AutoMsg(fmt.Sprintf(
			"i (%d) is out of range [0, %d]", i, len(s)-1)))
	} else if s[i] != '0' {
		return s[:i] + "0" + s[i+1:]
	}
	return s[:i] + "1" + s[i+1:]
}

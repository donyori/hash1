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

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/donyori/gogo/errors"
	"github.com/spf13/cobra"

	"github.com/donyori/hash1/hashcs"
)

// verifyCmd represents the verify command.
var verifyCmd = &cobra.Command{
	Use:   "verify [flags] [file]",
	Short: "Verify the hash checksum of the specified local file",
	Long: `Verify (hash1 verify) compares the hash checksum of the specified local file
with the expected value specified by the flags.
If they are consistent, it outputs "OK" and exits with error code 0.
If they are inconsistent, it outputs "FAIL" followed by the actual hash checksum,
then exits with error code 3. (Error code 1 is for program error; 2 is for program panic.)

The supported hash algorithms are listed as follows:
    MD4, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256,
    RIPEMD-160, SHA3-224, SHA3-256, SHA3-384, SHA3-512, BLAKE2s-256, BLAKE2b-256,
    BLAKE2b-384, BLAKE2b-512

The user can specify the hash checksum of one or more hash algorithms by corresponding flags.
If no hash checksum is specified, Verify reports an error.

The hash checksum must be provided in hexadecimal representation (case insensitive).
The user can specify either the entire hash checksum or an arbitrary prefix of it.
Moreover, the user can specify an arbitrary suffix by following "..." (three periods),
and can combine a prefix and a suffix by "..." (prefix and suffix cannot overlap each other).
For example:
    "hash1 verify -s 123abc FILE" specifies the expected SHA-256 hash checksum
with the prefix "123abc".
    "hash1 verify -s ...456def FILE" specifies the expected SHA-256 hash checksum
with the suffix "456def".
    "hash1 verify -s 123abc...456def FILE" specifies the expected SHA-256 hash checksum
with the prefix "123abc" and the suffix "456def".
In particular, it is also allowed to specify the hash checksum as "..." (only three periods).
In this case, the program reports OK as long as the hash checksum can be calculated.

The user can set the flag "silent" ("S" for short) to disable the output to the
standard output and error streams, including the result and program error messages,
excluding messages for the help and illegal use of this command.
It may be useful when using this program in scripts.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if verifyFlagSilent {
			defer func() {
				if err := recover(); err != nil {
					// In silent mode, capture any possible panic without
					// displaying anything, then exit with ExitCodePanic (2).
					os.Exit(ExitCodePanic)
				}
			}()
		}
		if len(args) == 0 {
			checkErr(globalFlagDebug, cmd.Help()) // display the help, even in silent mode
			return
		}
		mismatch, err, isIllegalUseError := verifyChecksum(
			args[0], &verifyFlagsHashChecksum)
		switch {
		case err != nil:
			if verifyFlagSilent && !isIllegalUseError {
				os.Exit(ExitCodeError)
			}
			checkErr(globalFlagDebug, err)
		case verifyFlagSilent:
			if len(mismatch) > 0 {
				os.Exit(ExitCodeVerifyFail)
			}
		case len(mismatch) == 0:
			fmt.Println("OK")
		default:
			fmt.Println("FAIL")
			for i := range mismatch {
				fmt.Printf("%s: %s\n",
					mismatch[i].HashName, mismatch[i].Checksum)
			}
			os.Exit(ExitCodeVerifyFail)
		}
	},
}

const (
	ExitCodeError int = 1 + iota
	ExitCodePanic
	ExitCodeVerifyFail
)

// Local flags used by the verify command.
var (
	verifyFlagSilent        bool
	verifyFlagsHashChecksum [hashcs.NumHash]string
)

// verifyFlagNamesHashChecksum are flag names
// corresponding to verifyFlagsHashChecksum.
//
// For each item (of type [2]string), the first element is the flag name,
// and the second element is the flag shorthand (empty for no shorthand).
var verifyFlagNamesHashChecksum = [hashcs.NumHash][2]string{
	{"md4"},
	{"md5", "m"},
	{"sha1"},
	{"sha224"},
	{"sha256", "s"},
	{"sha384"},
	{"sha512"},
	{"sha512-224"},
	{"sha512-256"},
	{"ripemd160"},
	{"sha3-224"},
	{"sha3-256"},
	{"sha3-384"},
	{"sha3-512"},
	{"blake2s-256"},
	{"blake2b-256"},
	{"blake2b-384"},
	{"blake2b-512"},
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().BoolVarP(&verifyFlagSilent, "silent", "S", false,
		`disable the output to the standard output and error streams,
including result and program error, excluding messages for
help and illegal use of this command`)

	for i := 0; i < hashcs.NumHash; i++ {
		verifyCmd.Flags().StringVarP(
			&verifyFlagsHashChecksum[i],
			verifyFlagNamesHashChecksum[i][0],
			verifyFlagNamesHashChecksum[i][1],
			"",
			"specify the expected "+hashcs.Hashes[i].String()+" hash checksum",
		)
	}
}

// expectedHashChecksum consists of the hash algorithm name and
// the prefix and suffix of the expected hash checksum.
type expectedHashChecksum struct {
	hashName string // Hash algorithm name, consistent with crypto.Hash.String.
	prefix   string // Expected hash checksum or its prefix, in lowercase.
	suffix   string // Expected hash checksum suffix, in lowercase.
}

// verifyChecksum calculates the hash checksum of the specified file,
// then compares the result with the expected values specified by the flags.
//
// It returns the hash checksums that mismatch the expected
// and any error encountered.
// It also reports whether the error is for illegal use of the command.
//
// Caller should guarantee that the array pointer flags is not nil.
func verifyChecksum(filename string, flags *[hashcs.NumHash]string) (
	mismatch []hashcs.HashChecksum, err error, isIllegalUseError bool) {
	if flags == nil {
		panic(errors.AutoMsg("flag array pointer is nil"))
	}
	expected, err := parseHashChecksumFlags(flags)
	if err != nil {
		return nil, errors.AutoWrap(err), true
	}
	n := len(expected)
	if n == 0 {
		return nil, errors.AutoNew("hash checksum not specified"), true
	}
	hashNames := make([]string, n)
	for i := 0; i < n; i++ {
		hashNames[i] = strings.ToLower(expected[i].hashName)
	}
	checksums, err := hashcs.CalculateChecksum(filename, false, hashNames)
	if err != nil {
		return nil, errors.AutoWrap(err), false
	} else if len(checksums) != n {
		return nil, errors.AutoWrap(fmt.Errorf(
			"got %d hash checksums; want %d",
			len(checksums), n,
		)), false
	}
	for i := 0; i < n; i++ {
		if expected[i].hashName != checksums[i].HashName {
			return nil, errors.AutoWrap(fmt.Errorf(
				"the hash name of No.%d hash checksum is %q; want %q",
				i, checksums[i].HashName, expected[i].hashName,
			)), false
		} else if !strings.HasPrefix(
			checksums[i].Checksum,
			expected[i].prefix,
		) || !strings.HasSuffix(
			checksums[i].Checksum[len(expected[i].prefix):],
			expected[i].suffix,
		) {
			mismatch = append(mismatch, checksums[i])
		}
	}
	return
}

// parseHashChecksumFlags parses hash checksum flags of the verify command
// to []expectedHashChecksum.
//
// It reports an error if any flag argument is invalid.
//
// Caller should guarantee that the array pointer flags is not nil.
func parseHashChecksumFlags(flags *[hashcs.NumHash]string) (
	expected []expectedHashChecksum, err error) {
	if flags == nil {
		panic(errors.AutoMsg("flag array pointer is nil"))
	}
	for i := 0; i < hashcs.NumHash; i++ {
		if flags[i] == "" {
			continue
		}
		prefix, suffix, _ := strings.Cut(strings.ToLower(flags[i]), "...")
		prefixTrimmed := strings.TrimPrefix(strings.TrimSpace(prefix), "0x")
		if notLowerHexString(prefixTrimmed) {
			return nil, errors.AutoWrap(fmt.Errorf(
				"invalid flag --%s: hash checksum prefix %q "+
					"is not a valid hexadecimal representation",
				verifyFlagNamesHashChecksum[i][0],
				prefix,
			))
		}
		suffixTrimmed := strings.TrimPrefix(strings.TrimSpace(suffix), "0x")
		if notLowerHexString(suffixTrimmed) {
			return nil, errors.AutoWrap(fmt.Errorf(
				"invalid flag --%s: hash checksum suffix %q "+
					"is not a valid hexadecimal representation",
				verifyFlagNamesHashChecksum[i][0],
				suffix,
			))
		}
		expected = append(expected, expectedHashChecksum{
			hashName: hashcs.Hashes[i].String(),
			prefix:   prefixTrimmed,
			suffix:   suffixTrimmed,
		})
	}
	return
}

// notLowerHexString reports whether s is not
// a valid lowercase hexadecimal representation.
func notLowerHexString(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' && r < 'a' || r > 'f' {
			return true
		}
	}
	return false
}

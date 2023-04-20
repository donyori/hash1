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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/donyori/gogo/errors"
	"github.com/donyori/gogo/filesys"
	"github.com/donyori/gogo/filesys/local"
	"github.com/spf13/cobra"

	"github.com/donyori/hash1/hashcs"
)

// printCmd represents the print command.
var printCmd = &cobra.Command{
	Use:   "print [flags] [file]",
	Short: "Output the hash checksum of the specified local file",
	Long: `Print (hash1 print) outputs the hash checksum of the specified local file
to the console or a target file (see the flag "output" ("o" for short)).

The 18 supported hash algorithms are listed as follows:
    MD4, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256,
    RIPEMD-160, SHA3-224, SHA3-256, SHA3-384, SHA3-512, BLAKE2s-256, BLAKE2b-256,
    BLAKE2b-384, BLAKE2b-512

The user can specify the hash algorithms using the flag "hash" ("H" for short).
The provided hash algorithm names must be in lowercase, separated by commas (',') or whitespaces.
The hyphens ('-') and slashes ('/') in the name can be replaced with underscores ('_')
or omitted (for example, "sha-512/224" can be "sha_512_224" or "sha512224").
Or more conveniently, the user can set the flag "md5" ("m" for short) to use MD5,
or set the flag "all" ("a" for short) to use all the 18 hash algorithms.
These three flags are mutually exclusive: only one of them can be used at the same time.
If the user does not specify a hash algorithm, SHA-256 is used by default.

The output format can be either plain text (by default)
or JSON (by setting the flag "json" ("j" for short)).

The checksum is in hexadecimal, and in lowercase by default.
To use uppercase, the user can set the flag "upper" ("u" for short).`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cobra.CheckErr(cmd.Help())
			return
		}
		var hashNames []string
		switch {
		case printFlagAll:
			hashNames = make([]string, len(hashcs.Names))
			for i := range hashNames {
				hashNames[i] = hashcs.Names[i][0]
			}
		case printFlagMD5:
			hashNames = []string{"md5"}
		case printFlagHash != "":
			hashNames = strings.FieldsFunc(printFlagHash, func(r rune) bool {
				return r == ',' || unicode.IsSpace(r)
			})
		}
		err := printChecksum(
			printFlagOutput,
			args[0],
			printFlagUpper,
			printFlagJSON,
			hashNames,
		)
		err, _ = errors.UnwrapAllAutoWrappedErrors(err)
		cobra.CheckErr(err)
	},
}

// Local flags used by the print command.
var (
	printFlagAll    bool
	printFlagHash   string
	printFlagJSON   bool
	printFlagMD5    bool
	printFlagOutput string
	printFlagUpper  bool
)

func init() {
	rootCmd.AddCommand(printCmd)

	printCmd.Flags().BoolVarP(&printFlagAll, "all", "a", false,
		"use all the supported hash algorithms")
	printCmd.Flags().StringVarP(&printFlagHash, "hash", "H", "",
		"specify hash algorithms (see help for details)")
	printCmd.Flags().BoolVarP(&printFlagJSON, "json", "j", false,
		"output the result in JSON format")
	printCmd.Flags().BoolVarP(&printFlagMD5, "md5", "m", false,
		"use the MD5 hash algorithm")
	printCmd.Flags().StringVarP(&printFlagOutput, "output", "o", "",
		`Specify the output file. In particular, "STDERR" (in uppercase) represents
the standard error stream. By default, the standard output stream is used.`)
	printCmd.Flags().BoolVarP(&printFlagUpper, "upper", "u", false,
		"output the result in uppercase (lowercase by default)")

	printCmd.MarkFlagsMutuallyExclusive("all", "hash", "md5")
}

// printChecksum calculates the hash checksum of the input file
// using the specified hash algorithms and outputs the result
// to the output file.
//
// It returns any error encountered.
//
// upper indicates whether to output the result in uppercase.
//
// inJSON indicates whether to output the result in JSON format.
func printChecksum(output, input string, upper, inJSON bool, hashNames []string) error {
	checksums, err := hashcs.CalculateChecksum(input, upper, hashNames)
	if err != nil {
		return errors.AutoWrap(err)
	}
	var w io.Writer
	switch output {
	case "":
		w = os.Stdout
	case "STDERR":
		w = os.Stderr
	default:
		writer, err := local.WriteTrunc(output, 0644, true, nil)
		if err != nil {
			return errors.AutoWrap(err)
		}
		defer func(writer filesys.Writer) {
			_ = writer.Close() // ignore error
		}(writer)
		w = writer
	}
	if inJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "    ")
		return errors.AutoWrap(enc.Encode(checksums))
	} else {
		for i := range checksums {
			_, err = fmt.Fprintf(w, "%s: %s\n",
				checksums[i].HashName, checksums[i].Checksum)
			if err != nil {
				return errors.AutoWrap(err)
			}
		}
		return nil
	}
}

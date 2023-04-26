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
	"strings"

	"github.com/donyori/gogo/errors"
	"github.com/spf13/cobra"
)

// appendFunctionNamesToError appends the full function names recorded in
// github.com/donyori/gogo/errors.AutoWrappedError to the end of
// the error message of the root error of the AutoWrappedError,
// one function name per line.
//
// If err is a github.com/donyori/gogo/errors.AutoWrappedError,
// appendFunctionNamesToError returns the error message of type string.
//
// Otherwise, appendFunctionNamesToError returns err itself.
//
// The result can work well with function github.com/spf13/cobra.CheckErr.
func appendFunctionNamesToError(err error) any {
	names, err := errors.ListFunctionNamesInAutoWrappedErrors(err)
	if len(names) == 0 {
		return err
	}
	var b strings.Builder
	b.WriteString(err.Error())
	var notFirst bool
	for _, name := range names {
		switch {
		case name == "":
			continue
		case notFirst:
			b.WriteString("\n    <- ")
		default:
			notFirst = true
			b.WriteString("\nError function chain:\n    ")
		}
		b.WriteString(name)
	}
	return b.String()
}

// checkErr applies appendFunctionNamesToError to err if debugFlag is set.
// Otherwise, checkErr applies
// github.com/donyori/gogo/errors.UnwrapAllAutoWrappedErrors to err.
// Finally, checkErr calls github.com/spf13/cobra.CheckErr on the above result.
func checkErr(debugFlag bool, err error) {
	var errMsg any
	if debugFlag {
		errMsg = appendFunctionNamesToError(err)
	} else {
		errMsg, _ = errors.UnwrapAllAutoWrappedErrors(err)
	}
	cobra.CheckErr(errMsg)
}

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
	"fmt"
	"strconv"
	"testing"

	"github.com/donyori/gogo/errors"

	"github.com/donyori/hash1/cmd"
)

func TestAppendFunctionNamesToError(t *testing.T) {
	var errs [6]error
	errs[0] = errors.New("test error")
	func() {
		// This function name:
		// "github.com/donyori/hash1/cmd_test.TestAppendFunctionNamesToError.func1".
		errs[1] = errors.AutoWrap(errs[0])
	}()
	errs[2] = fmt.Errorf("wrapping %w", errs[1])
	func() {
		// This function name:
		// "github.com/donyori/hash1/cmd_test.TestAppendFunctionNamesToError.func2".
		errs[3] = errors.AutoWrap(errs[2])
	}()
	func() {
		// This function name:
		// "github.com/donyori/hash1/cmd_test.TestAppendFunctionNamesToError.func3".
		errs[4] = errors.AutoWrap(errs[3])
	}()
	func() {
		// This function name:
		// "github.com/donyori/hash1/cmd_test.TestAppendFunctionNamesToError.func4".
		errs[5] = errors.AutoWrap(errs[4])
	}()

	testCases := []struct {
		err  error
		want any
	}{
		{nil, nil},
		{errs[0], errs[0]},
		{errs[1], errs[0].Error() + `
Error function chain:
    github.com/donyori/hash1/cmd_test.TestAppendFunctionNamesToError.func1`},
		{errs[2], errs[2]},
		{errs[3], errs[2].Error() + `
Error function chain:
    github.com/donyori/hash1/cmd_test.TestAppendFunctionNamesToError.func2`},
		{errs[4], errs[2].Error() + `
Error function chain:
    github.com/donyori/hash1/cmd_test.TestAppendFunctionNamesToError.func3
    <- github.com/donyori/hash1/cmd_test.TestAppendFunctionNamesToError.func2`},
		{errs[5], errs[2].Error() + `
Error function chain:
    github.com/donyori/hash1/cmd_test.TestAppendFunctionNamesToError.func4
    <- github.com/donyori/hash1/cmd_test.TestAppendFunctionNamesToError.func3
    <- github.com/donyori/hash1/cmd_test.TestAppendFunctionNamesToError.func2`},
	}

	for i, tc := range testCases {
		errName := "<nil>"
		if tc.err != nil {
			errName = strconv.QuoteToASCII(tc.err.Error())
		}
		t.Run(fmt.Sprintf("case %d?err=%s", i, errName), func(t *testing.T) {
			got := cmd.AppendFunctionNamesToError(tc.err)
			if got != tc.want {
				t.Errorf("got (type: %T) %[1]s\nwant (type: %T) %[2]s",
					got, tc.want)
			}
		})
	}
}

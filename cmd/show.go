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

	"github.com/donyori/gogo/copyright/agpl3"
	"github.com/spf13/cobra"
)

// showCmd represents the show command.
var showCmd = &cobra.Command{
	Use:   "show [flags] [w|warranty|c|conditions]",
	Short: "Print the disclaimer of warranty or the terms and conditions of the license",
	Long: `Show (hash1 show) prints the disclaimer of warranty or the terms and conditions
of the GNU Affero General Public License.

    "hash1 show w" or "hash1 show warranty" prints the disclaimer of warranty.
    "hash1 show c" or "hash1 show conditions" prints the terms and conditions.`,
	ValidArgs: []string{"w", "c", "warranty", "conditions"},
	Args:      cobra.MatchAll(cobra.MaximumNArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cobra.CheckErr(cmd.Help())
		} else if args[0] == "w" || args[0] == "warranty" {
			fmt.Println(agpl3.DisclaimerOfWarranty)
		} else {
			fmt.Println(agpl3.TermsAndConditions)
		}
	},
}

func init() {
	rootCmd.AddCommand(showCmd)
}

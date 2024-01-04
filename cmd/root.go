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
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "hash1",
	Short: "A tool to calculate the hash checksum of one local file",
	Long: `hash1 calculates the hash checksum of one local file
and then prints it (hash1 print) or compares it with
the expected value (hash1 verify).`,
	Version: "0.1.2",
}

// Execute adds all child commands to the root command
// and sets flags appropriately.
// This is called by main.main().
// It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// globalFlagDebug is a global flag for debugging mode.
var globalFlagDebug bool

func init() {
	// Prepend a short copyright notice to the default help template.
	rootCmd.SetHelpTemplate(`hash1  Copyright (C) 2023  Yuan Gao
This program comes with ABSOLUTELY NO WARRANTY; for details type "hash1 show w".
This is free software, and you are welcome to redistribute it
under certain conditions; type "hash1 show c" for details.
Program source: <https://github.com/donyori/hash1>.

{{with (or .Long .Short)}}{{. | trimTrailingWhitespaces}}

{{end}}{{if or .Runnable .HasSubCommands}}{{.UsageString}}{{end}}`)

	// Append a short copyright notice to the default version template
	// and replace "version " with "v".
	rootCmd.SetVersionTemplate(`{{with .Name}}{{printf "%s " .}}{{end}}{{printf "v%s" .Version}}
Copyright (C) 2023  Yuan Gao
This program comes with ABSOLUTELY NO WARRANTY; for details type "hash1 show w".
This is free software, and you are welcome to redistribute it
under certain conditions; type "hash1 show c" for details.
Program source: <https://github.com/donyori/hash1>.
`)

	rootCmd.PersistentFlags().BoolVar(&globalFlagDebug, "debug", false,
		"print more information when encountering an error")
}

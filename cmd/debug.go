// Copyright © 2023 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	bpf "github.com/moolen/skouter/pkg/controller"
	"github.com/spf13/cobra"
)

// debugCmd represents the debug command
var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		err := bpf.DumpConfig(bpffs, cacheStoragePath)
		if err != nil {
			logger.Error(err, "unable to dump config")
		}
	},
}

func init() {
	rootCmd.AddCommand(debugCmd)
}

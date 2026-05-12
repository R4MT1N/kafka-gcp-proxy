package server

import (
	"fmt"
	"github.com/R4MT1N/kafka-gcp-proxy/config"
	"github.com/spf13/cobra"
)

var Version = &cobra.Command{
	Use:   "version",
	Short: "Print the kafka-proxy version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(config.Version)
	},
}

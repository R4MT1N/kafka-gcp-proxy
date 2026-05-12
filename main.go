package main

import (
	"fmt"
	"os"

	server "github.com/R4MT1N/kafka-gcp-proxy/cmd/kafka-proxy"
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "kafka-gcp-proxy",
	Short: "Sidecar that proxies plain local Kafka clients to GCP Managed Kafka (SASL/OAUTHBEARER over TLS)",
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
		os.Exit(1)
	},
}

func init() {
	RootCmd.AddCommand(server.Server)
	RootCmd.AddCommand(server.Version)
}

func main() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

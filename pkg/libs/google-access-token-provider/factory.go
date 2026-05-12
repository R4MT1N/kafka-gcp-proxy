package googleaccesstokenprovider

import (
	"flag"

	"github.com/R4MT1N/kafka-gcp-proxy/pkg/apis"
	"github.com/R4MT1N/kafka-gcp-proxy/pkg/registry"
)

func init() {
	registry.NewComponentInterface(new(apis.TokenProviderFactory))
	registry.Register(new(Factory), "google-access-token-provider")
}

func (f *pluginMeta) flagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("google access-token provider settings", flag.ContinueOnError)
	return fs
}

type pluginMeta struct {
	timeout         int
	adc             bool
	credentialsFile string
	scope           string
}

type Factory struct {
}

// New implements apis.TokenProviderFactory.
func (t *Factory) New(params []string) (apis.TokenProvider, error) {
	pluginMeta := &pluginMeta{}
	fs := pluginMeta.flagSet()
	fs.IntVar(&pluginMeta.timeout, "timeout", 10, "Request timeout in seconds")
	fs.BoolVar(&pluginMeta.adc, "adc", false, "Use Google Application Default Credentials instead of a ServiceAccount JSON file")
	fs.StringVar(&pluginMeta.credentialsFile, "credentials-file", "", "Path to a Google service account JSON key (sets GOOGLE_APPLICATION_CREDENTIALS)")
	fs.StringVar(&pluginMeta.scope, "scope", "https://www.googleapis.com/auth/cloud-platform", "OAuth 2.0 scope for the access token")

	if err := fs.Parse(params); err != nil {
		return nil, err
	}

	options := TokenProviderOptions{
		Timeout:         pluginMeta.timeout,
		Adc:             pluginMeta.adc,
		CredentialsFile: pluginMeta.credentialsFile,
		Scope:           pluginMeta.scope,
	}

	return NewTokenProvider(options)
}

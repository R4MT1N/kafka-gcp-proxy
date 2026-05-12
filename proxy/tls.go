package proxy

import (
	"crypto/tls"
	"log/slog"

	tlsconfig "github.com/grepplabs/cert-source/config"
	tlsclientconfig "github.com/grepplabs/cert-source/tls/client/config"

	"github.com/R4MT1N/kafka-gcp-proxy/config"
)

// newTLSClientConfig builds the TLS config used when dialing upstream brokers.
// Listener-side TLS is intentionally not supported — clients connect to the
// proxy on plain localhost.
func newTLSClientConfig(conf *config.Config) (TLSConfigFunc, error) {
	opts := conf.Kafka.TLS
	clientConfig := &tlsconfig.TLSClientConfig{
		Enable:             true,
		Refresh:            opts.Refresh,
		InsecureSkipVerify: opts.InsecureSkipVerify,
		UseSystemPool:      opts.SystemCertPool,
	}
	if opts.CAChainCertFile != "" {
		clientConfig.File = tlsconfig.TLSClientFiles{RootCAs: opts.CAChainCertFile}
	}
	tlsConfigFunc, err := tlsclientconfig.GetTLSClientConfigFunc(slog.Default(), clientConfig)
	if err != nil {
		return nil, err
	}
	return func() *tls.Config {
		return tlsConfigFunc()
	}, nil
}

// Package googleaccesstokenprovider implements a SASL OAUTHBEARER TokenProvider
// that returns Google OAuth 2.0 access tokens. It is intended for upstream
// authentication to services that accept Google ADC-issued bearer tokens, such
// as Google Cloud Managed Service for Apache Kafka.
//
// Unlike the google-id-provider plugin (which issues OIDC ID tokens for
// proxy-to-proxy auth), this plugin produces opaque access tokens and relies on
// golang.org/x/oauth2's ReuseTokenSource for cache + refresh-before-expiry.
package googleaccesstokenprovider

import (
	"context"
	"os"
	"time"

	"github.com/R4MT1N/kafka-gcp-proxy/pkg/apis"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	StatusOK             = 0
	StatusGetTokenFailed = 1
)

// tokenSource is satisfied by oauth2.TokenSource. Defined locally so tests can
// inject fakes without depending on the oauth2 package.
type tokenSource interface {
	Token() (*oauth2.Token, error)
}

type TokenProvider struct {
	timeout time.Duration
	source  tokenSource
}

type TokenProviderOptions struct {
	Timeout         int
	Adc             bool
	CredentialsFile string
	Scope           string
}

// NewTokenProvider builds a TokenProvider backed by Google ADC. It performs an
// initial token fetch to surface auth misconfiguration at startup rather than
// at first Kafka connection.
func NewTokenProvider(options TokenProviderOptions) (*TokenProvider, error) {
	if options.Scope == "" {
		return nil, errors.New("parameter scope is required")
	}
	if !options.Adc && options.CredentialsFile == "" {
		return nil, errors.New("either --adc=true or --credentials-file must be set")
	}
	if options.CredentialsFile != "" {
		// Canonical ADC behaviour: set the env var, then let DefaultTokenSource
		// pick it up. Avoids duplicating CredentialsFromJSON logic.
		if err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", options.CredentialsFile); err != nil {
			return nil, errors.Wrap(err, "setting GOOGLE_APPLICATION_CREDENTIALS")
		}
	}

	// context.Background — the token source must outlive any per-request ctx.
	src, err := google.DefaultTokenSource(context.Background(), options.Scope)
	if err != nil {
		return nil, errors.Wrap(err, "creating google default token source")
	}
	// ReuseTokenSource handles caching + refresh-before-expiry internally; it
	// is goroutine-safe so we don't need our own mutex around p.source.
	reusable := oauth2.ReuseTokenSource(nil, src)

	p := &TokenProvider{
		timeout: time.Duration(options.Timeout) * time.Second,
		source:  reusable,
	}

	// Fail-fast on misconfiguration: do one fetch now.
	if _, err := p.source.Token(); err != nil {
		return nil, errors.Wrap(err, "initial google access token fetch failed")
	}
	return p, nil
}

// GetToken implements apis.TokenProvider.
func (p *TokenProvider) GetToken(_ context.Context, _ apis.TokenRequest) (apis.TokenResponse, error) {
	tok, err := p.source.Token()
	if err != nil {
		// Fail-closed. Returning a stale token would let traffic continue with
		// an expired credential and obscure the real failure.
		logrus.Errorf("failed to fetch google access token: %v", err)
		return apis.TokenResponse{Success: false, Status: int32(StatusGetTokenFailed)}, nil
	}
	return apis.TokenResponse{Success: true, Status: int32(StatusOK), Token: tok.AccessToken}, nil
}

// Package googleaccesstokenprovider implements a SASL OAUTHBEARER TokenProvider
// for GCP Managed Service for Apache Kafka. The Managed Kafka broker does not
// accept raw OAuth access tokens — it expects a Google-specific JWT envelope:
//
//	base64url(header) . base64url(payload) . base64url(access_token)
//
// where header is {"typ":"JWT","alg":"GOOG_OAUTH2_TOKEN"} and payload carries
// iss/sub/iat/exp claims (sub = service account email). This mirrors the
// reference implementation at:
//
//	https://github.com/googleapis/managedkafka/blob/main/kafka-auth-local-server/kafka_gcp_credentials_server.py
package googleaccesstokenprovider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"cloud.google.com/go/compute/metadata"
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
	timeout            time.Duration
	source             tokenSource
	serviceAccountEmail string
}

type TokenProviderOptions struct {
	Timeout         int
	Adc             bool
	CredentialsFile string
	Scope           string
}

// NewTokenProvider builds a TokenProvider backed by Google ADC. It performs an
// initial token fetch and SA-email discovery to surface auth misconfiguration
// at startup rather than at first Kafka connection.
func NewTokenProvider(options TokenProviderOptions) (*TokenProvider, error) {
	if options.Scope == "" {
		return nil, errors.New("parameter scope is required")
	}
	if !options.Adc && options.CredentialsFile == "" {
		return nil, errors.New("either --adc=true or --credentials-file must be set")
	}
	if options.CredentialsFile != "" {
		if err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", options.CredentialsFile); err != nil {
			return nil, errors.Wrap(err, "setting GOOGLE_APPLICATION_CREDENTIALS")
		}
	}

	src, err := google.DefaultTokenSource(context.Background(), options.Scope)
	if err != nil {
		return nil, errors.Wrap(err, "creating google default token source")
	}
	reusable := oauth2.ReuseTokenSource(nil, src)

	email, err := discoverServiceAccountEmail(options.CredentialsFile)
	if err != nil {
		return nil, errors.Wrap(err, "discovering service account email")
	}
	logrus.Infof("google-access-token-provider: authenticating as %s", email)

	p := &TokenProvider{
		timeout:             time.Duration(options.Timeout) * time.Second,
		source:              reusable,
		serviceAccountEmail: email,
	}
	if _, err := p.source.Token(); err != nil {
		return nil, errors.Wrap(err, "initial google access token fetch failed")
	}
	return p, nil
}

// discoverServiceAccountEmail finds the SA email from the credentials file (if
// set) or the GCE/GKE metadata server otherwise. Required for the Managed Kafka
// JWT envelope's "sub" claim.
func discoverServiceAccountEmail(credentialsFile string) (string, error) {
	if credentialsFile != "" {
		raw, err := os.ReadFile(credentialsFile)
		if err != nil {
			return "", errors.Wrap(err, "reading credentials file")
		}
		var sa struct {
			ClientEmail string `json:"client_email"`
		}
		if err := json.Unmarshal(raw, &sa); err != nil {
			return "", errors.Wrap(err, "parsing credentials file")
		}
		if sa.ClientEmail == "" {
			return "", errors.New("credentials file has no client_email — not a service account key?")
		}
		return sa.ClientEmail, nil
	}
	email, err := metadata.EmailWithContext(context.Background(), "default")
	if err != nil {
		return "", errors.Wrap(err, "querying metadata server")
	}
	return email, nil
}

func (p *TokenProvider) GetToken(_ context.Context, _ apis.TokenRequest) (apis.TokenResponse, error) {
	tok, err := p.source.Token()
	if err != nil {
		logrus.Errorf("failed to fetch google access token: %v", err)
		return apis.TokenResponse{Success: false, Status: int32(StatusGetTokenFailed)}, nil
	}
	wrapped, err := wrapForManagedKafka(tok, p.serviceAccountEmail)
	if err != nil {
		logrus.Errorf("failed to wrap access token for managed kafka: %v", err)
		return apis.TokenResponse{Success: false, Status: int32(StatusGetTokenFailed)}, nil
	}
	return apis.TokenResponse{Success: true, Status: int32(StatusOK), Token: wrapped}, nil
}

// wrapForManagedKafka builds the Google-specific OAUTHBEARER envelope expected
// by GCP Managed Kafka brokers: base64url(header).base64url(payload).base64url(access_token).
// All three segments use unpadded base64url, matching the reference Python
// implementation byte-for-byte.
func wrapForManagedKafka(tok *oauth2.Token, saEmail string) (string, error) {
	header, err := json.Marshal(map[string]string{"typ": "JWT", "alg": "GOOG_OAUTH2_TOKEN"})
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	exp := tok.Expiry.UTC()
	if exp.IsZero() {
		// oauth2 sometimes returns zero expiry for non-expiring sources; default
		// to one hour so the broker doesn't reject for a missing exp claim.
		exp = now.Add(time.Hour)
	}
	payload, err := json.Marshal(map[string]any{
		"exp": float64(exp.Unix()),
		"iss": "Google",
		"iat": float64(now.Unix()),
		"sub": saEmail,
	})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString
	return fmt.Sprintf("%s.%s.%s", enc(header), enc(payload), enc([]byte(tok.AccessToken))), nil
}

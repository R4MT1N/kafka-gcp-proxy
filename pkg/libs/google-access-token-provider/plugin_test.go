package googleaccesstokenprovider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/R4MT1N/kafka-gcp-proxy/pkg/apis"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

const testSAEmail = "svc@project.iam.gserviceaccount.com"

type fakeTokenSource struct {
	tokens []*oauth2.Token
	err    error
	mu     sync.Mutex
	calls  int32
}

func (f *fakeTokenSource) Token() (*oauth2.Token, error) {
	atomic.AddInt32(&f.calls, 1)
	if f.err != nil {
		return nil, f.err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.tokens) == 0 {
		return nil, fmt.Errorf("fake source exhausted")
	}
	t := f.tokens[0]
	if len(f.tokens) > 1 {
		f.tokens = f.tokens[1:]
	}
	return t, nil
}

// unwrap parses the three-part envelope and returns (header, payload, token).
func unwrap(t *testing.T, envelope string) (map[string]any, map[string]any, string) {
	t.Helper()
	parts := strings.Split(envelope, ".")
	if len(parts) != 3 {
		t.Fatalf("envelope must have 3 parts, got %d: %q", len(parts), envelope)
	}
	decode := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("base64 decode failed for %q: %v", s, err)
		}
		return b
	}
	var header, payload map[string]any
	if err := json.Unmarshal(decode(parts[0]), &header); err != nil {
		t.Fatalf("header parse failed: %v", err)
	}
	if err := json.Unmarshal(decode(parts[1]), &payload); err != nil {
		t.Fatalf("payload parse failed: %v", err)
	}
	return header, payload, string(decode(parts[2]))
}

func TestGetToken_HappyPath(t *testing.T) {
	a := assert.New(t)
	src := &fakeTokenSource{tokens: []*oauth2.Token{
		{AccessToken: "ya29.fresh-token", Expiry: time.Now().Add(time.Hour)},
	}}
	p := &TokenProvider{timeout: 10 * time.Second, source: src, serviceAccountEmail: testSAEmail}

	resp, err := p.GetToken(context.Background(), apis.TokenRequest{})
	a.Nil(err)
	a.True(resp.Success)
	a.Equal(int32(StatusOK), resp.Status)

	header, payload, accessToken := unwrap(t, resp.Token)
	a.Equal("JWT", header["typ"])
	a.Equal("GOOG_OAUTH2_TOKEN", header["alg"])
	a.Equal("Google", payload["iss"])
	a.Equal(testSAEmail, payload["sub"])
	a.Equal("ya29.fresh-token", accessToken)
}

// TestGetToken_RefreshAfterExpiry catches the most likely regression: silent
// reuse of expired tokens. The first call seeds the ReuseTokenSource cache
// with the expired token; the second call sees it's past expiry and re-fetches.
func TestGetToken_RefreshAfterExpiry(t *testing.T) {
	a := assert.New(t)
	src := &fakeTokenSource{tokens: []*oauth2.Token{
		{AccessToken: "expired", Expiry: time.Now().Add(-time.Minute)},
		{AccessToken: "refreshed", Expiry: time.Now().Add(time.Hour)},
	}}
	reusable := oauth2.ReuseTokenSource(nil, src)
	p := &TokenProvider{timeout: 10 * time.Second, source: reusable, serviceAccountEmail: testSAEmail}

	first, err := p.GetToken(context.Background(), apis.TokenRequest{})
	a.Nil(err)
	_, _, t1 := unwrap(t, first.Token)
	a.Equal("expired", t1)

	second, err := p.GetToken(context.Background(), apis.TokenRequest{})
	a.Nil(err)
	_, _, t2 := unwrap(t, second.Token)
	a.Equal("refreshed", t2, "ReuseTokenSource should refresh once the cached token is past expiry")
}

func TestGetToken_FetchFailureFailsClosed(t *testing.T) {
	a := assert.New(t)
	src := &fakeTokenSource{err: fmt.Errorf("ADC unavailable")}
	p := &TokenProvider{timeout: 10 * time.Second, source: src, serviceAccountEmail: testSAEmail}

	resp, err := p.GetToken(context.Background(), apis.TokenRequest{})
	a.Nil(err, "GetToken returns nil error and signals via Success=false")
	a.Equal(apis.TokenResponse{Success: false, Status: int32(StatusGetTokenFailed), Token: ""}, resp)
}

// TestGetToken_Concurrent must be run with -race to be meaningful.
func TestGetToken_Concurrent(t *testing.T) {
	a := assert.New(t)
	src := &fakeTokenSource{tokens: []*oauth2.Token{
		{AccessToken: "tok", Expiry: time.Now().Add(time.Hour)},
	}}
	reusable := oauth2.ReuseTokenSource(nil, src)
	p := &TokenProvider{timeout: 10 * time.Second, source: reusable, serviceAccountEmail: testSAEmail}

	var wg sync.WaitGroup
	const N = 50
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := p.GetToken(context.Background(), apis.TokenRequest{})
			a.Nil(err)
			a.True(resp.Success)
			_, _, accessToken := unwrap(t, resp.Token)
			a.Equal("tok", accessToken)
		}()
	}
	wg.Wait()
}

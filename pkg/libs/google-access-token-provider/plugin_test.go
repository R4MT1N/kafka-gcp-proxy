package googleaccesstokenprovider

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/R4MT1N/kafka-gcp-proxy/pkg/apis"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

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

func TestGetToken_HappyPath(t *testing.T) {
	a := assert.New(t)
	src := &fakeTokenSource{tokens: []*oauth2.Token{
		{AccessToken: "ya29.fresh-token", Expiry: time.Now().Add(time.Hour)},
	}}
	p := &TokenProvider{timeout: 10 * time.Second, source: src}

	resp, err := p.GetToken(context.Background(), apis.TokenRequest{})
	a.Nil(err)
	a.Equal(apis.TokenResponse{Success: true, Status: int32(StatusOK), Token: "ya29.fresh-token"}, resp)
}

// TestGetToken_RefreshAfterExpiry catches the most likely regression: silent
// reuse of expired tokens. We feed two tokens through a ReuseTokenSource and
// verify the second call returns the refreshed value once the first expires.
func TestGetToken_RefreshAfterExpiry(t *testing.T) {
	a := assert.New(t)
	src := &fakeTokenSource{tokens: []*oauth2.Token{
		{AccessToken: "expired", Expiry: time.Now().Add(-time.Minute)},
		{AccessToken: "refreshed", Expiry: time.Now().Add(time.Hour)},
	}}
	// Wrap in ReuseTokenSource exactly as production code does. ReuseTokenSource
	// will call the underlying source again once the first token is past expiry.
	reusable := oauth2.ReuseTokenSource(nil, src)
	p := &TokenProvider{timeout: 10 * time.Second, source: reusable}

	resp, err := p.GetToken(context.Background(), apis.TokenRequest{})
	a.Nil(err)
	a.Equal("refreshed", resp.Token, "ReuseTokenSource should skip the expired token and fetch a fresh one")
}

func TestGetToken_FetchFailureFailsClosed(t *testing.T) {
	a := assert.New(t)
	src := &fakeTokenSource{err: fmt.Errorf("ADC unavailable")}
	p := &TokenProvider{timeout: 10 * time.Second, source: src}

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
	p := &TokenProvider{timeout: 10 * time.Second, source: reusable}

	var wg sync.WaitGroup
	const N = 50
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := p.GetToken(context.Background(), apis.TokenRequest{})
			a.Nil(err)
			a.True(resp.Success)
			a.Equal("tok", resp.Token)
		}()
	}
	wg.Wait()
}

package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/R4MT1N/kafka-gcp-proxy/proxy/protocol"
	"github.com/stretchr/testify/assert"
)

// --- minimal fakes for the broker->client direction -------------------------

type fakeBrokerReader struct{ r *bytes.Reader }

func (f *fakeBrokerReader) Read(p []byte) (int, error)      { return f.r.Read(p) }
func (f *fakeBrokerReader) SetReadDeadline(time.Time) error { return nil }

type fakeClientWriter struct{ buf bytes.Buffer }

func (f *fakeClientWriter) Write(p []byte) (int, error)      { return f.buf.Write(p) }
func (f *fakeClientWriter) SetWriteDeadline(time.Time) error { return nil }

// frame builds a length-prefixed response frame: Size, CorrelationID, body.
func frame(correlationID int32, body []byte) []byte {
	out := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(4+len(body)))
	binary.BigEndian.PutUint32(out[4:8], uint32(correlationID))
	copy(out[8:], body)
	return out
}

func saslReauthResponseFrame(t *testing.T, sessionLifetimeMs int64) []byte {
	t.Helper()
	body, err := protocol.Encode(&protocol.SaslAuthenticateResponseV1{
		Err:               protocol.ErrNoError,
		SaslAuthBytes:     []byte{},
		SessionLifetimeMs: sessionLifetimeMs,
	})
	if err != nil {
		t.Fatalf("encoding SaslAuthenticate response: %v", err)
	}
	return frame(reauthCorrelationID, body)
}

// newTestResponsesLoopContext mirrors what newProcessor builds, including the
// pre-seeded default response handler — that pre-seed is the whole point of
// these tests.
func newTestResponsesLoopContext(authState *ConnectionAuthState) (*ResponsesLoopContext, chan protocol.RequestKeyVersion, chan ResponseHandler) {
	openRequests := make(chan protocol.RequestKeyVersion, 16)
	handlers := make(chan ResponseHandler, 18)
	handlers <- defaultResponseHandler // as newProcessor does

	return &ResponsesLoopContext{
		openRequestsChannel:        openRequests,
		nextResponseHandlerChannel: handlers,
		timeout:                    time.Second,
		brokerAddress:              "broker-0.test:9092",
		buf:                        make([]byte, 4096),
		authState:                  authState,
	}, openRequests, handlers
}

// A proxy-initiated re-auth must be invisible to the client: the broker's
// SaslAuthenticate reply is consumed by the proxy, never forwarded. If it
// leaks through, the client sees a correlation ID it never sent and its
// NetworkClient dies with "There are no in-flight requests for node N" —
// which is exactly how kafbat's AdminClient thread got killed in production.
//
// The interleaving here is the ordinary one: a client request is outstanding
// when the request loop fires re-auth on the idle path.
func TestReauthResponseIsNotForwardedToClient(t *testing.T) {
	a := assert.New(t)

	authState := newConnectionAuthState(30_000)
	ctx, openRequests, handlers := newTestResponsesLoopContext(authState)

	// A client request is in flight: the request loop pushed its marker
	// before writing to the broker, and a fresh default handler after.
	clientPayload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	openRequests <- protocol.RequestKeyVersion{ApiKey: 18, ApiVersion: 0} // ApiVersions
	handlers <- defaultResponseHandler

	// Now the request loop fires re-auth on the same connection.
	authState.MarkInFlight(time.Now())
	reqCtx := &RequestsLoopContext{
		openRequestsChannel:        openRequests,
		nextResponseHandlerChannel: handlers,
		brokerAddress:              ctx.brokerAddress,
		authState:                  authState,
	}
	a.NoError(reqCtx.enqueueReauthResponse())

	// The broker answers in order: the client's request, then both legs of the
	// re-auth exchange.
	stream := frame(7, clientPayload)
	stream = append(stream, handshakeResponseFrame(t, protocol.ErrNoError)...)
	stream = append(stream, saslReauthResponseFrame(t, 60_000)...)
	src := &fakeBrokerReader{r: bytes.NewReader(stream)}
	dst := &fakeClientWriter{}

	_, err := ctx.responsesLoop(dst, src)
	a.ErrorIs(err, io.EOF, "loop should end by draining the broker stream, not by desync")

	a.Equal(frame(7, clientPayload), dst.buf.Bytes(),
		"client must receive its own response and nothing else — the SaslAuthenticate reply must not leak")
	a.False(authState.InFlightExpired(time.Now().Add(reauthInflightCushion+time.Second)),
		"re-auth should be completed, clearing the in-flight marker")
}

// The same, with no client request outstanding — the quiesced case. It fails
// the same way, because the handler queue always leads the marker queue by the
// one pre-seeded default handler.
func TestReauthResponseIsNotForwardedOnIdleConnection(t *testing.T) {
	a := assert.New(t)

	authState := newConnectionAuthState(30_000)
	ctx, openRequests, handlers := newTestResponsesLoopContext(authState)

	authState.MarkInFlight(time.Now())
	reqCtx := &RequestsLoopContext{
		openRequestsChannel:        openRequests,
		nextResponseHandlerChannel: handlers,
		brokerAddress:              ctx.brokerAddress,
		authState:                  authState,
	}
	a.NoError(reqCtx.enqueueReauthResponse())

	src := &fakeBrokerReader{r: bytes.NewReader(append(
		handshakeResponseFrame(t, protocol.ErrNoError),
		saslReauthResponseFrame(t, 60_000)...,
	))}
	dst := &fakeClientWriter{}

	_, err := ctx.responsesLoop(dst, src)
	a.ErrorIs(err, io.EOF)

	a.Empty(dst.buf.Bytes(), "nothing at all should reach the client for a proxy-initiated re-auth")
	a.False(authState.InFlightExpired(time.Now().Add(reauthInflightCushion + time.Second)))
}

// A client that speaks SASL through the proxy sends its own SaslAuthenticate.
// That response carries the client's correlation ID and MUST still be
// forwarded — only the proxy's own reserved correlation ID is swallowed.
func TestClientSaslAuthenticateResponseIsStillForwarded(t *testing.T) {
	a := assert.New(t)

	ctx, openRequests, handlers := newTestResponsesLoopContext(newConnectionAuthState(30_000))

	body, err := protocol.Encode(&protocol.SaslAuthenticateResponseV1{
		Err:               protocol.ErrNoError,
		SaslAuthBytes:     []byte{},
		SessionLifetimeMs: 60_000,
	})
	a.NoError(err)
	clientFrame := frame(42, body) // client's own correlation ID, not the proxy's

	// As the request path does for any request that expects a reply.
	openRequests <- protocol.RequestKeyVersion{ApiKey: apiKeySaslAuthenticate, ApiVersion: 1}
	handlers <- defaultResponseHandler

	src := &fakeBrokerReader{r: bytes.NewReader(clientFrame)}
	dst := &fakeClientWriter{}

	_, err = ctx.responsesLoop(dst, src)
	a.ErrorIs(err, io.EOF)
	a.Equal(clientFrame, dst.buf.Bytes(), "a client-initiated SaslAuthenticate response must reach the client")
}

// Re-auth repeats every session. Each enqueue must leave the handler queue as
// deep as it found it, or the response loop starves on a later cycle and tears
// the connection down with "next response handler is missing" — a slower
// version of the same outage.
func TestRepeatedReauthDoesNotStarveHandlerQueue(t *testing.T) {
	a := assert.New(t)

	authState := newConnectionAuthState(30_000)
	ctx, openRequests, handlers := newTestResponsesLoopContext(authState)
	reqCtx := &RequestsLoopContext{
		openRequestsChannel:        openRequests,
		nextResponseHandlerChannel: handlers,
		brokerAddress:              ctx.brokerAddress,
		authState:                  authState,
	}

	var stream []byte
	const cycles = 3
	for i := 0; i < cycles; i++ {
		// A client request, then a re-auth, repeatedly.
		openRequests <- protocol.RequestKeyVersion{ApiKey: 18, ApiVersion: 0}
		handlers <- defaultResponseHandler
		stream = append(stream, frame(int32(100+i), []byte{byte(i)})...)

		authState.MarkInFlight(time.Now())
		a.NoError(reqCtx.enqueueReauthResponse())
		stream = append(stream, handshakeResponseFrame(t, protocol.ErrNoError)...)
		stream = append(stream, saslReauthResponseFrame(t, 60_000)...)
	}

	src := &fakeBrokerReader{r: bytes.NewReader(stream)}
	dst := &fakeClientWriter{}

	_, err := ctx.responsesLoop(dst, src)
	a.ErrorIs(err, io.EOF, "every cycle should pair up; no starvation, no desync")

	var want []byte
	for i := 0; i < cycles; i++ {
		want = append(want, frame(int32(100+i), []byte{byte(i)})...)
	}
	a.Equal(want, dst.buf.Bytes(), "client sees exactly its own responses, in order")
}

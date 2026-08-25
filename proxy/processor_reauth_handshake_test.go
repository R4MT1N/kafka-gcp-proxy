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

// fakeSaslAuthByProxy stands in for the OAUTHBEARER implementation so re-auth
// can be exercised without a token provider.
type fakeSaslAuthByProxy struct {
	handshakeErr error
	authErr      error
}

func (f *fakeSaslAuthByProxy) sendAndReceiveSASLAuth(DeadlineReaderWriter, string) (int64, error) {
	return 30_000, nil
}

func (f *fakeSaslAuthByProxy) buildReauthHandshakeRequest(correlationID int32) ([]byte, error) {
	if f.handshakeErr != nil {
		return nil, f.handshakeErr
	}
	return framedRequest(&protocol.Request{
		CorrelationID: correlationID,
		ClientID:      "test",
		Body:          &protocol.SaslHandshakeRequestV0orV1{Version: 1, Mechanism: SASLOAuthBearer},
	})
}

func (f *fakeSaslAuthByProxy) buildReauthRequest(correlationID int32) ([]byte, error) {
	if f.authErr != nil {
		return nil, f.authErr
	}
	return framedRequest(&protocol.Request{
		CorrelationID: correlationID,
		ClientID:      "test",
		Body:          &protocol.SaslAuthenticateRequestV1{SaslAuthBytes: []byte("token")},
	})
}

// framedRequest encodes a request with its 4-byte length prefix, as the real
// buildReauth*Request implementations do.
func framedRequest(req *protocol.Request) ([]byte, error) {
	buf, err := protocol.Encode(req)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(buf))
	binary.BigEndian.PutUint32(out[:4], uint32(len(buf)))
	copy(out[4:], buf)
	return out, nil
}

func handshakeResponseFrame(t *testing.T, kerr protocol.KError) []byte {
	t.Helper()
	body, err := protocol.Encode(&protocol.SaslHandshakeResponseV0orV1{
		Err:               kerr,
		EnabledMechanisms: []string{SASLOAuthBearer},
	})
	if err != nil {
		t.Fatalf("encoding SaslHandshake response: %v", err)
	}
	return frame(reauthHandshakeCorrelationID, body)
}

// KIP-368 re-authentication is SaslHandshake THEN SaslAuthenticate on the live
// connection. Sending only the SaslAuthenticate gets it rejected with
// "Request is not valid given the current SASL state", which is what GCP
// Managed Kafka did to every re-auth we attempted.
func TestReauthSendsHandshakeBeforeAuthenticate(t *testing.T) {
	a := assert.New(t)

	// scaleSessionLifetime floors the schedule at one second, so no shorter
	// lifetime arms re-auth any faster.
	authState := newConnectionAuthState(1)
	time.Sleep(1100 * time.Millisecond)

	openRequests := make(chan protocol.RequestKeyVersion, 16)
	handlers := make(chan ResponseHandler, 18)
	reqCtx := &RequestsLoopContext{
		openRequestsChannel:        openRequests,
		nextResponseHandlerChannel: handlers,
		timeout:                    time.Second,
		brokerAddress:              "broker-0.test:9092",
		authState:                  authState,
		saslAuthByProxy:            &fakeSaslAuthByProxy{},
	}
	dst := &fakeClientWriter{}
	a.NoError(reqCtx.runReauth(dst))

	// Two framed requests on the wire, handshake first.
	sent := dst.buf.Bytes()
	first, rest := splitFrame(t, sent)
	second, remainder := splitFrame(t, rest)
	a.Empty(remainder, "exactly two requests should be written")

	a.EqualValues(apiKeySaslHandshake, apiKeyOf(first), "handshake must come first")
	a.EqualValues(reauthHandshakeCorrelationID, correlationIDOf(first))
	a.EqualValues(apiKeySaslAuthenticate, apiKeyOf(second), "authenticate must follow")
	a.EqualValues(reauthCorrelationID, correlationIDOf(second))

	// One marker + one handler per request, so the response loop stays paired.
	a.Len(openRequests, 2)
	a.Len(handlers, 2)
}

// Neither leg of the re-auth may reach the client.
func TestReauthHandshakeResponseIsNotForwardedToClient(t *testing.T) {
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
	a.Empty(dst.buf.Bytes(), "handshake and authenticate replies are both the proxy's own")
	a.False(authState.InFlightExpired(time.Now().Add(reauthInflightCushion+time.Second)),
		"re-auth should have completed")
}

// A broker that refuses the mechanism must tear the connection down rather
// than leave the proxy believing it re-authenticated.
func TestReauthHandshakeRejectionTearsDownConnection(t *testing.T) {
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

	src := &fakeBrokerReader{r: bytes.NewReader(handshakeResponseFrame(t, protocol.ErrUnsupportedSASLMechanism))}
	dst := &fakeClientWriter{}

	_, err := ctx.responsesLoop(dst, src)
	a.Error(err)
	a.Contains(err.Error(), "re-auth: broker rejected")
	a.Empty(dst.buf.Bytes())
}

// A client speaking SASL through the proxy still gets its own handshake reply.
func TestClientSaslHandshakeResponseIsStillForwarded(t *testing.T) {
	a := assert.New(t)

	ctx, openRequests, handlers := newTestResponsesLoopContext(newConnectionAuthState(30_000))

	body, err := protocol.Encode(&protocol.SaslHandshakeResponseV0orV1{
		Err:               protocol.ErrNoError,
		EnabledMechanisms: []string{SASLOAuthBearer},
	})
	a.NoError(err)
	clientFrame := frame(9, body) // the client's own correlation ID

	openRequests <- protocol.RequestKeyVersion{ApiKey: apiKeySaslHandshake, ApiVersion: 1}
	handlers <- defaultResponseHandler

	src := &fakeBrokerReader{r: bytes.NewReader(clientFrame)}
	dst := &fakeClientWriter{}

	_, err = ctx.responsesLoop(dst, src)
	a.ErrorIs(err, io.EOF)
	a.Equal(clientFrame, dst.buf.Bytes())
}

// --- helpers ---------------------------------------------------------------

// splitFrame peels one length-prefixed frame off the head of buf.
func splitFrame(t *testing.T, buf []byte) (frameBody, rest []byte) {
	t.Helper()
	if len(buf) < 4 {
		t.Fatalf("buffer too short for a frame: %d bytes", len(buf))
	}
	n := binary.BigEndian.Uint32(buf[:4])
	if uint32(len(buf)) < 4+n {
		t.Fatalf("truncated frame: want %d bytes, have %d", 4+n, len(buf))
	}
	return buf[4 : 4+n], buf[4+n:]
}

// A request body starts ApiKey:int16, ApiVersion:int16, CorrelationID:int32.
func apiKeyOf(request []byte) int16        { return int16(binary.BigEndian.Uint16(request[0:2])) }
func correlationIDOf(request []byte) int32 { return int32(binary.BigEndian.Uint32(request[4:8])) }

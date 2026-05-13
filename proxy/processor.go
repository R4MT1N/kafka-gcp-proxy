package proxy

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/R4MT1N/kafka-gcp-proxy/config"
	"github.com/R4MT1N/kafka-gcp-proxy/proxy/protocol"
	"github.com/sirupsen/logrus"
)

const (
	openRequestSendTimeout    = 5 * time.Second
	openRequestReceiveTimeout = 5 * time.Second
	defaultRequestBufferSize  = 4096
	defaultResponseBufferSize = 4096
	defaultWriteTimeout       = 30 * time.Second
	defaultReadTimeout        = 30 * time.Second
	minOpenRequests           = 16

	apiKeyProduce          = int16(0)
	apiKeySaslHandshake    = int16(17)
	apiKeyApiApiVersions   = int16(18)
	apiKeySaslAuthenticate = int16(36)

	minRequestApiKey = int16(0)     // 0 - Produce
	maxRequestApiKey = int16(20000) // so far 67 is the last (reserve some for the feature)

	// reauthSafetyMargin is the fraction of session_lifetime we deduct so that
	// the proxy refreshes credentials with time to spare. 20% covers token
	// fetch + round-trip + clock skew under typical conditions.
	reauthSafetyMargin = 0.2

	// reauthInflightCushion bounds how long we wait for a re-auth response
	// before treating the connection as broken. Far shorter than the session
	// lifetime so a stuck re-auth doesn't pass unnoticed.
	reauthInflightCushion = 30 * time.Second
)

var (
	defaultRequestHandler     = &DefaultRequestHandler{}
	defaultResponseHandler    = &DefaultResponseHandler{}
	saslAuthV0RequestHandler  = &SaslAuthV0RequestHandler{}
	saslAuthV0ResponseHandler = &SaslAuthV0ResponseHandler{}
	saslReauthResponseHandler = &SaslReauthResponseHandler{}
)

type ProcessorConfig struct {
	MaxOpenRequests       int
	NetAddressMappingFunc config.NetAddressMappingFunc
	RequestBufferSize     int
	ResponseBufferSize    int
	WriteTimeout          time.Duration
	ReadTimeout           time.Duration
	ForbiddenApiKeys      map[int16]struct{}
	ProducerAcks0Disabled bool

	// Set per-connection when copyThenClose hands a fresh dial off to the
	// processor. Zero means the broker did not advertise a session lifetime —
	// the proxy won't attempt KIP-368 re-auth.
	InitialSessionLifetimeMs int64
	// Same — supplied per-connection. Nil disables re-auth entirely (e.g. for
	// non-SASL brokers, if we ever support them).
	SaslAuthByProxy SASLAuthByProxy
}

type processor struct {
	openRequestsChannel        chan protocol.RequestKeyVersion
	nextRequestHandlerChannel  chan RequestHandler
	nextResponseHandlerChannel chan ResponseHandler

	netAddressMappingFunc config.NetAddressMappingFunc
	requestBufferSize     int
	responseBufferSize    int
	writeTimeout          time.Duration
	readTimeout           time.Duration

	forbiddenApiKeys map[int16]struct{}
	brokerAddress    string
	// producer will never send request with acks=0
	producerAcks0Disabled bool

	// Shared state between request & response loops. Lifetimes are
	// per-connection; we build it once in newProcessor.
	authState       *ConnectionAuthState
	saslAuthByProxy SASLAuthByProxy
}

// ConnectionAuthState tracks when the current SASL session expires on a single
// broker connection and coordinates re-auth between the request and response
// loops. The request loop initiates re-auth (and marks the state in-flight);
// the response loop completes it (and clears in-flight, sets the new deadline).
type ConnectionAuthState struct {
	mu sync.Mutex

	// When the proxy should re-authenticate. Zero = no re-auth required.
	reauthAt time.Time
	// True between the moment we write a re-auth request and the moment the
	// response handler consumes the broker's reply.
	inFlight bool
	// Deadline after which we give up on the in-flight re-auth and tear down
	// the connection. Bound by reauthInflightCushion.
	inFlightDeadline time.Time
	// Latest session lifetime advertised by the broker. Used for both initial
	// scheduling and re-scheduling after each successful re-auth.
	sessionLifetime time.Duration
}

func newConnectionAuthState(sessionLifetimeMs int64) *ConnectionAuthState {
	s := &ConnectionAuthState{}
	if sessionLifetimeMs > 0 {
		s.sessionLifetime = time.Duration(sessionLifetimeMs) * time.Millisecond
		s.reauthAt = time.Now().Add(scaleSessionLifetime(s.sessionLifetime))
	}
	return s
}

func scaleSessionLifetime(d time.Duration) time.Duration {
	scaled := time.Duration(float64(d) * (1.0 - reauthSafetyMargin))
	if scaled < time.Second {
		// Guard against pathological session lifetimes from misconfigured brokers.
		scaled = time.Second
	}
	return scaled
}

// NeedsReauth reports whether a fresh re-auth should be initiated now. False
// while one is already in flight to avoid double-firing.
func (s *ConnectionAuthState) NeedsReauth(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reauthAt.IsZero() || s.inFlight {
		return false
	}
	return !now.Before(s.reauthAt)
}

// NextReadDeadline returns the deadline the request loop should use on its
// next client-read so that it wakes in time to run re-auth even on an idle
// connection. Zero = no deadline.
func (s *ConnectionAuthState) NextReadDeadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inFlight {
		return s.inFlightDeadline
	}
	return s.reauthAt
}

// MarkInFlight records that we have just written a re-auth request and are
// waiting for the response. The response handler will call CompleteReauth.
func (s *ConnectionAuthState) MarkInFlight(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inFlight = true
	s.inFlightDeadline = now.Add(reauthInflightCushion)
}

// CompleteReauth applies a newly-advertised session lifetime from the broker.
// A non-positive value means the broker no longer requires re-auth on this
// connection — we keep the current deadline as-is, on the theory that quietly
// dropping reauth would be more surprising than continuing to refresh.
func (s *ConnectionAuthState) CompleteReauth(sessionLifetimeMs int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inFlight = false
	s.inFlightDeadline = time.Time{}
	if sessionLifetimeMs > 0 {
		s.sessionLifetime = time.Duration(sessionLifetimeMs) * time.Millisecond
		s.reauthAt = time.Now().Add(scaleSessionLifetime(s.sessionLifetime))
	}
}

// InFlightExpired returns true if we're in-flight and the cushion has elapsed,
// meaning the response never arrived and the connection is wedged.
func (s *ConnectionAuthState) InFlightExpired(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inFlight && !s.inFlightDeadline.IsZero() && now.After(s.inFlightDeadline)
}

func newProcessor(cfg ProcessorConfig, brokerAddress string) *processor {
	maxOpenRequests := cfg.MaxOpenRequests
	if maxOpenRequests < minOpenRequests {
		maxOpenRequests = minOpenRequests
	}
	requestBufferSize := cfg.RequestBufferSize
	if requestBufferSize <= 0 {
		requestBufferSize = defaultRequestBufferSize
	}
	responseBufferSize := cfg.ResponseBufferSize
	if responseBufferSize <= 0 {
		responseBufferSize = defaultResponseBufferSize
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = defaultWriteTimeout
	}
	readTimeout := cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = defaultReadTimeout
	}
	nextRequestHandlerChannel := make(chan RequestHandler, 1)
	// +2 leaves room for both the default handler and a re-auth handler that
	// the request loop may push concurrently while a normal request is queued.
	nextResponseHandlerChannel := make(chan ResponseHandler, maxOpenRequests+2)

	// initial handlers -> standard kafka message arrives always as first
	nextRequestHandlerChannel <- defaultRequestHandler
	nextResponseHandlerChannel <- defaultResponseHandler

	return &processor{
		openRequestsChannel:        make(chan protocol.RequestKeyVersion, maxOpenRequests),
		nextRequestHandlerChannel:  nextRequestHandlerChannel,
		nextResponseHandlerChannel: nextResponseHandlerChannel,
		netAddressMappingFunc:      cfg.NetAddressMappingFunc,
		requestBufferSize:          requestBufferSize,
		responseBufferSize:         responseBufferSize,
		readTimeout:                readTimeout,
		writeTimeout:               writeTimeout,
		brokerAddress:              brokerAddress,
		forbiddenApiKeys:           cfg.ForbiddenApiKeys,
		producerAcks0Disabled:      cfg.ProducerAcks0Disabled,
		authState:                  newConnectionAuthState(cfg.InitialSessionLifetimeMs),
		saslAuthByProxy:            cfg.SaslAuthByProxy,
	}
}

func (p *processor) RequestsLoop(dst DeadlineWriter, src DeadlineReaderWriter) (readErr bool, err error) {
	err = src.SetDeadline(time.Time{})
	if err != nil {
		return false, err
	}
	ctx := &RequestsLoopContext{
		openRequestsChannel:        p.openRequestsChannel,
		nextRequestHandlerChannel:  p.nextRequestHandlerChannel,
		nextResponseHandlerChannel: p.nextResponseHandlerChannel,
		timeout:                    p.writeTimeout,
		brokerAddress:              p.brokerAddress,
		forbiddenApiKeys:           p.forbiddenApiKeys,
		buf:                        make([]byte, p.requestBufferSize),
		producerAcks0Disabled:      p.producerAcks0Disabled,
		authState:                  p.authState,
		saslAuthByProxy:            p.saslAuthByProxy,
	}

	return ctx.requestsLoop(dst, src)
}

type RequestsLoopContext struct {
	openRequestsChannel        chan<- protocol.RequestKeyVersion
	nextRequestHandlerChannel  chan RequestHandler
	nextResponseHandlerChannel chan<- ResponseHandler

	timeout          time.Duration
	brokerAddress    string
	forbiddenApiKeys map[int16]struct{}
	buf              []byte // bufSize

	producerAcks0Disabled bool

	authState       *ConnectionAuthState
	saslAuthByProxy SASLAuthByProxy
}

// used by local authentication
func (ctx *RequestsLoopContext) putNextRequestHandler(nextRequestHandler RequestHandler) error {

	select {
	case ctx.nextRequestHandlerChannel <- nextRequestHandler:
	default:
		return errors.New("next request handler channel is full")
	}
	return nil
}

func (ctx *RequestsLoopContext) putNextHandlers(nextRequestHandler RequestHandler, nextResponseHandler ResponseHandler) error {

	select {
	case ctx.nextRequestHandlerChannel <- nextRequestHandler:
	default:
		return errors.New("next request handler channel is full")
	}

	select {
	case ctx.nextResponseHandlerChannel <- nextResponseHandler:
	default:
		timer := time.NewTimer(openRequestSendTimeout)
		defer timer.Stop()

		select {
		case ctx.nextResponseHandlerChannel <- nextResponseHandler:
		case <-timer.C:
			return errors.New("next response handler channel is full")
		}
	}
	return nil
}

func (r *RequestsLoopContext) getNextRequestHandler() (RequestHandler, error) {
	select {
	case nextRequestHandler := <-r.nextRequestHandlerChannel:
		return nextRequestHandler, nil
	default:
		return nil, errors.New("next request handler is missing")
	}
}

type RequestHandler interface {
	handleRequest(dst DeadlineWriter, src DeadlineReaderWriter, ctx *RequestsLoopContext) (readErr bool, err error)
}

// runReauth writes a fresh SaslAuthenticate v1 onto the broker connection and
// enqueues a SaslReauthResponseHandler so the response loop consumes the reply
// without forwarding to the client. Idempotent if NeedsReauth was checked
// beforehand — but cheap enough to also check internally.
//
// Concurrency: this runs on the request loop's goroutine, which is the only
// writer to the broker connection, so we're safe to write directly. The
// response handler reads on the response loop's goroutine; the shared
// ConnectionAuthState mutex makes the hand-off race-free.
func (r *RequestsLoopContext) runReauth(dst DeadlineWriter) error {
	if r.authState == nil || r.saslAuthByProxy == nil {
		return nil
	}
	now := time.Now()
	if !r.authState.NeedsReauth(now) {
		return nil
	}
	reqBytes, err := r.saslAuthByProxy.buildReauthRequest(reauthCorrelationID)
	if err != nil {
		// Fail loud — we'd rather close the connection than serve traffic on
		// a credential that's about to expire.
		return err
	}
	if err := dst.SetWriteDeadline(now.Add(r.timeout)); err != nil {
		return err
	}
	if _, err := dst.Write(reqBytes); err != nil {
		return err
	}
	// Mark in-flight before publishing onto the channels so the request loop
	// won't re-fire even if the response handler is delayed.
	r.authState.MarkInFlight(now)
	// Tell the response loop what API key/version to expect next, and which
	// handler to use.
	select {
	case r.openRequestsChannel <- protocol.RequestKeyVersion{ApiKey: apiKeySaslAuthenticate, ApiVersion: saslAuthenticateRequestVersion}:
	default:
		return errors.New("re-auth: openRequestsChannel full")
	}
	select {
	case r.nextResponseHandlerChannel <- saslReauthResponseHandler:
	default:
		return errors.New("re-auth: nextResponseHandlerChannel full")
	}
	logrus.Debugf("re-auth: SaslAuthenticate v1 sent to %s", r.brokerAddress)
	return nil
}

func (r *RequestsLoopContext) requestsLoop(dst DeadlineWriter, src DeadlineReaderWriter) (readErr bool, err error) {
	var nextRequestHandler RequestHandler
	for {
		if r.authState != nil && r.authState.InFlightExpired(time.Now()) {
			return false, errors.New("re-auth response did not arrive within cushion window — connection wedged")
		}
		if nextRequestHandler, err = r.getNextRequestHandler(); err != nil {
			return false, nil
		}
		if readErr, err = nextRequestHandler.handleRequest(dst, src, r); err != nil {
			return readErr, err
		}
	}
}

func (p *processor) ResponsesLoop(dst DeadlineWriter, src DeadlineReader) (readErr bool, err error) {
	ctx := &ResponsesLoopContext{
		openRequestsChannel:        p.openRequestsChannel,
		nextResponseHandlerChannel: p.nextResponseHandlerChannel,
		netAddressMappingFunc:      p.netAddressMappingFunc,
		timeout:                    p.readTimeout,
		brokerAddress:              p.brokerAddress,
		buf:                        make([]byte, p.responseBufferSize),
		authState:                  p.authState,
	}
	return ctx.responsesLoop(dst, src)
}

type ResponsesLoopContext struct {
	openRequestsChannel        <-chan protocol.RequestKeyVersion
	nextResponseHandlerChannel <-chan ResponseHandler
	netAddressMappingFunc      config.NetAddressMappingFunc
	timeout                    time.Duration
	brokerAddress              string
	buf                        []byte // bufSize

	authState *ConnectionAuthState
}

type ResponseHandler interface {
	handleResponse(dst DeadlineWriter, src DeadlineReader, ctx *ResponsesLoopContext) (readErr bool, err error)
}

func (r *ResponsesLoopContext) responsesLoop(dst DeadlineWriter, src DeadlineReader) (readErr bool, err error) {
	var nextResponseHandler ResponseHandler
	for {
		if nextResponseHandler, err = r.getNextResponseHandler(); err != nil {
			return false, err
		}
		if readErr, err = nextResponseHandler.handleResponse(dst, src, r); err != nil {
			return readErr, err
		}
	}
}

func (r *ResponsesLoopContext) getNextResponseHandler() (ResponseHandler, error) {
	select {
	case handler := <-r.nextResponseHandlerChannel:
		return handler, nil
	default:
		timer := time.NewTimer(openRequestReceiveTimeout)
		defer timer.Stop()

		select {
		case handler := <-r.nextResponseHandlerChannel:
			return handler, nil
		case <-timer.C:
			return nil, errors.New("next response handler is missing")
		}
	}
}

// SaslReauthResponseHandler consumes the broker's reply to a proxy-initiated
// SaslAuthenticate v1, updates the per-connection auth state with the new
// session_lifetime_ms, and writes nothing to the client.
//
// The kafka header for an in-flight request also has to be drained off the
// openRequestsChannel. We do that here so the channel queue stays aligned with
// the response stream.
type SaslReauthResponseHandler struct{}

func (h *SaslReauthResponseHandler) handleResponse(dst DeadlineWriter, src DeadlineReader, ctx *ResponsesLoopContext) (readErr bool, err error) {
	if err = src.SetReadDeadline(time.Now().Add(ctx.timeout)); err != nil {
		return true, err
	}
	// Drain the matching request marker so subsequent default responses pair
	// correctly. If it isn't there we're out of sync — fail loud.
	select {
	case rkv := <-ctx.openRequestsChannel:
		if rkv.ApiKey != apiKeySaslAuthenticate {
			return false, errors.New("re-auth: openRequestsChannel out of sync; expected SaslAuthenticate marker")
		}
	default:
		return false, errors.New("re-auth: openRequestsChannel empty when SaslAuthenticate response expected")
	}

	// Standard length-prefixed frame: Size:int32, CorrelationID:int32, body.
	header := make([]byte, 8)
	if _, err = io.ReadFull(src, header); err != nil {
		return true, err
	}
	length := binary.BigEndian.Uint32(header[:4])
	if length < 4 {
		return true, errors.New("re-auth: response too short")
	}
	payload := make([]byte, length-4)
	if _, err = io.ReadFull(src, payload); err != nil {
		return true, err
	}

	res := &protocol.SaslAuthenticateResponseV1{}
	if err := protocol.Decode(payload, res); err != nil {
		return true, err
	}
	if !errors.Is(res.Err, protocol.ErrNoError) {
		errMsg := ""
		if res.ErrMsg != nil {
			errMsg = *res.ErrMsg
		}
		// The connection is about to be force-closed by the broker. Tear it
		// down here so the client reconnects rather than continuing to send
		// requests that will silently fail.
		return false, errors.New("re-auth: broker rejected refreshed credentials: " + res.Err.Error() + " (" + errMsg + ")")
	}

	if ctx.authState != nil {
		ctx.authState.CompleteReauth(res.SessionLifetimeMs)
	}
	logrus.Debugf("re-auth: succeeded on %s, session_lifetime_ms=%d", ctx.brokerAddress, res.SessionLifetimeMs)
	return false, nil
}

package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/R4MT1N/kafka-gcp-proxy/pkg/apis"
	"github.com/R4MT1N/kafka-gcp-proxy/proxy/protocol"
	"github.com/sirupsen/logrus"
)

const (
	SASLOAuthBearer = "OAUTHBEARER"

	// SaslAuthenticate V1 introduces session_lifetime_ms (KIP-368). We use it
	// for both initial auth and re-auth so we can refresh credentials on the
	// same TCP connection before the broker force-closes it.
	saslAuthenticateRequestVersion = int16(1)

	// Sentinel correlation ID used for proxy-injected re-auth requests. Picked
	// at the top of the int32 range so it's effectively impossible for a real
	// Kafka client to collide with it (clients increment from 0).
	reauthCorrelationID = int32(0x7FFFFFFE)
)

type SASLHandshake struct {
	clientID  string
	version   int16
	mechanism string

	writeTimeout time.Duration
	readTimeout  time.Duration
}

type SASLOAuthBearerAuth struct {
	clientID string

	writeTimeout time.Duration
	readTimeout  time.Duration

	tokenProvider apis.TokenProvider
}

// SASLAuthByProxy is the interface used by the dial path for the initial
// authentication. It is intentionally narrow — re-auth on a live connection is
// driven by the processor via the protocol-aware path (see runReauth).
type SASLAuthByProxy interface {
	// sendAndReceiveSASLAuth does the SaslHandshake + SaslAuthenticate
	// round-trips on a fresh connection. Returns the session_lifetime_ms the
	// broker advertised; 0 means the broker does not require re-authentication.
	sendAndReceiveSASLAuth(conn DeadlineReaderWriter, brokerAddress string) (int64, error)

	// buildReauthRequest produces the framed bytes (length prefix + request
	// header + body) for a SaslAuthenticate v1 carrying a fresh token. The
	// caller writes those bytes onto a live broker connection while the rest
	// of the proxy is paused; the response is consumed by a dedicated handler
	// in the response loop. The correlation ID lets the proxy match the
	// response off the wire if needed.
	buildReauthRequest(correlationID int32) ([]byte, error)
}

func (b *SASLHandshake) sendAndReceiveHandshake(conn DeadlineReaderWriter) error {
	logrus.Debugf("Sending SaslHandshakeRequest mechanism: %v  version: %v", b.mechanism, b.version)
	req := &protocol.Request{
		ClientID: b.clientID,
		Body:     &protocol.SaslHandshakeRequestV0orV1{Version: b.version, Mechanism: b.mechanism},
	}
	reqBuf, err := protocol.Encode(req)
	if err != nil {
		return err
	}
	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf, uint32(len(reqBuf)))

	if err := conn.SetWriteDeadline(time.Now().Add(b.writeTimeout)); err != nil {
		return err
	}
	if _, err := conn.Write(bytes.Join([][]byte{sizeBuf, reqBuf}, nil)); err != nil {
		return fmt.Errorf("failed to send SASL handshake: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(b.readTimeout)); err != nil {
		return err
	}

	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read SASL handshake header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[:4])
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return fmt.Errorf("failed to read SASL handshake payload: %w", err)
	}
	res := &protocol.SaslHandshakeResponseV0orV1{}
	if err := protocol.Decode(payload, res); err != nil {
		return fmt.Errorf("failed to parse SASL handshake: %w", err)
	}
	if !errors.Is(res.Err, protocol.ErrNoError) {
		return fmt.Errorf("invalid SASL Mechanism: %w", res.Err)
	}
	logrus.Debugf("Successful SASL handshake. Available mechanisms: %v", res.EnabledMechanisms)
	return nil
}

func (b *SASLOAuthBearerAuth) getOAuthBearerToken() (string, error) {
	resp, err := b.tokenProvider.GetToken(context.Background(), apis.TokenRequest{})
	if err != nil {
		return "", err
	}
	if !resp.Success {
		return "", fmt.Errorf("get sasl token failed with status: %d", resp.Status)
	}
	if resp.Token == "" {
		return "", errors.New("get sasl token returned empty token")
	}
	return resp.Token, nil
}

func (b *SASLOAuthBearerAuth) sendAndReceiveSASLAuth(conn DeadlineReaderWriter, _ string) (int64, error) {
	token, err := b.getOAuthBearerToken()
	if err != nil {
		return 0, err
	}
	saslHandshake := &SASLHandshake{
		clientID:     b.clientID,
		version:      1,
		mechanism:    SASLOAuthBearer,
		writeTimeout: b.writeTimeout,
		readTimeout:  b.readTimeout,
	}
	if err := saslHandshake.sendAndReceiveHandshake(conn); err != nil {
		return 0, err
	}
	return b.sendSaslAuthenticateRequest(token, conn)
}

// sendSaslAuthenticateRequest performs a synchronous V1 SaslAuthenticate
// round-trip and returns the broker-advertised session_lifetime_ms. Used only
// for the initial auth, where the proxy fully controls the connection.
func (b *SASLOAuthBearerAuth) sendSaslAuthenticateRequest(token string, conn DeadlineReaderWriter) (int64, error) {
	logrus.Debugf("Sending SaslAuthenticateRequest, mechanism OAUTHBEARER")

	reqBytes, err := b.encodeSaslAuthenticate(token, 0)
	if err != nil {
		return 0, err
	}

	if err := conn.SetWriteDeadline(time.Now().Add(b.writeTimeout)); err != nil {
		return 0, err
	}
	if _, err := conn.Write(reqBytes); err != nil {
		return 0, fmt.Errorf("failed to send SASL auth request: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(b.readTimeout)); err != nil {
		return 0, err
	}

	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, fmt.Errorf("failed to read SASL auth header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[:4])
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, fmt.Errorf("failed to read SASL auth payload: %w", err)
	}

	res := &protocol.SaslAuthenticateResponseV1{}
	if err := protocol.Decode(payload, res); err != nil {
		return 0, fmt.Errorf("failed to parse SASL auth response: %w", err)
	}
	if !errors.Is(res.Err, protocol.ErrNoError) {
		errMsg := ""
		if res.ErrMsg != nil {
			errMsg = *res.ErrMsg
		}
		return 0, fmt.Errorf("SASL authentication failed: %v (broker: %q)", res.Err, errMsg)
	}
	if res.SessionLifetimeMs > 0 {
		logrus.Infof("SASL authenticated; broker session_lifetime_ms=%d", res.SessionLifetimeMs)
	}
	return res.SessionLifetimeMs, nil
}

// buildReauthRequest packages a SaslAuthenticate v1 with a fresh token plus
// length prefix, suitable for writing onto the live broker connection from the
// processor's request loop. It does not touch the wire itself.
func (b *SASLOAuthBearerAuth) buildReauthRequest(correlationID int32) ([]byte, error) {
	token, err := b.getOAuthBearerToken()
	if err != nil {
		return nil, fmt.Errorf("re-auth: fetching token: %w", err)
	}
	return b.encodeSaslAuthenticate(token, correlationID)
}

func (b *SASLOAuthBearerAuth) encodeSaslAuthenticate(token string, correlationID int32) ([]byte, error) {
	authBytes := SaslOAuthBearer{}.ToBytes(token, "", map[string]string{})
	req := &protocol.Request{
		CorrelationID: correlationID,
		ClientID:      b.clientID,
		Body:          &protocol.SaslAuthenticateRequestV1{SaslAuthBytes: authBytes},
	}
	reqBuf, err := protocol.Encode(req)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(reqBuf))
	binary.BigEndian.PutUint32(out[:4], uint32(len(reqBuf)))
	copy(out[4:], reqBuf)
	return out, nil
}

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

type SASLAuthByProxy interface {
	sendAndReceiveSASLAuth(conn DeadlineReaderWriter, brokerAddress string) error
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

func (b *SASLOAuthBearerAuth) sendAndReceiveSASLAuth(conn DeadlineReaderWriter, _ string) error {
	token, err := b.getOAuthBearerToken()
	if err != nil {
		return err
	}
	saslHandshake := &SASLHandshake{
		clientID:     b.clientID,
		version:      1,
		mechanism:    SASLOAuthBearer,
		writeTimeout: b.writeTimeout,
		readTimeout:  b.readTimeout,
	}
	if err := saslHandshake.sendAndReceiveHandshake(conn); err != nil {
		return err
	}
	return b.sendSaslAuthenticateRequest(token, conn)
}

func (b *SASLOAuthBearerAuth) sendSaslAuthenticateRequest(token string, conn DeadlineReaderWriter) error {
	saslAuthBytes := SaslOAuthBearer{}.ToBytes(token, "", map[string]string{})
	// Dump structural envelope (substitute the token itself with <TOKEN>) so we
	// can spot SASL formatting bugs without leaking the credential.
	envelope := bytes.ReplaceAll(saslAuthBytes, []byte(token), []byte("<TOKEN>"))
	logrus.Debugf("Sending SaslAuthenticateRequest OAUTHBEARER token-len=%d envelope=%q raw-hex=% x", len(token), string(envelope), envelope)

	saslAuthReqV0 := protocol.SaslAuthenticateRequestV0{SaslAuthBytes: saslAuthBytes}

	req := &protocol.Request{
		ClientID: b.clientID,
		Body:     &saslAuthReqV0,
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
		return fmt.Errorf("failed to send SASL auth request: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(b.readTimeout)); err != nil {
		return err
	}

	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read SASL auth header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[:4])
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return fmt.Errorf("failed to read SASL auth payload: %w", err)
	}

	res := &protocol.SaslAuthenticateResponseV0{}
	if err := protocol.Decode(payload, res); err != nil {
		return fmt.Errorf("failed to parse SASL auth response: %w", err)
	}
	if !errors.Is(res.Err, protocol.ErrNoError) {
		errMsg := ""
		if res.ErrMsg != nil {
			errMsg = *res.ErrMsg
		}
		return fmt.Errorf("SASL authentication failed: %v (broker: %q)", res.Err, errMsg)
	}
	return nil
}

package proxy

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/R4MT1N/kafka-gcp-proxy/config"
	"github.com/R4MT1N/kafka-gcp-proxy/pkg/apis"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Conn represents a connection from a client to a specific instance.
type Conn struct {
	BrokerAddress   string
	LocalConnection net.Conn
}

// Client handles connecting to upstream Kafka brokers and proxying traffic.
type Client struct {
	conns *ConnSet

	config *config.Config

	processorConfig ProcessorConfig

	dialer         Dialer
	tcpConnOptions TCPConnOptions

	stopRun  chan struct{}
	stopOnce sync.Once

	saslAuthByProxy SASLAuthByProxy

	dialAddressMapping map[string]config.DialAddressMapping
}

func NewClient(conns *ConnSet, c *config.Config, netAddressMappingFunc config.NetAddressMappingFunc, saslTokenProvider apis.TokenProvider) (*Client, error) {
	var tlsConfigFunc TLSConfigFunc
	if c.Kafka.TLS.Enable {
		var err error
		tlsConfigFunc, err = newTLSClientConfig(c)
		if err != nil {
			return nil, err
		}
	}
	dialer, err := newDialer(c, tlsConfigFunc)
	if err != nil {
		return nil, err
	}
	tcpConnOptions := TCPConnOptions{
		KeepAlive:       c.Kafka.KeepAlive,
		WriteBufferSize: c.Kafka.ConnectionWriteBufferSize,
		ReadBufferSize:  c.Kafka.ConnectionReadBufferSize,
	}

	forbiddenApiKeys := make(map[int16]struct{})
	if len(c.Kafka.ForbiddenApiKeys) != 0 {
		logrus.Warnf("Kafka operations for Api Keys %v will be forbidden.", c.Kafka.ForbiddenApiKeys)
		for _, apiKey := range c.Kafka.ForbiddenApiKeys {
			forbiddenApiKeys[int16(apiKey)] = struct{}{}
		}
	}

	if !c.Kafka.SASL.Enable || saslTokenProvider == nil {
		return nil, errors.New("SASL must be enabled with a token provider (SASL/OAUTHBEARER via google-access-token-provider)")
	}
	saslAuthByProxy := &SASLOAuthBearerAuth{
		clientID:      c.Kafka.ClientID,
		writeTimeout:  c.Kafka.WriteTimeout,
		readTimeout:   c.Kafka.ReadTimeout,
		tokenProvider: saslTokenProvider,
	}

	dialAddressMapping, err := getAddressToDialAddressMapping(c)
	if err != nil {
		return nil, err
	}

	return &Client{
		conns:           conns,
		config:          c,
		dialer:          dialer,
		tcpConnOptions:  tcpConnOptions,
		stopRun:         make(chan struct{}, 1),
		saslAuthByProxy: saslAuthByProxy,
		processorConfig: ProcessorConfig{
			MaxOpenRequests:       c.Kafka.MaxOpenRequests,
			NetAddressMappingFunc: netAddressMappingFunc,
			RequestBufferSize:     c.Proxy.RequestBufferSize,
			ResponseBufferSize:    c.Proxy.ResponseBufferSize,
			ReadTimeout:           c.Kafka.ReadTimeout,
			WriteTimeout:          c.Kafka.WriteTimeout,
			ForbiddenApiKeys:      forbiddenApiKeys,
			ProducerAcks0Disabled: c.Kafka.Producer.Acks0Disabled,
		},
		dialAddressMapping: dialAddressMapping,
	}, nil
}

func getAddressToDialAddressMapping(cfg *config.Config) (map[string]config.DialAddressMapping, error) {
	addressToDialAddressMapping := make(map[string]config.DialAddressMapping)
	for _, v := range cfg.Proxy.DialAddressMappings {
		if lc, ok := addressToDialAddressMapping[v.SourceAddress]; ok {
			if lc.SourceAddress != v.SourceAddress || lc.DestinationAddress != v.DestinationAddress {
				return nil, fmt.Errorf("dial address mapping %s configured twice: %v and %v", v.SourceAddress, v, lc)
			}
			continue
		}
		logrus.Infof("Dial address mapping src %s dst %s", v.SourceAddress, v.DestinationAddress)
		addressToDialAddressMapping[v.SourceAddress] = v
	}
	return addressToDialAddressMapping, nil
}

func newDialer(c *config.Config, tlsConfigFunc TLSConfigFunc) (Dialer, error) {
	rawDialer := directDialer{
		dialTimeout: c.Kafka.DialTimeout,
		keepAlive:   c.Kafka.KeepAlive,
	}
	if c.Kafka.TLS.Enable {
		if tlsConfigFunc == nil || tlsConfigFunc() == nil {
			return nil, errors.New("tlsConfigFunc must not be nil")
		}
		return tlsDialer{
			timeout:    c.Kafka.DialTimeout,
			rawDialer:  rawDialer,
			configFunc: tlsConfigFunc,
		}, nil
	}
	return rawDialer, nil
}

// Run causes the client to start waiting for new connections to connSrc and
// proxy them to the destination instance. It blocks until connSrc is closed.
func (c *Client) Run(connSrc <-chan Conn) error {
STOP:
	for {
		select {
		case conn := <-connSrc:
			go withRecover(func() { c.handleConn(conn) })
		case <-c.stopRun:
			break STOP
		}
	}

	logrus.Info("Closing connections")
	if err := c.conns.Close(); err != nil {
		logrus.Infof("closing client had error: %v", err)
	}
	logrus.Info("Proxy is stopped")
	return nil
}

func (c *Client) Close() {
	c.stopOnce.Do(func() {
		close(c.stopRun)
	})
}

func (c *Client) handleConn(conn Conn) {
	proxyConnectionsTotal.WithLabelValues(conn.BrokerAddress).Inc()

	dialAddress := conn.BrokerAddress
	if addressMapping, ok := c.dialAddressMapping[dialAddress]; ok {
		dialAddress = addressMapping.DestinationAddress
		logrus.Infof("Dial address changed from %s to %s", conn.BrokerAddress, dialAddress)
	}

	server, sessionLifetimeMs, err := c.DialAndAuth(dialAddress)
	if err != nil {
		logrus.Infof("couldn't connect to %s(%s): %v", dialAddress, conn.BrokerAddress, err)
		_ = conn.LocalConnection.Close()
		return
	}
	if tcpConn, ok := server.(*net.TCPConn); ok {
		if err := c.tcpConnOptions.setTCPConnOptions(tcpConn); err != nil {
			logrus.Infof("WARNING: Error while setting TCP options for kafka connection %s on %v: %v", conn.BrokerAddress, server.LocalAddr(), err)
		}
	}
	c.conns.Add(conn.BrokerAddress, conn.LocalConnection)
	localDesc := "local connection on " + conn.LocalConnection.LocalAddr().String() + " from " + conn.LocalConnection.RemoteAddr().String() + " (" + conn.BrokerAddress + ")"
	// Per-connection config: same static processor settings + the freshly
	// negotiated session lifetime + the auth handle used for in-flight reauth.
	cfg := c.processorConfig
	cfg.InitialSessionLifetimeMs = sessionLifetimeMs
	cfg.SaslAuthByProxy = c.saslAuthByProxy
	if sessionLifetimeMs > 0 {
		proxyReauthSessionLifetimeSeconds.WithLabelValues(conn.BrokerAddress).Set(float64(sessionLifetimeMs) / 1000.0)
	}
	copyThenClose(cfg, server, conn.LocalConnection, conn.BrokerAddress, conn.BrokerAddress, localDesc)
	if err := c.conns.Remove(conn.BrokerAddress, conn.LocalConnection); err != nil {
		logrus.Info(err)
	}
}

func (c *Client) DialAndAuth(brokerAddress string) (net.Conn, int64, error) {
	conn, err := c.dialer.Dial("tcp", brokerAddress)
	if err != nil {
		return nil, 0, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	sessionLifetimeMs, err := c.auth(conn, brokerAddress)
	if err != nil {
		return nil, 0, err
	}
	return conn, sessionLifetimeMs, nil
}

func (c *Client) auth(conn net.Conn, brokerAddress string) (int64, error) {
	if !c.config.Kafka.SASL.Enable {
		return 0, nil
	}
	sessionLifetimeMs, err := c.saslAuthByProxy.sendAndReceiveSASLAuth(conn, brokerAddress)
	if err != nil {
		_ = conn.Close()
		return 0, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return 0, err
	}
	return sessionLifetimeMs, nil
}

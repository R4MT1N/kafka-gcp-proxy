package proxy

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/pkg/errors"
)

type Dialer interface {
	Dial(network, addr string) (c net.Conn, err error)
}

type directDialer struct {
	dialTimeout time.Duration
	keepAlive   time.Duration
}

func (d directDialer) Dial(network, addr string) (net.Conn, error) {
	dialer := net.Dialer{
		Timeout:   d.dialTimeout,
		KeepAlive: d.keepAlive,
	}
	return dialer.Dial(network, addr)
}

type TLSConfigFunc func() *tls.Config

type tlsDialer struct {
	timeout    time.Duration
	rawDialer  Dialer
	configFunc TLSConfigFunc
}

func (d tlsDialer) Dial(network, addr string) (net.Conn, error) {
	cfg := d.configFunc()
	if cfg == nil {
		return nil, errors.New("nil tls config")
	}
	rawConn, err := d.rawDialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	tlsCfg := cfg.Clone()
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = host
	}
	conn := tls.Client(rawConn, tlsCfg)
	if err := conn.SetDeadline(time.Now().Add(d.timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

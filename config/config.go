package config

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/R4MT1N/kafka-gcp-proxy/pkg/libs/util"
	"github.com/pkg/errors"
)

const defaultClientID = "kafka-gcp-proxy"

var (
	// Version is the current version of the app, generated at build time
	Version = "unknown"
)

type NetAddressMappingFunc func(brokerHost string, brokerPort int32, brokerId int32) (listenerHost string, listenerPort int32, err error)

type ListenerConfig struct {
	BrokerAddress     string
	ListenerAddress   string
	AdvertisedAddress string
}

type DialAddressMapping struct {
	SourceAddress      string
	DestinationAddress string
}

type Config struct {
	Http struct {
		ListenAddress string
		MetricsPath   string
		HealthPath    string
		Disable       bool
	}
	Debug struct {
		ListenAddress string
		DebugPath     string
		Enabled       bool
	}
	Log struct {
		Format string
		Level  string
	}
	Proxy struct {
		DefaultListenerIP         string
		BootstrapServers          []ListenerConfig
		ExternalServers           []ListenerConfig
		DeterministicListeners    bool
		DialAddressMappings       []DialAddressMapping
		DisableDynamicListeners   bool
		DynamicAdvertisedListener string
		DynamicSequentialMinPort  uint16
		DynamicSequentialMaxPorts uint16
		RequestBufferSize         int
		ResponseBufferSize        int
		ListenerReadBufferSize    int
		ListenerWriteBufferSize   int
		ListenerKeepAlive         time.Duration
	}
	Kafka struct {
		ClientID string

		MaxOpenRequests int

		ForbiddenApiKeys []int

		DialTimeout               time.Duration
		WriteTimeout              time.Duration
		ReadTimeout               time.Duration
		KeepAlive                 time.Duration
		ConnectionReadBufferSize  int
		ConnectionWriteBufferSize int

		TLS struct {
			Enable             bool
			Refresh            time.Duration
			InsecureSkipVerify bool
			CAChainCertFile    string
			SystemCertPool     bool
		}

		SASL struct {
			Enable bool
		}
		Producer struct {
			Acks0Disabled bool
		}
	}
}

func (c *Config) InitBootstrapServers(bootstrapServersMapping []string) (err error) {
	c.Proxy.BootstrapServers, err = getListenerConfigs(bootstrapServersMapping)
	return err
}

func (c *Config) InitExternalServers(externalServersMapping []string) (err error) {
	c.Proxy.ExternalServers, err = getListenerConfigs(externalServersMapping)
	return err
}

func (c *Config) InitDialAddressMappings(dialMappings []string) (err error) {
	c.Proxy.DialAddressMappings, err = getDialAddressMappings(dialMappings)
	return err
}

func getDialAddressMappings(dialMapping []string) ([]DialAddressMapping, error) {
	dialMappings := make([]DialAddressMapping, 0, len(dialMapping))
	for _, v := range dialMapping {
		pair := strings.Split(v, ",")
		if len(pair) != 2 {
			return nil, errors.New("dial-mapping must be in form 'srchost:srcport,dsthost:dstport'")
		}
		srcHost, srcPort, err := util.SplitHostPort(pair[0])
		if err != nil {
			return nil, err
		}
		dstHost, dstPort, err := util.SplitHostPort(pair[1])
		if err != nil {
			return nil, err
		}
		dialMappings = append(dialMappings, DialAddressMapping{
			SourceAddress:      net.JoinHostPort(srcHost, fmt.Sprint(srcPort)),
			DestinationAddress: net.JoinHostPort(dstHost, fmt.Sprint(dstPort)),
		})
	}
	return dialMappings, nil
}

func getListenerConfigs(serversMapping []string) ([]ListenerConfig, error) {
	listenerConfigs := make([]ListenerConfig, 0, len(serversMapping))
	for _, v := range serversMapping {
		pair := strings.Split(v, ",")
		if len(pair) != 2 && len(pair) != 3 {
			return nil, errors.New("server-mapping must be in form 'remotehost:remoteport,localhost:localport(,advhost:advport)'")
		}
		remoteHost, remotePort, err := util.SplitHostPort(pair[0])
		if err != nil {
			return nil, err
		}
		localHost, localPort, err := util.SplitHostPort(pair[1])
		if err != nil {
			return nil, err
		}
		advertisedHost, advertisedPort := localHost, localPort
		if len(pair) == 3 {
			advertisedHost, advertisedPort, err = util.SplitHostPort(pair[2])
			if err != nil {
				return nil, err
			}
		}

		listenerConfigs = append(listenerConfigs, ListenerConfig{
			BrokerAddress:     net.JoinHostPort(remoteHost, fmt.Sprint(remotePort)),
			ListenerAddress:   net.JoinHostPort(localHost, fmt.Sprint(localPort)),
			AdvertisedAddress: net.JoinHostPort(advertisedHost, fmt.Sprint(advertisedPort)),
		})
	}
	return listenerConfigs, nil
}

func NewConfig() *Config {
	c := &Config{}

	c.Kafka.ClientID = defaultClientID
	c.Kafka.MaxOpenRequests = 256
	c.Kafka.DialTimeout = 15 * time.Second
	c.Kafka.ReadTimeout = 30 * time.Second
	c.Kafka.WriteTimeout = 30 * time.Second
	c.Kafka.KeepAlive = 60 * time.Second
	c.Kafka.ForbiddenApiKeys = make([]int, 0)
	c.Kafka.SASL.Enable = true

	c.Http.MetricsPath = "/metrics"
	c.Http.HealthPath = "/health"

	c.Proxy.DefaultListenerIP = "127.0.0.1"
	c.Proxy.DisableDynamicListeners = false
	c.Proxy.RequestBufferSize = 4096
	c.Proxy.ResponseBufferSize = 4096
	c.Proxy.ListenerKeepAlive = 60 * time.Second

	return c
}

func (c *Config) Validate() error {
	if !c.Kafka.SASL.Enable {
		return errors.New("Kafka.SASL.Enable must be true (OAUTHBEARER via google-access-token-provider)")
	}
	if c.Kafka.KeepAlive < 0 {
		return errors.New("KeepAlive must be greater or equal 0")
	}
	if c.Kafka.DialTimeout < 0 {
		return errors.New("DialTimeout must be greater or equal 0")
	}
	if c.Kafka.ReadTimeout < 0 {
		return errors.New("ReadTimeout must be greater or equal 0")
	}
	if c.Kafka.WriteTimeout < 0 {
		return errors.New("WriteTimeout must be greater or equal 0")
	}
	if c.Kafka.MaxOpenRequests < 1 {
		return errors.New("MaxOpenRequests must be greater than 0")
	}
	if len(c.Proxy.BootstrapServers) == 0 {
		return errors.New("list of bootstrap-server-mapping must not be empty")
	}
	if c.Proxy.DefaultListenerIP == "" {
		return errors.New("DefaultListenerIP must not be empty")
	}
	if net.ParseIP(c.Proxy.DefaultListenerIP) == nil {
		return errors.New("DefaultListenerIP is not a valid IP")
	}
	if c.Proxy.RequestBufferSize < 1 {
		return errors.New("RequestBufferSize must be greater than 0")
	}
	if c.Proxy.ResponseBufferSize < 1 {
		return errors.New("ResponseBufferSize must be greater than 0")
	}
	if c.Proxy.ListenerKeepAlive < 0 {
		return errors.New("ListenerKeepAlive must be greater or equal 0")
	}

	if !c.Proxy.DisableDynamicListeners {
		if c.Proxy.DynamicSequentialMinPort == 0 && c.Proxy.DeterministicListeners {
			return errors.New("Proxy.DynamicSequentialMinPort must be set when Proxy.DeterministicListeners is enabled")
		}
		if c.Proxy.DynamicSequentialMinPort == 0 && c.Proxy.DynamicSequentialMaxPorts > 0 {
			return errors.New("Proxy.DynamicSequentialMinPort must be set when Proxy.DynamicSequentialMaxPorts is set")
		}
		if c.Proxy.DynamicSequentialMaxPorts == 0 && c.Proxy.DynamicSequentialMinPort > 0 {
			c.Proxy.DynamicSequentialMaxPorts = uint16(65536 - uint32(c.Proxy.DynamicSequentialMinPort))
		}
	}
	return nil
}

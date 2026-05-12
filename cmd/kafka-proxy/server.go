package server

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/R4MT1N/kafka-gcp-proxy/config"
	"github.com/R4MT1N/kafka-gcp-proxy/pkg/apis"
	"github.com/R4MT1N/kafka-gcp-proxy/pkg/registry"
	"github.com/R4MT1N/kafka-gcp-proxy/proxy"
	"github.com/oklog/run"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	sloglogrus "github.com/samber/slog-logrus/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	// built-in token provider
	_ "github.com/R4MT1N/kafka-gcp-proxy/pkg/libs/google-access-token-provider"
)

var (
	c = new(config.Config)

	bootstrapServersMapping = make([]string, 0)
	externalServersMapping  = make([]string, 0)
	dialAddressMapping      = make([]string, 0)

	tokenProviderCommand = "google-access-token-provider"
	tokenProviderParams  = make([]string, 0)
)

var Server = &cobra.Command{
	Use:   "server",
	Short: "Run the kafka-gcp-proxy server",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		SetLogger()
		// This binary only speaks SASL/OAUTHBEARER — there is no opt-out.
		c.Kafka.SASL.Enable = true
		if err := c.InitBootstrapServers(getOrEnvStringSlice(bootstrapServersMapping, "BOOTSTRAP_SERVER_MAPPING")); err != nil {
			return err
		}
		if err := c.InitExternalServers(getOrEnvStringSlice(externalServersMapping, "EXTERNAL_SERVER_MAPPING")); err != nil {
			return err
		}
		if err := c.InitDialAddressMappings(getOrEnvStringSlice(dialAddressMapping, "DIAL_ADDRESS_MAPPING")); err != nil {
			return err
		}
		return c.Validate()
	},
	Run: Run,
}

func getOrEnvStringSlice(value []string, envKey string) []string {
	if len(value) != 0 {
		return value
	}
	return strings.Fields(os.Getenv(envKey))
}

func init() {
	initFlags()
}

func initFlags() {
	// proxy
	Server.Flags().StringVar(&c.Proxy.DefaultListenerIP, "default-listener-ip", "127.0.0.1", "Default listener IP")
	Server.Flags().StringVar(&c.Proxy.DynamicAdvertisedListener, "dynamic-advertised-listener", "", "Advertised address for dynamic listeners. If empty, default-listener-ip is used. Supports {{.brokerId}} templating.")
	Server.Flags().StringArrayVar(&bootstrapServersMapping, "bootstrap-server-mapping", []string{}, "Mapping of Kafka bootstrap server address to local address (host:port,host:port(,advhost:advport))")
	Server.Flags().StringArrayVar(&externalServersMapping, "external-server-mapping", []string{}, "Mapping of Kafka server address to external address (host:port,host:port)")
	Server.Flags().StringArrayVar(&dialAddressMapping, "dial-address-mapping", []string{}, "Mapping of target broker address to new one (host:port,host:port)")
	Server.Flags().BoolVar(&c.Proxy.DeterministicListeners, "deterministic-listeners", false, "Enable deterministic listeners (listener port = min port + broker id).")
	Server.Flags().BoolVar(&c.Proxy.DisableDynamicListeners, "dynamic-listeners-disable", false, "Disable dynamic listeners.")
	Server.Flags().Uint16Var(&c.Proxy.DynamicSequentialMinPort, "dynamic-sequential-min-port", 0, "Sequential port allocation start.")
	Server.Flags().Uint16Var(&c.Proxy.DynamicSequentialMaxPorts, "dynamic-sequential-max-ports", 0, "Number of sequential ports from min-port.")

	Server.Flags().IntVar(&c.Proxy.RequestBufferSize, "proxy-request-buffer-size", 4096, "Request buffer size per tcp connection")
	Server.Flags().IntVar(&c.Proxy.ResponseBufferSize, "proxy-response-buffer-size", 4096, "Response buffer size per tcp connection")
	Server.Flags().IntVar(&c.Proxy.ListenerReadBufferSize, "proxy-listener-read-buffer-size", 0, "SO_RCVBUF for listener; 0 = system default")
	Server.Flags().IntVar(&c.Proxy.ListenerWriteBufferSize, "proxy-listener-write-buffer-size", 0, "SO_SNDBUF for listener; 0 = system default")
	Server.Flags().DurationVar(&c.Proxy.ListenerKeepAlive, "proxy-listener-keep-alive", 60*time.Second, "Keep alive for listener connections.")

	// kafka
	Server.Flags().StringVar(&c.Kafka.ClientID, "kafka-client-id", "kafka-gcp-proxy", "Identifier for tracking the source of requests")
	Server.Flags().IntVar(&c.Kafka.MaxOpenRequests, "kafka-max-open-requests", 256, "Max open requests per tcp connection")
	Server.Flags().DurationVar(&c.Kafka.DialTimeout, "kafka-dial-timeout", 15*time.Second, "Connection dial timeout")
	Server.Flags().DurationVar(&c.Kafka.WriteTimeout, "kafka-write-timeout", 30*time.Second, "Write timeout")
	Server.Flags().DurationVar(&c.Kafka.ReadTimeout, "kafka-read-timeout", 30*time.Second, "Read timeout")
	Server.Flags().DurationVar(&c.Kafka.KeepAlive, "kafka-keep-alive", 60*time.Second, "Broker connection keep alive")
	Server.Flags().IntVar(&c.Kafka.ConnectionReadBufferSize, "kafka-connection-read-buffer-size", 0, "SO_RCVBUF for kafka connection; 0 = system default")
	Server.Flags().IntVar(&c.Kafka.ConnectionWriteBufferSize, "kafka-connection-write-buffer-size", 0, "SO_SNDBUF for kafka connection; 0 = system default")
	Server.Flags().IntSliceVar(&c.Kafka.ForbiddenApiKeys, "forbidden-api-keys", []int{}, "Forbidden Kafka request API keys")
	Server.Flags().BoolVar(&c.Kafka.Producer.Acks0Disabled, "producer-acks-0-disabled", false, "Assume fire-and-forget produces are never used")

	// TLS to broker
	Server.Flags().BoolVar(&c.Kafka.TLS.Enable, "tls-enable", true, "Use TLS to connect to broker (GCP Managed Kafka requires TLS)")
	Server.Flags().DurationVar(&c.Kafka.TLS.Refresh, "tls-refresh", 0*time.Second, "Refresh interval for client TLS")
	Server.Flags().BoolVar(&c.Kafka.TLS.InsecureSkipVerify, "tls-insecure-skip-verify", false, "Skip broker certificate verification")
	Server.Flags().StringVar(&c.Kafka.TLS.CAChainCertFile, "tls-ca-chain-cert-file", "", "PEM encoded CA's certificate file")
	Server.Flags().BoolVar(&c.Kafka.TLS.SystemCertPool, "tls-system-cert-pool", true, "Use system pool for root CAs")

	// token provider
	Server.Flags().StringVar(&tokenProviderCommand, "token-provider", "google-access-token-provider", "Built-in TokenProvider name")
	Server.Flags().StringArrayVar(&tokenProviderParams, "token-provider-param", []string{"--adc=true"}, "TokenProvider parameter (repeatable)")

	// Web
	Server.Flags().BoolVar(&c.Http.Disable, "http-disable", false, "Disable HTTP endpoints")
	Server.Flags().StringVar(&c.Http.ListenAddress, "http-listen-address", "0.0.0.0:9080", "Metrics/health listen address")
	Server.Flags().StringVar(&c.Http.MetricsPath, "http-metrics-path", "/metrics", "Path on which to expose metrics")
	Server.Flags().StringVar(&c.Http.HealthPath, "http-health-path", "/health", "Path on which to expose health")

	// Debug
	Server.Flags().BoolVar(&c.Debug.Enabled, "debug-enable", false, "Enable Debug endpoint")
	Server.Flags().StringVar(&c.Debug.ListenAddress, "debug-listen-address", "0.0.0.0:6060", "Debug listen address")

	// Logging
	Server.Flags().StringVar(&c.Log.Format, "log-format", "text", "Log format text or json")
	Server.Flags().StringVar(&c.Log.Level, "log-level", "info", "Log level")

	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}

func Run(_ *cobra.Command, _ []string) {
	logrus.Infof("Starting kafka-gcp-proxy version %s on platform %s/%s", config.Version, runtime.GOOS, runtime.GOARCH)

	factory, ok := registry.GetComponent(new(apis.TokenProviderFactory), tokenProviderCommand).(apis.TokenProviderFactory)
	if !ok {
		logrus.Fatal(errors.Errorf("unknown built-in token provider %q", tokenProviderCommand))
	}
	logrus.Infof("Using built-in %q TokenProvider for SASL/OAUTHBEARER", tokenProviderCommand)
	saslTokenProvider, err := factory.New(tokenProviderParams)
	if err != nil {
		logrus.Fatal(err)
	}

	var g run.Group
	{
		connset := proxy.NewConnSet()
		prometheus.MustRegister(proxy.NewCollector(connset))
		listeners, err := proxy.NewListeners(c)
		if err != nil {
			logrus.Fatal(err)
		}
		connSrc, err := listeners.ListenInstances(c.Proxy.BootstrapServers)
		if err != nil {
			logrus.Fatal(err)
		}
		proxyClient, err := proxy.NewClient(connset, c, listeners.GetNetAddressMapping, saslTokenProvider)
		if err != nil {
			logrus.Fatal(err)
		}
		g.Add(func() error {
			logrus.Print("Ready for new connections")
			return proxyClient.Run(connSrc)
		}, func(error) {
			proxyClient.Close()
		})
	}
	{
		cancelInterrupt := make(chan struct{})
		g.Add(func() error {
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			select {
			case sig := <-sigCh:
				return fmt.Errorf("received signal %s", sig)
			case <-cancelInterrupt:
				return nil
			}
		}, func(error) {
			close(cancelInterrupt)
		})
	}
	if !c.Http.Disable {
		httpListener, err := net.Listen("tcp", c.Http.ListenAddress)
		if err != nil {
			logrus.Fatal(err)
		}
		g.Add(func() error {
			return http.Serve(httpListener, NewHTTPHandler())
		}, func(error) {
			httpListener.Close()
		})
	}
	if c.Debug.Enabled {
		debugListener, err := net.Listen("tcp", c.Debug.ListenAddress)
		if err != nil {
			logrus.Fatal(err)
		}
		g.Add(func() error {
			return http.Serve(debugListener, http.DefaultServeMux)
		}, func(error) {
			debugListener.Close()
		})
	}

	if err := g.Run(); err != nil {
		logrus.Info("Exit ", err)
	}
}

func NewHTTPHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><h1>kafka-gcp-proxy</h1><p><a href='` + c.Http.MetricsPath + `'>Metrics</a></p></body></html>`))
	})
	m.HandleFunc(c.Http.HealthPath, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})
	m.Handle(c.Http.MetricsPath, promhttp.Handler())
	return m
}

func SetLogger() {
	if c.Log.Format == "json" {
		logrus.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	}
	level, err := logrus.ParseLevel(c.Log.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)
	slog.SetDefault(slog.New(sloglogrus.Option{Level: toSlogLevel(level), Logger: logrus.StandardLogger()}.NewLogrusHandler()))
}

func toSlogLevel(level logrus.Level) slog.Level {
	switch level {
	case logrus.TraceLevel, logrus.DebugLevel:
		return slog.LevelDebug
	case logrus.InfoLevel:
		return slog.LevelInfo
	case logrus.WarnLevel:
		return slog.LevelWarn
	case logrus.ErrorLevel, logrus.PanicLevel:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

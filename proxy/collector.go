package proxy

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	proxyConnectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "proxy_connections_total",
			Help: "Total number of created connections"},
		[]string{"broker"})

	proxyRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "proxy_requests_total",
			Help: "Total number of requests sent"},
		[]string{"broker", "api_key", "api_version"})

	proxyRequestsBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "proxy_requests_bytes",
			Help: "Size of outgoing requests"},
		[]string{"broker"})

	proxyResponsesBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "proxy_responses_bytes",
			Help: "Size of incoming responses"},
		[]string{"broker"})

	proxyOpenedConnections = prometheus.NewDesc(
		"proxy_opened_connections",
		"Number of opened connections",
		[]string{"broker"}, nil,
	)

	proxyLocalAuthTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "proxy_local_auth_total",
			Help: "Total number of local auth requests sent"},
		[]string{"success", "status"})

	// KIP-368 re-auth observability. These exist specifically so operators
	// can alert on credential refresh failures without grepping pod logs.

	proxyReauthAttemptsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "proxy_reauth_attempts_total",
			Help: "Total SASL re-authentication attempts initiated by the proxy"},
		[]string{"broker"})

	proxyReauthFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "proxy_reauth_failures_total",
			Help: "Total re-auth failures broken down by stage — token fetch, write to broker, broker reject, response timeout, channel saturation"},
		[]string{"broker", "reason"})

	proxyReauthSuccessTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "proxy_reauth_success_total",
			Help: "Total re-auth round-trips that completed successfully (broker accepted refreshed credentials)"},
		[]string{"broker"})

	proxyReauthDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "proxy_reauth_duration_seconds",
			Help:    "End-to-end latency from re-auth send to response handled. Should sit comfortably under the inflight cushion.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		},
		[]string{"broker"})

	proxyReauthSessionLifetimeSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "proxy_reauth_session_lifetime_seconds",
			Help: "Last broker-advertised session_lifetime_ms converted to seconds. 0 means the broker did not negotiate KIP-368 on this connection."},
		[]string{"broker"})

	proxyConnectionTeardownTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "proxy_connection_teardown_total",
			Help: "Broker-side connection teardowns by cause. 'client_eof' is the normal path; anything else means the connection died for a reason worth alerting on."},
		[]string{"broker", "reason"})
)

// Re-auth failure reasons. Stable label values for alerting.
const (
	ReauthReasonTokenFetch     = "token_fetch"
	ReauthReasonBrokerWrite    = "broker_write"
	ReauthReasonBrokerReject   = "broker_reject"
	ReauthReasonResponseStuck  = "response_timeout"
	ReauthReasonChannelFull    = "channel_full"
	ReauthReasonResponseDecode = "response_decode"
)

func init() {
	prometheus.MustRegister(proxyConnectionsTotal)
	prometheus.MustRegister(proxyRequestsTotal)
	prometheus.MustRegister(proxyRequestsBytes)
	prometheus.MustRegister(proxyResponsesBytes)
	prometheus.MustRegister(proxyLocalAuthTotal)
	prometheus.MustRegister(proxyReauthAttemptsTotal)
	prometheus.MustRegister(proxyReauthFailuresTotal)
	prometheus.MustRegister(proxyReauthSuccessTotal)
	prometheus.MustRegister(proxyReauthDurationSeconds)
	prometheus.MustRegister(proxyReauthSessionLifetimeSeconds)
	prometheus.MustRegister(proxyConnectionTeardownTotal)
}

type proxyCollector struct {
	connSet *ConnSet
}

func NewCollector(connSet *ConnSet) prometheus.Collector {
	return &proxyCollector{connSet: connSet}
}

func (p *proxyCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- proxyOpenedConnections
}

func (p *proxyCollector) Collect(ch chan<- prometheus.Metric) {

	brokerToCount := p.connSet.Count()
	for broker, count := range brokerToCount {
		ch <- prometheus.MustNewConstMetric(proxyOpenedConnections, prometheus.GaugeValue, float64(count), broker)
	}
}

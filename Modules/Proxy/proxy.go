package Proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/miekg/dns"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Logger"
)

var dotTLSConfig *tls.Config

// Load the DoT server's certificate into a trusted CA pool
func loadTLSConfig(certPath string) (*tls.Config, error) {
	caCert, err := os.ReadFile(certPath)
	if err != nil {
		Logger.LogError("❌ Failed to read certificate file", err)
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		Logger.LogError("❌ Failed to append certificate to pool", err)
		return nil, fmt.Errorf("failed to append certificate to pool")
	}

	return &tls.Config{
		ServerName: "localhost",
		RootCAs:    caPool,
	}, nil
}

// Initialize and start the proxy DNS server on port 53
func InitProxy() error {
	var err error
	dotTLSConfig, err = loadTLSConfig("Modules/SSL/localhost.pem")
	if err != nil {
		Logger.LogError("❌ TLS config error", err)
		return fmt.Errorf("TLS config error: %w", err)
	}

	dns.HandleFunc(".", ProxyToDoT)

	// Start UDP server on port 53
	go func() {
		udpServer := &dns.Server{Addr: ":53", Net: "udp"}
		Logger.LogApplication("📡 Starting UDP proxy server on port 53")
		if err := udpServer.ListenAndServe(); err != nil {
			Logger.LogError("❌ Failed to start UDP proxy server on port 53", err)
		}
	}()

	// Start TCP server on port 53
	go func() {
		tcpServer := &dns.Server{Addr: ":53", Net: "tcp"}
		Logger.LogApplication("📡 Starting TCP proxy server on port 53")
		if err := tcpServer.ListenAndServe(); err != nil {
			Logger.LogError("❌ Failed to start TCP proxy server on port 53", err)
		}
	}()

	Logger.LogApplication("📡 DNS proxy server is listening on port 53 and forwarding to DoT on port 853")
	return nil
}

// Proxy DNS requests to the DoT server securely
func ProxyToDoT(w dns.ResponseWriter, r *dns.Msg) {
	// Log the incoming DNS query
	Logger.LogApplication(fmt.Sprintf("🔍 Received DNS query for %s", r.Question[0].Name))

	// Establish a secure connection to the DoT server
	conn, err := tls.Dial("tcp", "127.0.0.1:853", dotTLSConfig)
	if err != nil {
		Logger.LogError("❌ Failed to connect to DoT server", err)
		dns.HandleFailed(w, r)
		return
	}
	defer conn.Close()

	client := &dns.Conn{Conn: conn}

	// Send the DNS query to the DoT server
	if err := client.WriteMsg(r); err != nil {
		Logger.LogError("❌ Failed to send query to DoT server", err)
		dns.HandleFailed(w, r)
		return
	}

	// Receive the response from the DoT server
	resp, err := client.ReadMsg()
	if err != nil {
		Logger.LogError("❌ Failed to read response from DoT server", err)
		dns.HandleFailed(w, r)
		return
	}

	// Log the successful query forwarding
	Logger.LogApplication(fmt.Sprintf("✅ Successfully forwarded query for %s to DoT server", r.Question[0].Name))

	// Send the response back to the client
	if err := w.WriteMsg(resp); err != nil {
		Logger.LogError("❌ Failed to send response back to client", err)
	}
}

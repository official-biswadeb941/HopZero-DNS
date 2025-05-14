package Proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/miekg/dns"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Logger"
)

var (
	dotTLSConfig *tls.Config
	logProxy     *Logger.ModuleLogger
)

func init() {
	var err error
	logProxy, err = Logger.GetLogger("Proxy")
	if err != nil {
		fmt.Println("Fallback: failed to initialize logger for Proxy module:", err)
	}
}

// Load the DoT server's certificate into a trusted CA pool
func loadTLSConfig(certPath string) (*tls.Config, error) {
	caCert, err := os.ReadFile(certPath)
	if err != nil {
		logProxy.Error(fmt.Sprintf("Failed to read certificate file: %s", certPath))
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		logProxy.Error("Failed to append certificate to pool")
		return nil, fmt.Errorf("failed to append certificate to pool")
	}

	logProxy.Info("✔️ TLS configuration loaded successfully")
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
		logProxy.Error("TLS config error: " + err.Error())
		return err
	}

	dns.HandleFunc(".", ProxyToDoT)

	go func() {
		logProxy.Info("📡 Starting UDP proxy server on port 53")
		udpServer := &dns.Server{Addr: ":53", Net: "udp"}
		if err := udpServer.ListenAndServe(); err != nil {
			logProxy.Error("Failed to start UDP proxy server: " + err.Error())
		}
	}()

	go func() {
		logProxy.Info("📡 Starting TCP proxy server on port 53")
		tcpServer := &dns.Server{Addr: ":53", Net: "tcp"}
		if err := tcpServer.ListenAndServe(); err != nil {
			logProxy.Error("Failed to start TCP proxy server: " + err.Error())
		}
	}()

	logProxy.Info("✅ DNS proxy server is listening on port 53 and forwarding to DoT on port 853")
	return nil
}

// Proxy DNS requests to the DoT server securely
func ProxyToDoT(w dns.ResponseWriter, r *dns.Msg) {
	domain := r.Question[0].Name
	logProxy.Info(fmt.Sprintf("🔍 Received DNS query for: %s", domain))

	conn, err := tls.Dial("tcp", "127.0.0.1:853", dotTLSConfig)
	if err != nil {
		logProxy.Error("❌ Failed to connect to DoT server: " + err.Error())
		dns.HandleFailed(w, r)
		return
	}
	defer conn.Close()

	client := &dns.Conn{Conn: conn}

	if err := client.WriteMsg(r); err != nil {
		logProxy.Error("❌ Failed to send DNS query to DoT server: " + err.Error())
		dns.HandleFailed(w, r)
		return
	}

	resp, err := client.ReadMsg()
	if err != nil {
		logProxy.Error("❌ Failed to read DNS response from DoT server: " + err.Error())
		dns.HandleFailed(w, r)
		return
	}

	logProxy.Info(fmt.Sprintf("✅ Successfully forwarded query for %s to DoT server", domain))

	if err := w.WriteMsg(resp); err != nil {
		logProxy.Warn("⚠️ Failed to send response back to client: " + err.Error())
	}
}

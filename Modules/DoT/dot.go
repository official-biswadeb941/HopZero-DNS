package DoT

import (
	"crypto/tls"
	"log"

	"github.com/miekg/dns"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Resolver"
)

type DoTServer struct {
	Addr      string
	CertPath  string
	KeyPath   string
	TLSConfig *tls.Config
	Server    *dns.Server
}

// Initialize a new DoT server
func NewDoTServer(addr, certPath, keyPath string) (*DoTServer, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	srv := &dns.Server{
		Addr:      addr,
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Handler:   dns.HandlerFunc(basicDNSHandler), // Will replace this later
	}

	return &DoTServer{
		Addr:      addr,
		CertPath:  certPath,
		KeyPath:   keyPath,
		TLSConfig: tlsConfig,
		Server:    srv,
	}, nil
}

// Start the DoT server
func (d *DoTServer) Start() error {
	log.Printf("[+] Starting DNS-over-TLS server on %s\n", d.Addr)
	return d.Server.ListenAndServe()
}

// Stop the server gracefully
func (d *DoTServer) Stop() error {
	log.Println("[-] Stopping DoT server...")
	return d.Server.Shutdown()
}

// Temporary DNS handler — replace this with actual resolution logic
func basicDNSHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	// Process each question (e.g., for A, AAAA records)
	for _, q := range r.Question {
		// Call the actual resolver function for real resolution
		answers, err := Resolver.RecursiveResolve(q.Name, q.Qtype)
		if err != nil {
			log.Printf("Failed to resolve %s: %v", q.Name, err)
			m.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(m)
			return
		}
		m.Answer = append(m.Answer, answers...)
	}

	_ = w.WriteMsg(m)
}

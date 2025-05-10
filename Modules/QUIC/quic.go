package QUIC

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"time"

	"github.com/quic-go/quic-go"
)

// ResolverFunc is the function signature for DNS query resolvers.
type ResolverFunc func([]byte) ([]byte, error)

// maxDNSPacketSize is the max size we allow for DNS packets (QUIC-safe).
const maxDNSPacketSize = 4096

// HandleStream processes a single DNS query over a QUIC stream.
func HandleStream(stream quic.Stream, resolver ResolverFunc) error {
	defer stream.Close()

	buf := make([]byte, maxDNSPacketSize)

	// Read the DNS query (at least 12 bytes for DNS header)
	n, err := io.ReadAtLeast(stream, buf, 12)
	if err != nil && err != io.EOF {
		return fmt.Errorf("stream read error: %w", err)
	}

	if n > maxDNSPacketSize {
		return fmt.Errorf("packet too large: %d bytes", n)
	}

	query := buf[:n]

	// Enforce resolver timeout
	responseCh := make(chan []byte, 1)
	errCh := make(chan error, 1)

	go func() {
		resp, err := resolver(query)
		if err != nil {
			errCh <- err
			return
		}
		responseCh <- resp
	}()

	select {
	case resp := <-responseCh:
		_, err = stream.Write(resp)
		if err != nil {
			return fmt.Errorf("stream write error: %w", err)
		}
	case err := <-errCh:
		return fmt.Errorf("resolver function error: %w", err)
	case <-time.After(2 * time.Second):
		return fmt.Errorf("resolver timeout")
	}

	return nil
}

// LoadTLSConfig loads and validates TLS credentials.
func LoadTLSConfig() (*tls.Config, error) {
	certPath := path.Join("Modules", "SSL", "cert.pem")
	keyPath := path.Join("Modules", "SSL", "key.pem")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("certificate file not found: %s", certPath)
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("key file not found: %s", keyPath)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair: %w", err)
	}

	return &tls.Config{
		Certificates:             []tls.Certificate{cert},
		NextProtos:               []string{"doq"},
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		},
	}, nil
}

// HandleConnection listens for incoming QUIC streams and dispatches them.
func HandleConnection(conn quic.Connection, resolver ResolverFunc) {
	remoteAddr := sanitizeRemoteAddr(conn.RemoteAddr())
	log.Printf("[QUIC] Accepted connection from %s", remoteAddr)

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		stream, err := conn.AcceptStream(ctx)
		cancel()

		if err != nil {
			log.Printf("[QUIC] Error accepting stream from %s: %v", remoteAddr, err)
			return
		}

		go func(s quic.Stream) {
			if err := HandleStream(s, resolver); err != nil {
				log.Printf("[QUIC] Stream error [%s]: %v", remoteAddr, err)
			}
		}(stream)
	}
}

// sanitizeRemoteAddr trims details for privacy/security (optional).
func sanitizeRemoteAddr(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	return addr.String() // You could strip port/IP for cleaner logs
}

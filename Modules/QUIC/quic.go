package QUIC

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/quic-go/quic-go"
)

// ResolverFunc is the function signature for DNS query resolvers.
type ResolverFunc func([]byte) ([]byte, error)

// HandleStream processes a single DNS query over a QUIC stream.
func HandleStream(stream quic.Stream, resolver ResolverFunc) error {
	defer stream.Close()

	buf := make([]byte, 65535)

	// Minimum read for DNS header: 12 bytes. Adjust as needed.
	n, err := io.ReadAtLeast(stream, buf, 12)
	if err != nil && err != io.EOF {
		return fmt.Errorf("stream read error: %w", err)
	}

	query := buf[:n]

	response, err := resolver(query)
	if err != nil {
		return fmt.Errorf("resolver function error: %w", err)
	}

	_, err = stream.Write(response)
	if err != nil {
		return fmt.Errorf("stream write error: %w", err)
	}

	return nil
}

// LoadTLSConfig loads the TLS certificate and key from disk.
func LoadTLSConfig() (*tls.Config, error) {
	certPath := filepath.Join("Modules", "SSL", "cert.pem")
	keyPath := filepath.Join("Modules", "SSL", "key.pem")

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
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"doq"}, // DNS over QUIC
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// HandleConnection listens for incoming QUIC streams and dispatches them.
func HandleConnection(conn quic.Connection, resolver ResolverFunc) {
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[QUIC] Accepted connection from %s", remoteAddr)

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		stream, err := conn.AcceptStream(ctx)
		cancel() // Ensure context is cleaned up

		if err != nil {
			log.Printf("[QUIC] Error accepting stream from %s: %v", remoteAddr, err)
			return
		}

		go func(s quic.Stream) {
			if err := HandleStream(s, resolver); err != nil {
				log.Printf("[QUIC] Error handling stream from %s: %v", remoteAddr, err)
			}
		}(stream)
	}
}

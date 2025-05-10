package main

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/miekg/dns"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Logger"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/QUIC"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Redis"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Resolver"
	"github.com/quic-go/quic-go"
)

func main() {
	Redis.InitRedis()

	// Start UDP DNS server
	//	go startUDPServer()

	// Start QUIC DNS server
	go startQUICServer()

	select {} // block forever
}

// ---------------- UDP DNS ----------------

//func startUDPServer() {
//	dns.HandleFunc(".", handleDNSRequestUDP)
//	server := &dns.Server{Addr: ":53", Net: "udp"}
//	Logger.LogApplication("🚀 UDP DNS server listening on port 53...")
//	if err := server.ListenAndServe(); err != nil {
//		Logger.LogError("❌ Failed to start UDP DNS server", err)
//	}
//}

func handleDNSRequestUDP(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if len(r.Question) == 0 {
		msg.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(msg)
		Logger.LogError("Invalid DNS query format", fmt.Errorf("no question in query"))
		return
	}

	question := r.Question[0]
	Logger.LogApplication(fmt.Sprintf("📨 [UDP] Received query for %s (%s)", question.Name, dns.TypeToString[question.Qtype]))

	answers, err := Resolver.RecursiveResolve(question.Name, question.Qtype)
	if err != nil {
		Logger.LogError(fmt.Sprintf("Failed to resolve %s", question.Name), err)
		msg.Rcode = dns.RcodeServerFailure
	} else {
		msg.Answer = answers
	}

	_ = w.WriteMsg(msg)
}

// ---------------- QUIC DNS ----------------

func startQUICServer() {
	tlsConf, err := QUIC.LoadTLSConfig()
	if err != nil {
		log.Fatalf("❌ Failed to load TLS config for QUIC: %v", err)
	}

	listener, err := quic.ListenAddr(":853", tlsConf, nil)
	if err != nil {
		log.Fatalf("❌ Failed to start QUIC server: %v", err)
	}
	Logger.LogApplication("🚀 QUIC DNS server listening on port 853...")

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			Logger.LogError("Failed to accept QUIC connection", err)
			continue
		}

		go handleQUICConnection(conn)
	}
}

func handleQUICConnection(conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			Logger.LogError("Failed to accept QUIC stream", err)
			return
		}
		go handleQUICStream(stream)
	}
}

func handleQUICStream(stream quic.Stream) {
	defer stream.Close()

	buf := make([]byte, 65535)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		Logger.LogError("❌ Failed to read from QUIC stream", err)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(buf[:n]); err != nil {
		Logger.LogError("❌ Failed to unpack QUIC DNS request", err)
		return
	}

	if len(req.Question) == 0 {
		Logger.LogError("❌ Invalid DNS over QUIC request", fmt.Errorf("empty question"))
		return
	}

	question := req.Question[0]
	Logger.LogApplication(fmt.Sprintf("📨 [QUIC] Received query for %s (%s)", question.Name, dns.TypeToString[question.Qtype]))

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	answers, err := Resolver.RecursiveResolve(question.Name, question.Qtype)
	if err != nil {
		Logger.LogError(fmt.Sprintf("Failed to resolve %s", question.Name), err)
		resp.Rcode = dns.RcodeServerFailure
	} else {
		resp.Answer = answers
	}

	packed, err := resp.Pack()
	if err != nil {
		Logger.LogError("❌ Failed to pack DNS response for QUIC", err)
		return
	}

	if _, err := stream.Write(packed); err != nil {
		Logger.LogError("❌ Failed to write QUIC response", err)
	}
	stream.Close()
}

package main

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Logger"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Redis"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Resolver"
)

func main() {
	Redis.InitRedis()

	// DNS request handler
	dns.HandleFunc(".", handleDNSRequest)

	// Start DNS server
	server := &dns.Server{Addr: ":53", Net: "udp"}
	Logger.LogApplication("🚀 DNS server listening on UDP port 53...")
	if err := server.ListenAndServe(); err != nil {
		Logger.LogError("Failed to start DNS server", err)
	}
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
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
	Logger.LogApplication(fmt.Sprintf("📨 Received query for %s (%s)", question.Name, dns.TypeToString[question.Qtype]))

	answers, err := Resolver.RecursiveResolve(question.Name, question.Qtype)
	if err != nil {
		Logger.LogError(fmt.Sprintf("Failed to resolve %s", question.Name), err)
		msg.Rcode = dns.RcodeServerFailure
	} else {
		msg.Answer = answers
	}

	_ = w.WriteMsg(msg)
}

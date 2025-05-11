package main

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/DoT"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Logger"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Proxy"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Redis"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Resolver"
)

func main() {
	// 🔀 Feature toggles
	enableProxy := true // toggle DNS proxy on port 53
	enableDoT := true // toggle DNS-over-TLS on port 853

	// Initialize Redis
	Redis.InitRedis()

	if enableProxy {
		if err := Proxy.InitProxy(); err != nil {
			Logger.LogError("❌ Failed to start DNS proxy server", err)
			return
		}
		Logger.LogApplication("📡 DNS proxy is active on port 53 and forwarding to DoT")
	}

	if enableDoT {
		dotServer, err := DoT.NewDoTServer(":853", "Modules/SSL/localhost.pem", "Modules/SSL/localhost-key.pem")
		if err != nil {
			Logger.LogError("❌ Failed to initialize DoT server", err)
			return
		}
		Logger.LogApplication("🚀 DNS-over-TLS server is running on port 853")

		if err := dotServer.Start(); err != nil {
			Logger.LogError("❌ Failed to start DoT server", err)
		}
	}
}

// DoT query handler
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

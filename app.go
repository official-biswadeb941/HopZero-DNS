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

var logApp *Logger.ModuleLogger

func main() {
	var err error
	logApp, err = Logger.GetLogger("App")
	if err != nil {
		fmt.Println("Fallback: failed to initialize logger for App module:", err)
		return
	}

	// 🔀 Feature toggles
	enableProxy := true // toggle DNS proxy on port 53
	enableDoT := true   // toggle DNS-over-TLS on port 853

	// Initialize Redis
	Redis.InitRedis()
	logApp.Info("🔌 Redis cache initialized")

	// Start DNS Proxy if enabled
	if enableProxy {
		if err := Proxy.InitProxy(); err != nil {
			logApp.Error("❌ Failed to start DNS proxy server: " + err.Error())
			return
		}
		logApp.Info("📡 DNS proxy is active on port 53 and forwarding to DoT")
	}

	// Start DoT Server if enabled
	if enableDoT {
		dotServer, err := DoT.NewDoTServer(":853", "Modules/SSL/localhost.pem", "Modules/SSL/localhost-key.pem")
		if err != nil {
			logApp.Error("❌ Failed to initialize DoT server: " + err.Error())
			return
		}
		logApp.Info("🚀 DNS-over-TLS server is running on port 853")

		if err := dotServer.Start(); err != nil {
			logApp.Error("❌ Failed to start DoT server: " + err.Error())
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
		logApp.Error("📛 Invalid DNS query format: no question in query")
		return
	}

	question := r.Question[0]
	logApp.Info(fmt.Sprintf("📨 Received query for %s (%s)", question.Name, dns.TypeToString[question.Qtype]))

	answers, err := Resolver.RecursiveResolve(question.Name, question.Qtype)
	if err != nil {
		logApp.Warn(fmt.Sprintf("❌ Failed to resolve %s: %s", question.Name, err.Error()))
		msg.Rcode = dns.RcodeServerFailure
	} else {
		msg.Answer = answers
	}

	_ = w.WriteMsg(msg)
}

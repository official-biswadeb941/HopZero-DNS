package Resolver

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/official-biswadeb941/HopZero-DNS/loader"

	"github.com/miekg/dns"
)

var rootServers = []string{
	"198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10",
}

func RecursiveResolve(domain string, qtype uint16) ([]dns.RR, error) {
	cacheKey := fmt.Sprintf("%s_%d", domain, qtype)

	cached, err := loader.RedisClient.Get(loader.Ctx, cacheKey).Result()
	if err == nil {
		var answers []dns.RR
		json.Unmarshal([]byte(cached), &answers)
		fmt.Println("✅ From cache")
		return answers, nil
	}

	client := new(dns.Client)
	client.Timeout = 5 * time.Second

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)

	for _, server := range rootServers {
		resp, _, err := client.Exchange(msg, net.JoinHostPort(server, "53"))
		if err != nil {
			continue
		}
		answers, err := followChain(client, resp, qtype)
		if err == nil && len(answers) > 0 {
			b, _ := json.Marshal(answers)
			loader.RedisClient.Set(loader.Ctx, cacheKey, b, 300*time.Second)
			return answers, nil
		}
	}

	return nil, fmt.Errorf("failed to resolve domain: %s", domain)
}

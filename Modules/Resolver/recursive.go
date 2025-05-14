package Resolver

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Logger"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Redis"
)

type RootServer struct {
	Address string
	Name    string
	Port    int
	TTL     int
}

var RootTrustAnchor *dns.DNSKEY

func loadRootServers() ([]RootServer, error) {
	configDir := "Confs"
	filePath := path.Join(configDir, "root.conf")

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open root.conf file at %s: %v", filePath, err)
	}
	defer file.Close()

	var rootServers []RootServer
	var currentServer RootServer

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "root-server-") {
			if currentServer.Address != "" {
				rootServers = append(rootServers, currentServer)
			}
			currentServer = RootServer{}
		} else if strings.HasPrefix(line, "address:") {
			currentServer.Address = strings.TrimSpace(strings.TrimPrefix(line, "address:"))
		} else if strings.HasPrefix(line, "name:") {
			currentServer.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		} else if strings.HasPrefix(line, "port:") {
			port := strings.TrimSpace(strings.TrimPrefix(line, "port:"))
			fmt.Sscanf(port, "%d", &currentServer.Port)
		} else if strings.HasPrefix(line, "ttl:") {
			ttl := strings.TrimSpace(strings.TrimPrefix(line, "ttl:"))
			fmt.Sscanf(ttl, "%d", &currentServer.TTL)
		}
	}

	if currentServer.Address != "" {
		rootServers = append(rootServers, currentServer)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read root.conf file at %s: %v", filePath, err)
	}

	return rootServers, nil
}

func loadRootTrustAnchor() (*dns.DNSKEY, error) {
	file, err := os.Open("./Confs/root.key")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ".") && strings.Contains(line, "DNSKEY") {
			if rr, err := dns.NewRR(line); err == nil {
				if key, ok := rr.(*dns.DNSKEY); ok {
					return key, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("DNSKEY not found in root.key")
}

func init() {
	key, err := loadRootTrustAnchor()
	if err != nil {
		Logger.LogError("Failed to load root trust anchor", err)
		os.Exit(1)
	}
	RootTrustAnchor = key
}

func RecursiveResolve(domain string, qtype uint16) ([]dns.RR, error) {
	rootServers, err := loadRootServers()
	if err != nil {
		return nil, fmt.Errorf("failed to load root servers: %v", err)
	}

	cacheKey := fmt.Sprintf("%s_%d", domain, qtype)
	cached, err := Redis.RedisClient.Get(Redis.Ctx, cacheKey).Result()
	if err == nil {
		var answerStrs []string
		if err := json.Unmarshal([]byte(cached), &answerStrs); err == nil {
			var answers []dns.RR
			for _, s := range answerStrs {
				if rr, err := dns.NewRR(s); err == nil {
					answers = append(answers, rr)
				}
			}
			Logger.LogApplication(fmt.Sprintf("✅ Cache hit for domain: %s, qtype: %d", domain, qtype))
			return answers, nil
		}
	}

	client := new(dns.Client)
	client.Net = "udp"
	client.Timeout = 5 * time.Second

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.SetEdns0(4096, true)

	for _, server := range rootServers {
		Logger.LogApplication(fmt.Sprintf("🔍 Querying root server: %s for domain: %s", server.Address, domain))
		resp, _, err := client.Exchange(msg, net.JoinHostPort(server.Address, fmt.Sprintf("%d", server.Port)))
		if err != nil {
			Logger.LogError(fmt.Sprintf("Failed to query server %s for domain %s", server.Address, domain), err)
			continue
		}
		answers, err := followChain(client, resp, qtype)
		if err == nil && len(answers) > 0 {
			var answerStrs []string
			for _, rr := range answers {
				answerStrs = append(answerStrs, rr.String())
			}
			if b, err := json.Marshal(answerStrs); err == nil {
				ttl := time.Duration(300) * time.Second
				if len(answers) > 0 {
					ttl = time.Duration(answers[0].Header().Ttl) * time.Second
				}
				Redis.RedisClient.Set(Redis.Ctx, cacheKey, b, ttl)
				Logger.LogApplication(fmt.Sprintf("✅ Successfully resolved domain: %s, qtype: %d", domain, qtype))
			}
			return answers, nil
		}
	}

	Logger.LogError(fmt.Sprintf("Failed to resolve domain: %s, qtype: %d", domain, qtype), fmt.Errorf("all root servers failed"))
	return nil, fmt.Errorf("failed to resolve domain: %s", domain)
}

func followChain(client *dns.Client, msg *dns.Msg, qtype uint16) ([]dns.RR, error) {
	if len(msg.Answer) > 0 {
		var answers []dns.RR
		for _, ans := range msg.Answer {
			answers = append(answers, ans)
			if cname, ok := ans.(*dns.CNAME); ok {
				Logger.LogApplication(fmt.Sprintf("🔄 CNAME found: %s, resolving target: %s", cname.Hdr.Name, cname.Target))
				cnameAnswers, err := RecursiveResolve(cname.Target, qtype)
				if err == nil {
					answers = append(answers, cnameAnswers...)
				}
			}
		}
		return answers, nil
	}

	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nsIP := resolveNSIP(ns.Ns)
			if nsIP == "" {
				continue
			}
			Logger.LogApplication(fmt.Sprintf("🔍 Querying NS: %s, IP: %s", ns.Ns, nsIP))
			query := new(dns.Msg)
			query.SetQuestion(msg.Question[0].Name, qtype)
			query.SetEdns0(4096, true)
			resp, _, err := client.Exchange(query, net.JoinHostPort(nsIP, "53"))
			if err != nil {
				Logger.LogError(fmt.Sprintf("Failed to query NS %s", ns.Ns), err)
				continue
			}
			if !validateDNSSEC(resp) {
				Logger.LogError("DNSSEC validation failed", fmt.Errorf("signature verification failed"))
				continue
			}
			Logger.LogApplication("✅ DNSSEC validation passed for zone: " + msg.Question[0].Name)
			return followChain(client, resp, qtype)
		}
	}

	return nil, fmt.Errorf("could not follow DNS chain")
}

func resolveNSIP(ns string) string {
	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(ns), dns.TypeA)
	msg.SetEdns0(4096, true)

	rootServers, err := loadRootServers()
	if err != nil {
		Logger.LogError("Failed to load root servers", err)
		return ""
	}

	for _, server := range rootServers {
		Logger.LogApplication(fmt.Sprintf("🔍 Querying A record for NS: %s from root server: %s", ns, server.Address))
		resp, _, err := client.Exchange(msg, net.JoinHostPort(server.Address, fmt.Sprintf("%d", server.Port)))
		if err != nil {
			Logger.LogError(fmt.Sprintf("Failed to query A record for NS: %s", ns), err)
			continue
		}
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				return a.A.String()
			}
		}
	}

	msg.SetQuestion(dns.Fqdn(ns), dns.TypeAAAA)
	for _, server := range rootServers {
		Logger.LogApplication(fmt.Sprintf("🔍 Querying AAAA record for NS: %s from root server: %s", ns, server.Address))
		resp, _, err := client.Exchange(msg, net.JoinHostPort(server.Address, fmt.Sprintf("%d", server.Port)))
		if err != nil {
			Logger.LogError(fmt.Sprintf("Failed to query AAAA record for NS: %s", ns), err)
			continue
		}
		for _, ans := range resp.Answer {
			if aaaa, ok := ans.(*dns.AAAA); ok {
				return aaaa.AAAA.String()
			}
		}
	}

	return ""
}

func validateDNSSEC(msg *dns.Msg) bool {
	var dnskeyRRs []dns.RR
	var rrsigRR *dns.RRSIG

	for _, rr := range msg.Answer {
		switch rr := rr.(type) {
		case *dns.DNSKEY:
			dnskeyRRs = append(dnskeyRRs, rr)
		case *dns.RRSIG:
			if rr.TypeCovered == dns.TypeDNSKEY {
				rrsigRR = rr
			}
		}
	}

	// Log the presence of key components
	if RootTrustAnchor == nil || rrsigRR == nil || len(dnskeyRRs) == 0 {
		Logger.LogApplication(fmt.Sprintf(
			"[DNSSEC] ❌ Incomplete validation set: RootKeyPresent=%v, RRSIGPresent=%v, DNSKEYCount=%d",
			RootTrustAnchor != nil, rrsigRR != nil, len(dnskeyRRs),
		))
		return false
	}

	for _, rr := range dnskeyRRs {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			Logger.LogApplication(fmt.Sprintf(
				"[DNSSEC] 🔍 Evaluating DNSKEY tag=%d against RRSIG tag=%d",
				dnskey.KeyTag(), rrsigRR.KeyTag,
			))

			if dnskey.KeyTag() == rrsigRR.KeyTag {
				err := rrsigRR.Verify(dnskey, dnskeyRRs)
				if err != nil {
					Logger.LogError(fmt.Sprintf(
						"[DNSSEC] ❌ Signature validation failed with DNSKEY tag=%d", dnskey.KeyTag(),
					), err)
					continue
				}

				Logger.LogApplication(fmt.Sprintf(
					"[DNSSEC] ✅ RRSIG validated successfully with DNSKEY tag=%d", dnskey.KeyTag(),
				))

				if dnskey.KeyTag() == RootTrustAnchor.KeyTag() && dnskey.PublicKey == RootTrustAnchor.PublicKey {
					Logger.LogApplication("[DNSSEC] 🔐 DNSSEC signature verified with trusted root anchor ✅")
					return true
				}

				Logger.LogApplication(fmt.Sprintf(
					"[DNSSEC] ⚠️ Signature OK, but DNSKEY tag=%d doesn't match Root Anchor tag=%d",
					dnskey.KeyTag(), RootTrustAnchor.KeyTag(),
				))
			}
		}
	}

	Logger.LogApplication("[DNSSEC] ❌ DNSSEC validation failed: no trusted DNSKEY matched.")
	return false
}

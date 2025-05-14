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
	"github.com/official-biswadeb941/HopZero-DNS/Modules/DNSSEC"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Logger"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Redis"
)

type RootServer struct {
	Address string
	Name    string
	Port    int
	TTL     int
}

var (
	RootTrustAnchor *dns.DNSKEY
	DNSSECEnforced  = true
)

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
		line := strings.TrimSpace(scanner.Text())
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
			fmt.Sscanf(strings.TrimPrefix(line, "port:"), "%d", &currentServer.Port)
		} else if strings.HasPrefix(line, "ttl:") {
			fmt.Sscanf(strings.TrimPrefix(line, "ttl:"), "%d", &currentServer.TTL)
		}
	}

	if currentServer.Address != "" {
		rootServers = append(rootServers, currentServer)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read root.conf file: %v", err)
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
		return nil, err
	}

	cacheKey := fmt.Sprintf("%s_%d", domain, qtype)
	if cached, err := Redis.RedisClient.Get(Redis.Ctx, cacheKey).Result(); err == nil {
		var answerStrs []string
		if err := json.Unmarshal([]byte(cached), &answerStrs); err == nil {
			var answers []dns.RR
			for _, s := range answerStrs {
				if rr, err := dns.NewRR(s); err == nil {
					answers = append(answers, rr)
				}
			}
			Logger.LogApplication(fmt.Sprintf("✅ Cache hit for domain: %s", domain))
			return answers, nil
		}
	}

	client := new(dns.Client)
	client.Net = "udp"
	client.Timeout = 5 * time.Second

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.SetEdns0(4096, DNSSECEnforced)

	for _, server := range rootServers {
		Logger.LogApplication(fmt.Sprintf("🔍 Querying root server: %s", server.Address))
		resp, _, err := client.Exchange(msg, net.JoinHostPort(server.Address, fmt.Sprintf("%d", server.Port)))
		if err != nil {
			Logger.LogError("Query failed", err)
			continue
		}
		answers, err := followChain(client, resp, qtype)
		if err == nil && len(answers) > 0 {
			var answerStrs []string
			for _, rr := range answers {
				answerStrs = append(answerStrs, rr.String())
			}
			if b, err := json.Marshal(answerStrs); err == nil {
				ttl := time.Duration(answers[0].Header().Ttl) * time.Second
				Redis.RedisClient.Set(Redis.Ctx, cacheKey, b, ttl)
			}
			Logger.LogApplication(fmt.Sprintf("✅ Successfully resolved: %s", domain))
			return answers, nil
		}
	}

	return nil, fmt.Errorf("failed to resolve domain: %s", domain)
}

func followChain(client *dns.Client, msg *dns.Msg, qtype uint16) ([]dns.RR, error) {
	if len(msg.Answer) > 0 {
		var answers []dns.RR
		for _, ans := range msg.Answer {
			answers = append(answers, ans)
			if cname, ok := ans.(*dns.CNAME); ok {
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
			query.SetEdns0(4096, DNSSECEnforced)
			resp, _, err := client.Exchange(query, net.JoinHostPort(nsIP, "53"))
			if err != nil {
				Logger.LogError("Failed to query NS", err)
				continue
			}
			if DNSSECEnforced && !DNSSEC.Validate(resp) {
				Logger.LogError("DNSSEC validation failed", fmt.Errorf("signature verification failed"))
				continue
			}
			Logger.LogApplication("✅ DNSSEC validated for: " + msg.Question[0].Name)
			return followChain(client, resp, qtype)
		}
	}
	return nil, fmt.Errorf("could not follow DNS chain")
}

func resolveNSIP(ns string) string {
	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(ns), dns.TypeA)
	msg.SetEdns0(4096, DNSSECEnforced)

	rootServers, err := loadRootServers()
	if err != nil {
		Logger.LogError("Failed to load root servers", err)
		return ""
	}

	for _, server := range rootServers {
		resp, _, err := client.Exchange(msg, net.JoinHostPort(server.Address, fmt.Sprintf("%d", server.Port)))
		if err != nil {
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
		resp, _, err := client.Exchange(msg, net.JoinHostPort(server.Address, fmt.Sprintf("%d", server.Port)))
		if err != nil {
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

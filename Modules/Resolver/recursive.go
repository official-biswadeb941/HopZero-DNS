package Resolver

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"time"
	"bufio"
	"strings"

	"github.com/miekg/dns"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Redis"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Logger"
)

type RootServer struct {
	Address string
	Name    string
	Port    int
	TTL     int
}

// Load root servers from root.conf file
func loadRootServers() ([]RootServer, error) {
	// Dynamically join the path to the root.conf file
	configDir := "Confs"  // This can be dynamic depending on where the configuration is located
	filePath := path.Join(configDir, "root.conf")
	
	// Open the root.conf file dynamically
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
			// If we find a new root-server entry, add the previous one (if any)
			if currentServer.Address != "" {
				rootServers = append(rootServers, currentServer)
			}
			// Reset for the new server
			currentServer = RootServer{}
		} else if strings.HasPrefix(line, "address:") {
			currentServer.Address = strings.TrimSpace(strings.TrimPrefix(line, "address:"))
		} else if strings.HasPrefix(line, "name:") {
			currentServer.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		} else if strings.HasPrefix(line, "port:") {
			port := strings.TrimSpace(strings.TrimPrefix(line, "port:"))
			// Convert port to integer
			fmt.Sscanf(port, "%d", &currentServer.Port)
		} else if strings.HasPrefix(line, "ttl:") {
			ttl := strings.TrimSpace(strings.TrimPrefix(line, "ttl:"))
			// Convert ttl to integer
			fmt.Sscanf(ttl, "%d", &currentServer.TTL)
		}
	}

	// Add the last root server entry to the list
	if currentServer.Address != "" {
		rootServers = append(rootServers, currentServer)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read root.conf file at %s: %v", filePath, err)
	}

	return rootServers, nil
}

// RecursiveResolve performs recursive DNS resolution using root servers from root.conf
func RecursiveResolve(domain string, qtype uint16) ([]dns.RR, error) {
	// Load root servers from the configuration file
	rootServers, err := loadRootServers()
	if err != nil {
		return nil, fmt.Errorf("failed to load root servers: %v", err)
	}

	cacheKey := fmt.Sprintf("%s_%d", domain, qtype)

	// Check cache first
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
			// Log cache hit
			Logger.LogApplication(fmt.Sprintf("✅ Cache hit for domain: %s, qtype: %d", domain, qtype))
			return answers, nil
		}
	}

	// Otherwise, start the recursive resolution
	client := new(dns.Client)
	client.Timeout = 5 * time.Second

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)

	// Use the dynamically loaded root servers
	for _, server := range rootServers {
		Logger.LogApplication(fmt.Sprintf("🔍 Querying root server: %s for domain: %s", server.Address, domain))
		resp, _, err := client.Exchange(msg, net.JoinHostPort(server.Address, fmt.Sprintf("%d", server.Port)))
		if err != nil {
			Logger.LogError(fmt.Sprintf("Failed to query server %s for domain %s", server.Address, domain), err)
			continue
		}
		answers, err := followChain(client, resp, qtype)
		if err == nil && len(answers) > 0 {
			// Convert RRs to string for serialization
			var answerStrs []string
			for _, rr := range answers {
				answerStrs = append(answerStrs, rr.String())
			}
			if b, err := json.Marshal(answerStrs); err == nil {
				ttl := time.Duration(300) * time.Second // Default TTL
				if len(answers) > 0 {
					ttl = time.Duration(answers[0].Header().Ttl) * time.Second
				}
				Redis.RedisClient.Set(Redis.Ctx, cacheKey, b, ttl)
				// Log successful resolution
				Logger.LogApplication(fmt.Sprintf("✅ Successfully resolved domain: %s, qtype: %d", domain, qtype))
			}
			return answers, nil
		}
	}

	// Log failure to resolve the domain
	Logger.LogError(fmt.Sprintf("Failed to resolve domain: %s, qtype: %d", domain, qtype), fmt.Errorf("all root servers failed"))
	return nil, fmt.Errorf("failed to resolve domain: %s", domain)
}

// followChain follows the chain of NS records to get to the final answer
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

	// Iterate over NS records and follow the chain
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nsIP := resolveNSIP(ns.Ns)
			if nsIP == "" {
				continue
			}
			Logger.LogApplication(fmt.Sprintf("🔍 Querying NS: %s, IP: %s", ns.Ns, nsIP))
			query := new(dns.Msg)
			query.SetQuestion(msg.Question[0].Name, qtype)
			resp, _, err := client.Exchange(query, net.JoinHostPort(nsIP, "53"))
			if err != nil {
				Logger.LogError(fmt.Sprintf("Failed to query NS %s", ns.Ns), err)
				continue
			}
			return followChain(client, resp, qtype)
		}
	}

	return nil, fmt.Errorf("could not follow DNS chain")
}

// resolveNSIP resolves an NS record's IP (both A and AAAA records) for DNS queries
func resolveNSIP(ns string) string {
	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(ns), dns.TypeA)

	// Look up A record for NS (IPv4)
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

	// Fallback to AAAA record for NS (IPv6)
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

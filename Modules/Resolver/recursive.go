package Resolver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Logger"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/QUIC"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Redis"
	"github.com/quic-go/quic-go"
)

type RootServer struct {
	Address string
	Name    string
	Port    int
	TTL     int
}

// Load root servers from root.conf file
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
		return nil, fmt.Errorf("failed to read root.conf file at %s: %v", filePath, err)
	}

	return rootServers, nil
}

// RecursiveResolve performs recursive DNS resolution using QUIC
func RecursiveResolve(domain string, qtype uint16) ([]dns.RR, error) {
	rootServers, err := loadRootServers()
	if err != nil {
		return nil, fmt.Errorf("failed to load root servers: %v", err)
	}

	cacheKey := fmt.Sprintf("%s_%d", domain, qtype)

	// Cache check
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

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)

	tlsConf, err := QUIC.LoadTLSConfig()
	if err != nil {
		Logger.LogError("Failed to load TLS config for QUIC", err)
		return nil, err
	}

	// Query over QUIC
	for _, server := range rootServers {
		addr := net.JoinHostPort(server.Address, fmt.Sprintf("%d", server.Port))
		Logger.LogApplication(fmt.Sprintf("🔍 Querying root server via QUIC: %s", addr))

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		quicConn, err := quic.DialAddr(ctx, addr, tlsConf, nil)
		if err != nil {
			Logger.LogError(fmt.Sprintf("❌ QUIC dial error to %s", addr), err)
			continue
		}

		stream, err := quicConn.OpenStreamSync(ctx)
		if err != nil {
			Logger.LogError(fmt.Sprintf("❌ Failed to open QUIC stream to %s", addr), err)
			continue
		}

		packed, err := msg.Pack()
		if err != nil {
			Logger.LogError("❌ Failed to pack DNS query", err)
			continue
		}

		if _, err := stream.Write(packed); err != nil {
			Logger.LogError(fmt.Sprintf("❌ Failed to write to QUIC stream for %s", domain), err)
			continue
		}

		buf := make([]byte, 65535)
		n, err := stream.Read(buf)
		if err != nil {
			Logger.LogError(fmt.Sprintf("❌ Failed to read from QUIC stream for %s", domain), err)
			continue
		}

		resp := new(dns.Msg)
		if err := resp.Unpack(buf[:n]); err != nil {
			Logger.LogError("❌ Failed to unpack DNS response", err)
			continue
		}

		answers, err := followChain(resp, qtype)
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
			}
			Logger.LogApplication(fmt.Sprintf("✅ Successfully resolved via QUIC: %s", domain))
			return answers, nil
		}
	}

	Logger.LogError(fmt.Sprintf("Failed to resolve via QUIC: %s", domain), fmt.Errorf("all root servers failed"))
	return nil, fmt.Errorf("failed to resolve domain: %s", domain)
}

// followChain recursively follows DNS delegation
func followChain(msg *dns.Msg, qtype uint16) ([]dns.RR, error) {
	if len(msg.Answer) > 0 {
		var answers []dns.RR
		for _, ans := range msg.Answer {
			answers = append(answers, ans)
			if cname, ok := ans.(*dns.CNAME); ok {
				Logger.LogApplication(fmt.Sprintf("🔄 CNAME found: %s -> %s", cname.Hdr.Name, cname.Target))
				cnameAnswers, err := RecursiveResolve(cname.Target, qtype)
				if err == nil {
					answers = append(answers, cnameAnswers...)
				}
			}
		}
		return answers, nil
	}

	// If only NS records, try resolving those
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nsIP := resolveNSIP(ns.Ns)
			if nsIP == "" {
				continue
			}
			Logger.LogApplication(fmt.Sprintf("🔍 Querying NS IP: %s (%s)", ns.Ns, nsIP))
			client := new(dns.Client)
			query := new(dns.Msg)
			query.SetQuestion(msg.Question[0].Name, qtype)
			resp, _, err := client.Exchange(query, net.JoinHostPort(nsIP, "53"))
			if err != nil {
				Logger.LogError(fmt.Sprintf("Failed to query NS: %s", ns.Ns), err)
				continue
			}
			return followChain(resp, qtype)
		}
	}

	return nil, fmt.Errorf("could not follow DNS chain")
}

// resolveNSIP resolves an NS name to an IP using root servers
func resolveNSIP(ns string) string {
	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(ns), dns.TypeA)

	rootServers, err := loadRootServers()
	if err != nil {
		Logger.LogError("Failed to load root servers for NS IP lookup", err)
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

package DNSSEC

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Logger"
	RedisModule "github.com/official-biswadeb941/HopZero-DNS/Modules/Redis"
)

var (
	RootTrustAnchor *dns.DNSKEY
	dnssecLogger    *Logger.ModuleLogger
	DNSSECEnforced  = true // 🔐 Enforce DNSSEC validation strictly
)

type CachedDNSKEY struct {
	RR       string    `json:"rr"`
	CachedAt time.Time `json:"cached_at"`
	TTL      uint32    `json:"ttl"`
}

func init() {
	var err error
	dnssecLogger, err = Logger.GetLogger("DNSSEC_Logs.log")
	if err != nil {
		// Silent fallback — if logger fails, no console fallback
		return
	}
	dnssecLogger.Info("DNSSEC logger initialized successfully.")
}

func LoadRootTrustAnchor(filename string) ([]*dns.DNSKEY, error) {
	file, err := os.Open(filename)
	if err != nil {
		if dnssecLogger != nil {
			dnssecLogger.Error(fmt.Sprintf("Could not open root trust anchor file: %s", filename))
		}
		return nil, err
	}
	defer file.Close()

	var keys []*dns.DNSKEY
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ".") && strings.Contains(line, "DNSKEY") {
			rr, err := dns.NewRR(line)
			if err != nil {
				if dnssecLogger != nil {
					dnssecLogger.Error(fmt.Sprintf("Failed to parse DNSKEY from line: %s", line))
				}
				return nil, fmt.Errorf("failed to parse DNSKEY: %v", err)
			}
			if key, ok := rr.(*dns.DNSKEY); ok {
				keys = append(keys, key)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		if dnssecLogger != nil {
			dnssecLogger.Error("Scanner error while loading root trust anchor")
		}
		return nil, fmt.Errorf("failed to scan root.key: %v", err)
	}

	if len(keys) == 0 {
		if dnssecLogger != nil {
			dnssecLogger.Warn(fmt.Sprintf("No valid DNSKEYs found in %s", filename))
		}
		return nil, fmt.Errorf("no valid DNSKEYs found in %s", filename)
	}

	if dnssecLogger != nil {
		dnssecLogger.Info(fmt.Sprintf("Loaded %d DNSKEY(s) from %s", len(keys), filename))
	}
	return keys, nil
}

func Validate(msg *dns.Msg) bool {
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

	if RootTrustAnchor == nil || rrsigRR == nil || len(dnskeyRRs) == 0 {
		if dnssecLogger != nil {
			dnssecLogger.Error(fmt.Sprintf("Incomplete validation set: RootKeyPresent=%v, RRSIGPresent=%v, DNSKEYCount=%d", RootTrustAnchor != nil, rrsigRR != nil, len(dnskeyRRs)))
		}
		return !DNSSECEnforced
	}

	zoneName := msg.Question[0].Name
	cacheKey := fmt.Sprintf("dnskey:%s", zoneName)

	cachedVal, err := RedisModule.RedisClient.Get(RedisModule.Ctx, cacheKey).Result()
	if err == nil {
		var cached CachedDNSKEY
		err := json.Unmarshal([]byte(cachedVal), &cached)
		if err == nil {
			rr, err := dns.NewRR(cached.RR)
			if err == nil {
				dnskey, ok := rr.(*dns.DNSKEY)
				if ok {
					if dnssecLogger != nil {
						dnssecLogger.Info("Using cached DNSKEY from Redis.")
					}
					if dnskey.KeyTag() == rrsigRR.KeyTag {
						if err := rrsigRR.Verify(dnskey, dnskeyRRs); err == nil {
							if dnssecLogger != nil {
								dnssecLogger.Info("DNSSEC verified with cached key ✅")
							}
							return true
						}
					}
				}
			}
		}
	}

	for _, rr := range dnskeyRRs {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			if dnssecLogger != nil {
				dnssecLogger.Info(fmt.Sprintf("Evaluating DNSKEY tag=%d against RRSIG tag=%d", dnskey.KeyTag(), rrsigRR.KeyTag))
			}
			if dnskey.KeyTag() == rrsigRR.KeyTag {
				if err := rrsigRR.Verify(dnskey, dnskeyRRs); err == nil {
					if dnssecLogger != nil {
						dnssecLogger.Info(fmt.Sprintf("RRSIG validated with DNSKEY tag=%d", dnskey.KeyTag()))
					}

					rrStr := dnskey.String()
					jsonVal, _ := json.Marshal(CachedDNSKEY{
						RR:       rrStr,
						CachedAt: time.Now(),
						TTL:      dnskey.Hdr.Ttl,
					})
					err := RedisModule.RedisClient.Set(RedisModule.Ctx, cacheKey, jsonVal, time.Duration(dnskey.Hdr.Ttl)*time.Second).Err()
					if err != nil && dnssecLogger != nil {
						dnssecLogger.Warn(fmt.Sprintf("Failed to cache DNSKEY in Redis: %v", err))
					} else if dnssecLogger != nil {
						dnssecLogger.Info("DNSKEY cached in Redis.")
					}

					if dnskey.KeyTag() == RootTrustAnchor.KeyTag() && dnskey.PublicKey == RootTrustAnchor.PublicKey {
						if dnssecLogger != nil {
							dnssecLogger.Info("DNSSEC signature verified with trusted root anchor ✅")
						}
						return true
					}
					if dnssecLogger != nil {
						dnssecLogger.Warn(fmt.Sprintf("Signature OK, but DNSKEY tag=%d doesn't match Root Anchor tag=%d", dnskey.KeyTag(), RootTrustAnchor.KeyTag()))
					}
				}
			}
		}
	}

	if dnssecLogger != nil {
		dnssecLogger.Error("DNSSEC validation failed: no trusted DNSKEY matched.")
	}

	if DNSSECEnforced {
		if dnssecLogger != nil {
			dnssecLogger.Error("⚠️ Enforcement active: rejecting unsigned/unverified DNS response.")
		}
		return false
	}

	if dnssecLogger != nil {
		dnssecLogger.Warn("DNSSEC verification failed, but continuing due to enforcement disabled.")
	}
	return true
}

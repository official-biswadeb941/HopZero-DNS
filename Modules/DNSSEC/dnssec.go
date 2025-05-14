package DNSSEC

import (
	"fmt"
	"strings"
	"bufio"
	"os"

	"github.com/miekg/dns"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Logger"
)

var RootTrustAnchor *dns.DNSKEY

func LoadRootTrustAnchor(filename string) ([]*dns.DNSKEY, error) {
	file, err := os.Open(filename)
	if err != nil {
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
				return nil, fmt.Errorf("failed to parse DNSKEY: %v", err)
			}
			if key, ok := rr.(*dns.DNSKEY); ok {
				keys = append(keys, key)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan root.key: %v", err)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid DNSKEYs found in %s", filename)
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
				if err := rrsigRR.Verify(dnskey, dnskeyRRs); err != nil {
					Logger.LogError(fmt.Sprintf("[DNSSEC] ❌ Signature validation failed with DNSKEY tag=%d", dnskey.KeyTag()), err)
					continue
				}
				Logger.LogApplication(fmt.Sprintf("[DNSSEC] ✅ RRSIG validated with DNSKEY tag=%d", dnskey.KeyTag()))

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

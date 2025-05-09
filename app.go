package main

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/official-biswadeb941/HopZero-DNS/loader"
)

func main() {
	loader.InitRedis()

	records, err := resolver.RecursiveResolve("example.com", dns.TypeA)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	for _, rec := range records {
		fmt.Println(rec)
	}
}

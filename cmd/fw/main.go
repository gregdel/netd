package main

import (
	"fmt"
	"net"
	"os"

	"github.com/google/nftables/expr"
	"github.com/gregdel/netd/lib/fw"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}

func run() error {
	rules := []*fw.Rule{
		&fw.Rule{
			Chain: fw.ChainPreroutingDNAT,
			Match: &fw.Match{
				Protocol: 17,
				DestPort: 5006,
			},
			Actions: []fw.Action{
				&fw.Limit{
					LimitType: expr.LimitTypePktBytes,
					Rate:      10000,
					Unit:      expr.LimitTimeSecond,
				},
			},
		},
		&fw.Rule{
			Chain: fw.ChainPreroutingDNAT,
			Match: &fw.Match{
				SrcIP: &net.IPNet{
					IP:   net.IPv4(109, 190, 254, 33),
					Mask: net.CIDRMask(32, 32),
				},
				Protocol: 6,
				DestPort: 8080,
			},
			Actions: []fw.Action{
				&fw.Limit{
					LimitType: expr.LimitTypePkts,
					Rate:      10,
					Unit:      expr.LimitTimeWeek,
				},
				&fw.DNAT{
					IP:   net.IPv4(10, 100, 200, 42).To4(),
					Port: 28828,
				},
			},
		},
		&fw.Rule{
			Chain: fw.ChainPreroutingDNAT,
			Actions: []fw.Action{
				&fw.DNAT{
					IP: net.IPv4(192, 168, 101, 12).To4(),
				},
			},
		},
	}

	firewall, _ := fw.New()
	return firewall.WriteRules(rules)
}

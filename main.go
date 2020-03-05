package main

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/google/nftables"
	"github.com/gregdel/nft/expr"
)

func createFilterTable(conn *nftables.Conn) {
	filterTable := &nftables.Table{
		Name:   "filter",
		Family: nftables.TableFamilyINet,
	}

	policyAccept := nftables.ChainPolicyAccept

	preroutingChain := &nftables.Chain{
		Name:     "input",
		Table:    filterTable,
		Type:     nftables.ChainTypeFilter,
		Policy:   &policyAccept,
		Priority: nftables.ChainPriorityFilter,
		Hooknum:  nftables.ChainHookInput,
	}

	forwardChain := &nftables.Chain{
		Name:     "forward",
		Table:    filterTable,
		Type:     nftables.ChainTypeFilter,
		Policy:   &policyAccept,
		Priority: nftables.ChainPriorityFilter,
		Hooknum:  nftables.ChainHookForward,
	}

	outputChain := &nftables.Chain{
		Name:     "output",
		Table:    filterTable,
		Type:     nftables.ChainTypeFilter,
		Policy:   &policyAccept,
		Priority: nftables.ChainPriorityFilter,
		Hooknum:  nftables.ChainHookOutput,
	}

	conn.AddTable(filterTable)
	conn.AddChain(preroutingChain)
	conn.AddChain(forwardChain)
	conn.AddChain(outputChain)
}

func createNatTable(conn *nftables.Conn) {
	natTable := &nftables.Table{
		Name:   "nat",
		Family: nftables.TableFamilyIPv4,
	}

	policyAccept := nftables.ChainPolicyAccept

	preroutingChain := &nftables.Chain{
		Name:     "prerouting",
		Table:    natTable,
		Type:     nftables.ChainTypeNAT,
		Policy:   &policyAccept,
		Priority: nftables.ChainPriorityNATDest,
		Hooknum:  nftables.ChainHookPrerouting,
	}

	postroutingChain := &nftables.Chain{
		Name:     "postrouting",
		Table:    natTable,
		Type:     nftables.ChainTypeNAT,
		Policy:   &policyAccept,
		Priority: nftables.ChainPriorityNATSource,
		Hooknum:  nftables.ChainHookPostrouting,
	}

	gscanSet := &nftables.Set{
		Table:    natTable,
		Name:     "gscan",
		Interval: true,
		KeyType:  nftables.TypeIPAddr,
	}

	gscanSetValues := []nftables.SetElement{
		{Key: net.IPv4(92, 222, 184, 0).To4()},
		{Key: net.IPv4(92, 222, 186, 255).To4(), IntervalEnd: true},
		{Key: net.IPv4(167, 114, 37, 0).To4()},
		{Key: net.IPv4(167, 114, 37, 255).To4(), IntervalEnd: true},
	}

	gscanRule := &nftables.Rule{
		Table: natTable,
		Chain: preroutingChain,
		Exprs: expr.Merge(
			expr.L4Proto(expr.L4ProtoICMP),
			expr.ICMPType(expr.ICMPTypeEchoRequest),
			expr.LookupNamedSet("gscan"),
			expr.VerdictReturn(),
		),
	}

	conn.AddTable(natTable)
	conn.AddChain(preroutingChain)
	conn.AddChain(postroutingChain)
	conn.AddSet(gscanSet, gscanSetValues)
	conn.AddRule(gscanRule)
}

func main() {
	fmt.Println("Starting netd...")
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
	fmt.Println("All done !")
}

func run() error {
	netnsPath := "/var/run/netns/netd"
	fd, err := syscall.Open(netnsPath, syscall.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	nft := &nftables.Conn{NetNS: fd}

	nft.FlushRuleset()
	createFilterTable(nft)
	createNatTable(nft)
	return nft.Flush()
}

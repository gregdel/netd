package netd

import (
	"fmt"

	"github.com/gregdel/netd/lib/fw"
)

// Netd represents the network daemon parameters
type Netd struct {
	netnsPath string
	firewall  *fw.Firewall
}

// New returns a new netd struct
func New(netnsPath string) *Netd {
	return &Netd{
		netnsPath: netnsPath,
	}
}

// Init initializes netd
func (n *Netd) Init() error {
	firewall, err := fw.NewFromNetnsPath(n.netnsPath)
	if err != nil {
		return err
	}

	if err := firewall.Init(); err != nil {
		return err
	}

	n.firewall = firewall

	return nil
}

// ReloadFirewall reload the firewall rules
func (n *Netd) ReloadFirewall() error {
	fmt.Println("reloading")
	defer fmt.Println("reloaded")

	rules, err := n.firewall.ReadRules()
	if err != nil {
		return err
	}

	for _, r := range rules {
		err := n.firewall.AddRule(r)
		if err != nil {
			return err
		}
	}

	err = n.firewall.Commit()
	if err != nil {
		return err
	}

	n.firewall.ShowRules()

	return nil
}

// Run runs netd
func (n *Netd) Run() error {
	// TODO watch for new files and load them
	return nil
}

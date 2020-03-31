package netd

import (
	"fmt"

	"github.com/gregdel/netd/lib/fw"
)

// Config represents the netd configuration options
type Config struct {
	FirewallConfig *fw.Config
}

// Netd represents the network daemon parameters
type Netd struct {
	config   *Config
	firewall *fw.Firewall
}

// New returns a new netd struct
func New(config *Config) *Netd {
	if config == nil {
		config = &Config{}
	}

	return &Netd{
		config: config,
	}
}

// Init initializes netd
func (n *Netd) Init() error {
	firewall, err := fw.New(n.config.FirewallConfig)
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

	n.firewall.Reset()

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

	return nil
}

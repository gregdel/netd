package fw

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/google/nftables"
)

const (
	// DefaultRuntimeDirectory is the default runtime directory of netd.
	DefaultRuntimeDirectory = "/run/netd"
	// DefaultRuleFile is the default file containing the rules
	DefaultRuleFile = "fw_rules.json"
)

// Custom error
var (
	ErrMissingNetlinkConn = errors.New("fw: missing netlink conn")
	ErrChainNotFound      = errors.New("fw: chain not found")
	ErrMissingRuntimeDir  = errors.New("fw: missing runtime directory")
)

// UserChain representing the user writeable chains
type UserChain string

// UserChains values
const (
	ChainPreroutingDNAT UserChain = "prerouting_dnat"
)

// Config represents the firewall configuration options
type Config struct {
	NetnsPath        string
	RuntimeDirectory string
	RulesFilePath    string

	rulesPath string
}

// Firewall represents the firewall
type Firewall struct {
	config *Config
	nft    *nftables.Conn
	chains map[UserChain]*nftables.Chain
}

// new returns a new firewall
func new(c *Config, conn *nftables.Conn) (*Firewall, error) {
	if c == nil {
		c = &Config{}
	}

	if c.RuntimeDirectory == "" {
		c.RuntimeDirectory = DefaultRuntimeDirectory
	}

	if c.RulesFilePath == "" {
		c.RulesFilePath = DefaultRuleFile
	}

	c.rulesPath = filepath.Join(c.RuntimeDirectory, c.RulesFilePath)

	return &Firewall{
		config: c,
		nft:    conn,
		chains: map[UserChain]*nftables.Chain{
			ChainPreroutingDNAT: nil,
		},
	}, nil
}

// New returns a new firewall
func New(c *Config) (*Firewall, error) {
	fw, err := new(c, &nftables.Conn{})
	if err != nil {
		return nil, err
	}

	if fw.config.NetnsPath != "" {
		fd, err := syscall.Open(fw.config.NetnsPath, syscall.O_RDONLY, 0)
		if err != nil {
			return nil, err
		}
		// TODO: check how to close this properly (if needed)
		// defer syscall.Close(fd)
		fw.nft = &nftables.Conn{NetNS: fd}
	}

	return fw, nil
}

// Init fetches the current firewall state
func (f *Firewall) Init() error {
	if f.nft == nil {
		return ErrMissingNetlinkConn
	}

	// Check if the runtime directory exists
	stat, err := os.Stat(f.config.RuntimeDirectory)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrMissingRuntimeDir
		}

		return err
	}

	if !stat.IsDir() {
		return ErrMissingRuntimeDir
	}

	chains, err := f.nft.ListChains()
	if err != nil {
		return err
	}

	for _, c := range chains {
		_, ok := f.chains[UserChain(c.Name)]
		if ok {
			f.chains[UserChain(c.Name)] = c
		}
	}

	return nil
}

// Reset flushes the rules from the registered chains
func (f *Firewall) Reset() {
	for _, c := range f.chains {
		f.nft.FlushChain(c)
	}
}

// Commit commits the firewall rules
func (f *Firewall) Commit() error {
	return f.nft.Flush()
}

// AddRule adds a rule in the firewall
func (f *Firewall) AddRule(rule *Rule) error {
	c, ok := f.chains[rule.Chain]
	if !ok {
		return ErrChainNotFound
	}

	if err := rule.Validate(); err != nil {
		return err
	}

	f.nft.AddRule(&nftables.Rule{
		Table: c.Table,
		Chain: c,
		Exprs: rule.Expr(),
	})

	return nil
}

// ReadRules reads the rules from a file
func (f *Firewall) ReadRules() ([]*Rule, error) {
	file, err := os.Open(f.config.rulesPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	rules := []*Rule{}
	return rules, json.NewDecoder(file).Decode(&rules)
}

// WriteRules writes the rules to a file
func (f *Firewall) WriteRules(rules []*Rule) error {
	file, err := os.Create(f.config.rulesPath)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(&rules)
}

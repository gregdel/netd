package fw

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/google/nftables"
	"github.com/kr/pretty"
)

// DefaultRuntimePath is the default runtime path
const DefaultRuntimePath = "/tmp/netd/fw"

// Custom error
var (
	ErrMissingNetlinkConn = errors.New("fw: missing netlink conn")
	ErrChainNotFound      = errors.New("fw: chain not found")
)

// UserChain representing the user writeable chains
type UserChain string

// UserChains values
const (
	ChainPreroutingDNAT UserChain = "prerouting_dnat"
)

// Firewall represents the firewall
type Firewall struct {
	nft    *nftables.Conn
	chains map[UserChain]*nftables.Chain
}

// new returns a new firewall
func new(conn *nftables.Conn) (*Firewall, error) {
	return &Firewall{
		nft: conn,
		chains: map[UserChain]*nftables.Chain{
			ChainPreroutingDNAT: nil,
		},
	}, nil
}

// New returns a new firewall
func New() (*Firewall, error) {
	return new(&nftables.Conn{})
}

// NewFromNetnsPath returns a new firewall from a netns path
func NewFromNetnsPath(path string) (*Firewall, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	// TODO: check how to close this properly (if needed)
	// defer syscall.Close(fd)
	conn := &nftables.Conn{NetNS: fd}
	return new(conn)
}

// Init fetches the current firewall state
func (f *Firewall) Init() error {
	if f.nft == nil {
		return ErrMissingNetlinkConn
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

// ShowRules needs to be removed TODO: remove this sub
func (f *Firewall) ShowRules() {
	c, ok := f.chains[ChainPreroutingDNAT]
	if !ok {
		fmt.Println("missing chains")
		return
	}

	rules, err := f.nft.GetRule(c.Table, c)
	if err != nil {
		fmt.Println("error: ", err)
		return
	}
	pretty.Println(rules)
}

// ReadRules reads the rules from a file
func (f *Firewall) ReadRules() ([]*Rule, error) {
	file, err := os.Open("/tmp/netd/fw_rules.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	rules := []*Rule{}
	return rules, json.NewDecoder(file).Decode(&rules)
}

// WriteRules writes the rules to a file
func (f *Firewall) WriteRules(rules []*Rule) error {
	file, err := os.Create("/tmp/netd/fw_rules.json")
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(&rules)
}

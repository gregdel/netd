package fw

import (
	"github.com/google/nftables/expr"
	nft "github.com/gregdel/nft/expr"
)

// Counter represents a Counter rule
type Counter struct {
	Bytes   uint64 `json:"bytes,omitempty"`
	Packets uint64 `json:"packets,omitempty"`
}

// Type implements the Action interface
func (c *Counter) Type() string { return "counter" }

// Expr implements the Action interface
func (c *Counter) Expr() []expr.Any {
	return nft.Counter(c.Bytes, c.Packets)
}

// Validate implements the Action interface
func (c *Counter) Validate() error {
	return nil
}

// IsTerminal implements the Action interface
func (c *Counter) IsTerminal() bool { return false }

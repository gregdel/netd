package fw

import (
	"github.com/google/nftables/expr"
	nft "github.com/gregdel/nft/expr"
)

// Drop represents an Drop rule
type Drop struct{}

// Type implements the Action interface
func (a *Drop) Type() string { return "drop" }

// Expr implements the Action interface
func (a *Drop) Expr() []expr.Any {
	return nft.VerdictDrop()
}

// Validate implements the Action interface
func (a *Drop) Validate() error {
	return nil
}

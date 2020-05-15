package fw

import (
	"github.com/google/nftables/expr"
	nft "github.com/gregdel/nft/expr"
)

// Accept represents an Accept rule
type Accept struct{}

// Type implements the Action interface
func (a *Accept) Type() string { return "accept" }

// Expr implements the Action interface
func (a *Accept) Expr() []expr.Any {
	return nft.VerdictAccept()
}

// Validate implements the Action interface
func (a *Accept) Validate() error {
	return nil
}

package fw

import (
	"github.com/google/nftables/expr"
)

// Rule represents a firewall rule
type Rule struct {
	Chain   UserChain `json:"chain,omitempty"`
	Match   *Match    `json:"match,omitempty"`
	Actions Actions   `json:"actions,omitempty"`
}

// Expr represents all the required expression for a rule
func (r *Rule) Expr() []expr.Any {
	expr := []expr.Any{}

	if r.Match != nil {
		expr = append(expr, r.Match.Expr()...)
	}

	for _, action := range r.Actions {
		expr = append(expr, action.Expr()...)
	}

	return expr
}

// Validate the rules
func (r *Rule) Validate() error {
	if err := r.Match.Validate(); err != nil {
		return err
	}

	for _, action := range r.Actions {
		if err := action.Validate(); err != nil {
			return err
		}
	}

	return nil
}

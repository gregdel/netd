package fw

import (
	"errors"

	"github.com/google/nftables/expr"
)

// Custom errors
var (
	ErrMissingRuleActions          = errors.New("fw: missing rule actions")
	ErrStuffAfterTerminalStatement = errors.New("fw: statement after terminal statement has no effect")
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
	if len(r.Actions) == 0 {
		return ErrMissingRuleActions
	}

	terminated := false

	for _, action := range r.Actions {
		if terminated {
			return ErrStuffAfterTerminalStatement
		}
		if err := action.Validate(); err != nil {
			return err
		}
		if action.IsTerminal() {
			terminated = true
		}
	}

	if r.Match == nil {
		return nil
	}

	return r.Match.Validate()
}

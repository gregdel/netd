package fw

import (
	"errors"

	"github.com/google/nftables/expr"
	nft "github.com/gregdel/nft/expr"
)

// Custom errors
var (
	ErrMissingLimitRate = errors.New("missing limit rate")
)

// Limit represents a limit
type Limit struct {
	LimitType expr.LimitType `json:"limit_type,omitempty"`
	Rate      uint64         `json:"rate,omitempty"`
	Over      bool           `json:"over,omitempty"`
	Unit      expr.LimitTime `json:"unit,omitempty"`
	Burst     uint32         `json:"burst,omitempty"`
}

// Type implements the Action interface
func (l *Limit) Type() string { return "limit" }

// Expr implements the Action interface
func (l *Limit) Expr() []expr.Any {
	return nft.Limit(l.LimitType, l.Rate, l.Unit, l.Over, l.Burst)
}

// Validate implements the Action interface
func (l *Limit) Validate() error {
	if l.Rate == 0 {
		return ErrMissingLimitRate
	}

	return nil
}

// IsTerminal implements the Action interface
func (l *Limit) IsTerminal() bool { return false }

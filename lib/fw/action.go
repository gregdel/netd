package fw

import (
	"github.com/google/nftables/expr"
)

// Action represents an actions in case of a match
type Action interface {
	// json.Marshaler
	// json.Unmarshaler

	Type() string
	Expr() []expr.Any
	Validate() error
}

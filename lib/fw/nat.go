package fw

import (
	"errors"
	"net"

	"github.com/google/nftables/expr"
	nft "github.com/gregdel/nft/expr"
)

// Custom errors
var (
	ErrDNATMissingDestination = errors.New("fw: missing DNAT destination")
)

// DNAT represents a DNAT
type DNAT struct {
	IP   net.IP `json:"ip"`
	Port uint16 `json:"port"`
}

// Type implements the Action interface
func (d *DNAT) Type() string { return "dnat" }

// Expr implements the Action interface
func (d *DNAT) Expr() []expr.Any {
	if d.Port != 0 {
		return nft.DNATIPPort(d.IP, d.Port)
	}
	return nft.DNATIP(d.IP)
}

// Validate implements the Action interface
func (d *DNAT) Validate() error {
	if d.IP == nil {
		return ErrDNATMissingDestination
	}

	return nil
}

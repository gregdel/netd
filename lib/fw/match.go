package fw

import (
	"net"

	"github.com/google/nftables/expr"
	nft "github.com/gregdel/nft/expr"
)

// Match represents the matching of a packet
type Match struct {
	SrcIP    *net.IPNet `json:"src_ip,omitempty"`
	SrcPort  uint16     `json:"src_port,omitempty"`
	DestIP   *net.IPNet `json:"dest_ip,omitempty"`
	DestPort uint16     `json:"dest_port,omitempty"`
	Protocol uint16     `json:"protocol,omitempty"`
}

// Type implements the Action interface
func (m *Match) Type() string { return "match" }

// Validate implements the Action interface
func (m *Match) Validate() error {
	return nil
}

// Expr implements the Action interface
func (m *Match) Expr() []expr.Any {
	expressions := []expr.Any{}

	if m.SrcIP != nil {
		expressions = append(expressions, nft.SrcIP(m.SrcIP)...)
	}

	if m.DestIP != nil {
		expressions = append(expressions, nft.DestIP(m.DestIP)...)
	}

	if m.Protocol == 0 {
		return expressions
	}
	expressions = append(expressions, nft.L4Proto(nft.L4ProtoValue(m.Protocol))...)

	if m.DestPort != 0 {
		expressions = append(expressions, nft.DPort(m.DestPort)...)
	}

	if m.SrcPort != 0 {
		expressions = append(expressions, nft.SPort(m.SrcPort)...)
	}

	return expressions
}

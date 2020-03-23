package fw

import (
	"encoding/json"
	"fmt"

	"github.com/google/nftables/expr"
)

// Rule represents a firewall rule
type Rule struct {
	Chain   UserChain
	Match   *Match
	Actions []Action
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

// MarshalJSON implements the Mashaler interface
func (r *Rule) MarshalJSON() ([]byte, error) {
	type actionType struct {
		Action `json:"params"`
		Type   string `json:"type"`
	}

	aux := struct {
		Chain   UserChain    `json:"chain"`
		Match   *Match       `json:"match"`
		Actions []actionType `json:"actions"`
	}{
		Chain:   r.Chain,
		Match:   r.Match,
		Actions: []actionType{},
	}

	for _, a := range r.Actions {
		aux.Actions = append(aux.Actions, actionType{
			Action: a,
			Type:   a.Type(),
		})
	}

	return json.Marshal(aux)
}

// UnmarshalJSON implements the Unmashaler interface
func (r *Rule) UnmarshalJSON(data []byte) error {
	type actionType struct {
		Params json.RawMessage `json:"params"`
		Type   string          `json:"type"`
	}

	aux := struct {
		Chain   UserChain    `json:"chain"`
		Match   *Match       `json:"match"`
		Actions []actionType `json:"actions"`
	}{}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	r.Chain = aux.Chain
	r.Match = aux.Match
	r.Actions = []Action{}

	for _, a := range aux.Actions {
		var action Action
		switch a.Type {
		case "dnat":
			action = &DNAT{}
		case "limit":
			action = &Limit{}
		default:
			return fmt.Errorf("unhandle action type %s", a.Type)
		}

		if err := json.Unmarshal(a.Params, action); err != nil {
			return err
		}

		r.Actions = append(r.Actions, action)
	}

	return nil
}

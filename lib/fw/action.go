package fw

import (
	"encoding/json"
	"fmt"

	"github.com/google/nftables/expr"
)

// Action represents an actions in case of a match
type Action interface {
	Type() string
	Expr() []expr.Any
	Validate() error
}

// Actions defines a set of actions
type Actions []Action

// MarshalJSON implements the Mashaler interface
func (as Actions) MarshalJSON() ([]byte, error) {
	type aux struct {
		Action `json:"params"`
		Type   string `json:"type"`
	}

	actions := []aux{}

	for _, a := range as {
		actions = append(actions, aux{
			Action: a,
			Type:   a.Type(),
		})
	}

	return json.Marshal(actions)
}

// UnmarshalJSON implements the Unmashaler interface
func (as *Actions) UnmarshalJSON(data []byte) error {
	*as = []Action{}

	type aux struct {
		Params json.RawMessage `json:"params"`
		Type   string          `json:"type"`
	}

	actions := []aux{}
	if err := json.Unmarshal(data, &actions); err != nil {
		return err
	}

	for _, a := range actions {
		var action Action
		switch a.Type {
		case "dnat":
			action = &DNAT{}
		case "limit":
			action = &Limit{}
		case "drop":
			action = &Drop{}
		case "accept":
			action = &Accept{}
		case "counter":
			action = &Counter{}
		default:
			return fmt.Errorf("unhandle action type %s", a.Type)
		}

		if err := json.Unmarshal(a.Params, action); err != nil {
			return err
		}

		*as = append(*as, action)
	}

	return nil
}

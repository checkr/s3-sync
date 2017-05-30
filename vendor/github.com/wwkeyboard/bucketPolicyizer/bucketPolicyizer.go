package bucketPolicyizer

import (
	"encoding/json"
)

var defaultVersion = "2012-10-17"

type Action []string
type Resource []string

// Custom json unmarshal for Resource and Action
func _unmarshalJSON(data []byte) ([]string, error) {
	var v []string
	if err := json.Unmarshal(data, &v); err != nil {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, err
		}
		return []string{s}, nil
	}
	return v, nil
}

// Custom json unmarshal for Action
func (ms *Action) UnmarshalJSON(data []byte) error {
	v, err := _unmarshalJSON(data)
	if err != nil {
		return err
	}
	*ms = v
	return nil
}

// Custom json unmarshal for Resource
func (ms *Resource) UnmarshalJSON(data []byte) error {
	v, err := _unmarshalJSON(data)
	if err != nil {
		return err
	}
	*ms = v
	return nil
}

// Policy is the Bucket policy
type Policy struct {
	Version   string
	Statement []Statement
}

// Statement is a single permission
// the Principal element is sometimes an
// array and sometimes a string
type Statement struct {
	Sid       string `json:",omitempty"`
	Effect    string
	Principal interface{} `json:",omitempty"`
	Action    Action
	Resource  Resource
}

// Principal is a list of ARNs
type Principal struct {
	AWS []string
}

// EmptyPolicy creates a valid empty policy
func EmptyPolicy() Policy {
	return Policy{
		Version: defaultVersion,
	}
}

// CompilePolicy renders the policy to JSON
func CompilePolicy(policy Policy) (string, error) {
	p, err := json.Marshal(policy)

	if err != nil {
		return "", err
	}

	return string(p), nil
}

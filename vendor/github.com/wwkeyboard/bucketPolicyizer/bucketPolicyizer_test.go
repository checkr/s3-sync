package bucketPolicyizer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"testing"
)

// Many of these test cases are taken from
// http://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html

func TestVersion(t *testing.T) {
	policy := EmptyPolicy()

	if policy.Version != "2012-10-17" {
		t.Error("version not set correctly")
	}
}

func TestActionAndResourceAsString(t *testing.T) {
	policy_json := `{
		"Version":"2012-10-17",
		"Statement":[
			{
				"Sid":"AddCannedAcl",
				"Effect":"Allow",
				"Principal":"*",
				"Action":"s3:GetObject",
				"Resource":"arn:aws:s3::exampleBucket/*"
			}
		]
	}`

	policy := Policy{}
	if err := json.Unmarshal([]byte(policy_json), &policy); err != nil {
		panic(err)
	}

	p, err := CompilePolicy(policy)
	if err != nil {
		t.Error("couldn't compile policy", err)
	}

	sidTest := regexp.MustCompile(`AddCannedAcl`)
	if !sidTest.MatchString(p) {
		fmt.Println(p)
		t.Error("couldn't match Sid")
	}
}

func TestReadOnlyFromAnonymous(t *testing.T) {
	policy := EmptyPolicy()
	action := Action{"s3:GetObject"}
	resource := Resource{"arn:aws:s3::exampleBucket/*"}
	s := Statement{
		Sid:       "AddCannedAcl",
		Effect:    "Allow",
		Principal: "*",
		Action:    action,
		Resource:  resource,
	}

	policy.Statement = []Statement{s}

	p, err := CompilePolicy(policy)
	if err != nil {
		t.Error("couldn't compile policy", err)
	}

	sidTest := regexp.MustCompile(`AddCannedAcl`)
	if !sidTest.MatchString(p) {
		fmt.Println(p)
		t.Error("couldn't match Sid")
	}
}

func TestReadOnlyFromSpecificARN(t *testing.T) {
	policy := EmptyPolicy()
	action := Action{"s3:GetObject"}
	resource := Resource{"arn:aws:s3::exampleBucket/*"}
	principal := Principal{
		AWS: []string{"arn:aws:iam::111122223333:root", "arn:aws:iam::444455556666:root"},
	}

	s := Statement{
		Sid:       "AddCannedAcl",
		Effect:    "Allow",
		Principal: principal,
		Action:    action,
		Resource:  resource,
	}

	policy.Statement = []Statement{s}

	p, err := CompilePolicy(policy)
	if err != nil {
		t.Error("couldn't compile policy", err)
	}

	sidTest := regexp.MustCompile(`AddCannedAcl`)
	if !sidTest.MatchString(p) {
		fmt.Println(p)
		t.Error("couldn't match Sid")
	}
}

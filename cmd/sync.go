// Copyright © 2017 NAME HERE <EMAIL ADDRESS>
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wwkeyboard/bucketPolicyizer"
)

// syncCmd represents the sync command
var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		sourceSess := session.Must(session.NewSessionWithOptions(
			session.Options{
				Config: aws.Config{
					Credentials: credentials.NewStaticCredentials(
						viper.GetString("source.aws_access_key_id"),
						viper.GetString("source.aws_secret_access_key"),
						"",
					),
				},
			},
		))

		destinationSess := session.Must(session.NewSessionWithOptions(
			session.Options{
				Config: aws.Config{
					Credentials: credentials.NewStaticCredentials(
						viper.GetString("destination.aws_access_key_id"),
						viper.GetString("destination.aws_secret_access_key"),
						"",
					),
				},
			},
		))

		// Create buckets and policies
		for sourceBucketName, destinationBucketName := range viper.GetStringMapString("buckets") {
			updateDestinationUserPolicy(destinationSess, sourceBucketName, destinationBucketName)

			// Get correct region
			ctx := context.Background()
			region, err := s3manager.GetBucketRegion(ctx, sourceSess, sourceBucketName, viper.GetString("source.aws_region"))
			if err != nil {
				if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "NotFound" {
					log.Printf("ERROR: bucket(%s) not found\n", sourceBucketName)
					return
				}
			}

			svcSourceBucket := s3.New(sourceSess, aws.NewConfig().WithRegion(region))
			params := &s3.GetBucketPolicyInput{
				Bucket: aws.String(sourceBucketName),
			}

			// Create or update policy
			log.Printf("Creating bucket(%s) policy", sourceBucketName)
			resp, err := svcSourceBucket.GetBucketPolicy(params)
			if err != nil {
				if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "NoSuchBucketPolicy" {
					// Create new policy
					policyJSON, _ := bucketPolicyizer.CompilePolicy(createSourcePolicy(sourceBucketName))
					params := &s3.PutBucketPolicyInput{
						Bucket: aws.String(sourceBucketName),
						Policy: aws.String(policyJSON),
					}
					_, err := svcSourceBucket.PutBucketPolicy(params)
					if err != nil {
						log.Fatal(err)
					}
				}
				//log.Fatal(err)
			} else {
				policy := bucketPolicyizer.Policy{}
				if err := json.Unmarshal([]byte(*resp.Policy), &policy); err != nil {
					panic(err)
				}

				policyJSON, _ := bucketPolicyizer.CompilePolicy(updateSourcePolicy(sourceBucketName, policy))
				params := &s3.PutBucketPolicyInput{
					Bucket: aws.String(sourceBucketName),
					Policy: aws.String(policyJSON),
				}
				_, err := svcSourceBucket.PutBucketPolicy(params)
				if err != nil {
					log.Fatal(err)
				}
			}

			// Create destination bucket
			svcDestinationBucket := s3.New(destinationSess, aws.NewConfig().WithRegion(viper.GetString("destination.aws_region")))

			log.Printf("Creating bucket(%s)", destinationBucketName)
			createBucketParams := &s3.CreateBucketInput{
				Bucket: aws.String(destinationBucketName), // Required
			}
			_, err = svcDestinationBucket.CreateBucket(createBucketParams)
			if err != nil {
				if aerr, ok := err.(awserr.Error); ok && (aerr.Code() == "BucketAlreadyExists" || aerr.Code() == "BucketAlreadyOwnedByYou") {
					log.Printf("bucket(%s) already exists\n", destinationBucketName)
				} else {
					log.Fatal(err)
				}
			}

			if viper.GetBool("destination.enable_bucket_versioning") {
				bucketVersioningParams := &s3.PutBucketVersioningInput{
					Bucket: aws.String(destinationBucketName),
					VersioningConfiguration: &s3.VersioningConfiguration{
						Status: aws.String("Enabled"),
					},
				}

				log.Printf("Enabling bucket(%s) versioning", destinationBucketName)
				_, err = svcDestinationBucket.PutBucketVersioning(bucketVersioningParams)
				if err != nil {
					log.Println(err.Error())
					return
				}
			}

			var syncCmd []string
			syncCmd = append(syncCmd, "s3")
			syncCmd = append(syncCmd, "sync")

			if viper.GetString("destination.sync_sse") != "" {
				syncCmd = append(syncCmd, "--sse")
				syncCmd = append(syncCmd, viper.GetString("destination.sync_sse"))
			}

			syncCmd = append(syncCmd, fmt.Sprintf("s3://%s", sourceBucketName))
			syncCmd = append(syncCmd, fmt.Sprintf("s3://%s", destinationBucketName))

			log.Printf("Syncing bucket(%s) => bucket(%s)", sourceBucketName, destinationBucketName)
			if err = awsCliRun(syncCmd); err != nil {
				log.Fatal(err)
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(syncCmd)
}

func createSourcePolicy(sourceBucketName string) bucketPolicyizer.Policy {
	policy := bucketPolicyizer.EmptyPolicy()
	policyStatment := bucketPolicyizer.Statement{
		Sid:    "DelegateS3AccessForMigration",
		Effect: "Allow",
		Principal: bucketPolicyizer.Principal{
			AWS: []string{fmt.Sprintf("arn:aws:iam::%s:user/%s", viper.GetString("destination.account_number"), viper.GetString("destination.aws_user"))},
		},
		Action: bucketPolicyizer.Action{"s3:*"},
		Resource: bucketPolicyizer.Resource{
			fmt.Sprintf("arn:aws:s3:::%s/*", sourceBucketName),
			fmt.Sprintf("arn:aws:s3:::%s", sourceBucketName),
		},
	}
	policy.Statement = append(policy.Statement, policyStatment)

	return policy
}

func updateSourcePolicy(sourceBucketName string, existingPolicy bucketPolicyizer.Policy) bucketPolicyizer.Policy {
	exists := false
	policy := createSourcePolicy(sourceBucketName)

	for i, statment := range existingPolicy.Statement {
		if statment.Sid == "DelegateS3AccessForMigration" {
			existingPolicy.Statement[i] = policy.Statement[0]
			exists = true
		}
	}

	if exists == false {
		existingPolicy.Statement = append(existingPolicy.Statement, policy.Statement[0])
	}

	return existingPolicy
}

func createDestinationUserPolicy(sourceBucketName string, destinationBucketName string) bucketPolicyizer.Policy {
	policy := bucketPolicyizer.EmptyPolicy()
	var resources []string

	resources = append(resources, fmt.Sprintf("arn:aws:s3:::%s/*", sourceBucketName))
	resources = append(resources, fmt.Sprintf("arn:aws:s3:::%s", sourceBucketName))
	resources = append(resources, fmt.Sprintf("arn:aws:s3:::%s/*", destinationBucketName))
	resources = append(resources, fmt.Sprintf("arn:aws:s3:::%s", destinationBucketName))

	policyStatment := bucketPolicyizer.Statement{
		Effect:   "Allow",
		Action:   bucketPolicyizer.Action{"s3:*"},
		Resource: resources,
	}
	policy.Statement = append(policy.Statement, policyStatment)

	return policy
}

func updateDestinationUserPolicy(destinationSess *session.Session, sourceBucketName string, destinationBucketName string) {
	svc := iam.New(destinationSess)

	destinationUserPolicy, err := bucketPolicyizer.CompilePolicy(createDestinationUserPolicy(sourceBucketName, destinationBucketName))
	if err != nil {
		log.Fatal(err)
	}

	params := &iam.PutUserPolicyInput{
		PolicyDocument: aws.String(destinationUserPolicy),
		PolicyName:     aws.String("DelegateS3AccessForMigration"),
		UserName:       aws.String(viper.GetString("destination.aws_user")),
	}

	log.Printf("Creating user(%s) policy", viper.GetString("destination.aws_user"))
	_, err = svc.PutUserPolicy(params)
	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return
	}
}

func awsCliRun(params []string) error {
	binary, err := exec.LookPath("aws")
	if err != nil {
		return err
	}

	cmd := exec.Command(binary, params...)
	env := os.Environ()
	env = append(env, fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", viper.GetString("destination.aws_access_key_id")))
	env = append(env, fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", viper.GetString("destination.aws_secret_access_key")))
	env = append(env, fmt.Sprintf("AWS_DEFAULT_REGION=%s", viper.GetString("destination.aws_region")))
	cmd.Env = env

	cmdOut, err := cmd.StdoutPipe()
	if err != nil {
		log.Println("Error creating StdoutPipe for Cmd", err)
		os.Exit(1)
	}

	cmdErr, err := cmd.StderrPipe()
	if err != nil {
		log.Println("Error creating StderrPipe for Cmd", err)
		os.Exit(1)
	}

	scanner1 := bufio.NewScanner(cmdOut)
	go func() {
		for scanner1.Scan() {
			log.Printf("(aws cli) => %s\n", scanner1.Text())
		}
	}()

	scanner2 := bufio.NewScanner(cmdErr)
	go func() {
		for scanner2.Scan() {
			log.Printf("(aws cli) => %s\n", scanner2.Text())
		}
	}()

	startErr := cmd.Start()
	if startErr != nil {
		return startErr
	}

	err = cmd.Wait()

	return err
}

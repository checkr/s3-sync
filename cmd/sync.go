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
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/go-redis/redis"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wwkeyboard/bucketPolicyizer"
)

const (
	NETWORK_ERROR     = 10
	PERMISSIONS_ERROR = 11
	OTHER_ERROR       = 12
)

type SyncStatus struct {
	TotalCount   int
	ErrorCount   int
	SuccessCount int
	CachedCount  int
	ElapsedTime  time.Duration
	ErrorMap     map[int]int
	SourceBucket string
	DestBucket   string
}

type copyConfig struct {
	SourceBucket      string
	DestBucket        string
	SourceCanonicalID string
	DestCanonicalID   string
}

type copyOutput struct {
	Success bool
	Err     error
	Message string
	ErrID   int
	Cached  bool
}

func init() {
	RootCmd.AddCommand(syncCmd)
}

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
		useCache := viper.GetBool("useCache")

		sourceRegion := viper.GetString("source.aws_region")
		sourceSess := session.Must(session.NewSessionWithOptions(
			session.Options{
				Config: aws.Config{
					Credentials: credentials.NewStaticCredentials(
						viper.GetString("source.aws_access_key_id"),
						viper.GetString("source.aws_secret_access_key"),
						"",
					),
					Region: &sourceRegion,
				},
			},
		))

		destRegion := viper.GetString("destination.aws_region")
		destinationSess := session.Must(session.NewSessionWithOptions(
			session.Options{
				Config: aws.Config{
					Credentials: credentials.NewStaticCredentials(
						viper.GetString("destination.aws_access_key_id"),
						viper.GetString("destination.aws_secret_access_key"),
						"",
					),
					Region: &destRegion,
				},
			},
		))

		// Update destination user policy
		svc := iam.New(destinationSess)

		destinationUserPolicy, err := bucketPolicyizer.CompilePolicy(createDestinationUserPolicy())
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

		// Create buckets and policies
		for sourceBucketName, destinationBucketName := range viper.GetStringMapString("buckets") {
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
				if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "BucketAlreadyExists" {
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
					log.Println("ERROR")
					return
				}

				encryptionScheme := viper.GetString("destination.sync_sse")
				if encryptionScheme != "" {
					encryptionAlgorithm := ""
					kmsMasterKey := viper.GetString("destination.kms_master_key_id")
					serverSideEncryptionParams := &s3.ServerSideEncryptionByDefault{}
					if encryptionScheme == "AES256" {
						encryptionAlgorithm = s3.ServerSideEncryptionAes256
						serverSideEncryptionParams = &s3.ServerSideEncryptionByDefault{
							SSEAlgorithm: &encryptionAlgorithm,
						}
					} else if encryptionScheme == "KMS" {
						encryptionAlgorithm = s3.ServerSideEncryptionAwsKms
						if kmsMasterKey == "" {
							log.Printf("Bucket encryption scheme KMS requires you to provide a kms_master_key_id")
						} else {
							serverSideEncryptionParams = &s3.ServerSideEncryptionByDefault{
								SSEAlgorithm:   &encryptionAlgorithm,
								KMSMasterKeyID: &kmsMasterKey,
							}
						}
					} else {
						log.Printf("Bucket encryption scheme: %s is not valid", encryptionScheme)
						return
					}
					encryptionAlgorithm = s3.ServerSideEncryptionAes256
					bucketEncryptionParams := &s3.PutBucketEncryptionInput{
						Bucket: aws.String(destinationBucketName),
						ServerSideEncryptionConfiguration: &s3.ServerSideEncryptionConfiguration{
							Rules: []*s3.ServerSideEncryptionRule{
								&s3.ServerSideEncryptionRule{
									ApplyServerSideEncryptionByDefault: serverSideEncryptionParams,
								},
							},
						},
					}
					log.Printf("Enabling bucket(%s) encryption", destinationBucketName)
					_, err = svcDestinationBucket.PutBucketEncryption(bucketEncryptionParams)
					if err != nil {
						log.Println(err.Error())
						return
					}

				}
			}

			destClient := s3.New(destinationSess)
			sourceClient := s3.New(sourceSess)

			sourceCanonicalID := viper.GetString("source.canonical_id")
			destCanonicalID := viper.GetString("destination.canonical_id")

			copyConfig := copyConfig{
				SourceBucket:      sourceBucketName,
				DestBucket:        destinationBucketName,
				SourceCanonicalID: sourceCanonicalID,
				DestCanonicalID:   destCanonicalID,
			}

			maxKeys := int64(1000)
			fetchOwners := true

			listObjectsInput := s3.ListObjectsV2Input{
				Bucket:     &sourceBucketName,
				MaxKeys:    &maxKeys,
				FetchOwner: &fetchOwners,
			}

			var redisClient *redis.Client = nil
			if useCache {
				redisClient = redis.NewClient(&redis.Options{
					Addr:       viper.GetString("redis.addr"),
					Password:   viper.GetString("redis.password"),
					DB:         viper.GetInt("redis.db"),
					PoolSize:   viper.GetInt("redis.poolsize"),
					MaxRetries: viper.GetInt("redis.max_retries"),
				})

				_, err = redisClient.Ping().Result()
				if err != nil {
					log.Fatal("Can not connect to redis client.")
				}

				if viper.GetBool("startFromLastCached") {

					val, _ := redisClient.Get(fmt.Sprintf("%s-LAST_CACHED_KEY", sourceBucketName)).Result()
					if val != "" {
						listObjectsInput.SetStartAfter(val)
					}
				}
			}

			var wg sync.WaitGroup
			processQueue := make(chan *s3.Object, viper.GetInt("queue_size"))
			resultsQueue := make(chan copyOutput, viper.GetInt("queue_size"))

			go listObjects(sourceClient, &listObjectsInput, processQueue)

			for i := 0; i < viper.GetInt("max_sync_workers"); i++ {
				wg.Add(1)
				go copyObject(destClient, &copyConfig, &wg, redisClient, processQueue, resultsQueue)
			}

			go func() {
				wg.Wait()
				close(resultsQueue)
			}()

			start := time.Now()
			elapsedPerChunk := time.Now()
			status := SyncStatus{
				SuccessCount: 0,
				TotalCount:   0,
				ErrorCount:   0,
				CachedCount:  0,
				ErrorMap: map[int]int{
					NETWORK_ERROR:     0,
					PERMISSIONS_ERROR: 0,
					OTHER_ERROR:       0,
				},
				SourceBucket: sourceBucketName,
				DestBucket:   destinationBucketName,
			}
			for output := range resultsQueue {
				if output.Success {
					status.SuccessCount++
				} else if !output.Success {
					status.ErrorCount++

					status.ErrorMap[output.ErrID]++
				}
				if output.Cached {
					status.CachedCount++
				}
				// count++
				status.ElapsedTime = time.Since(start)
				status.TotalCount++
				if status.TotalCount%10000 == 0 {
					fmt.Printf("\nELAPSED SINCE LAST STATUS: %s\n", time.Since(elapsedPerChunk))
					logStatus(status)
					elapsedPerChunk = time.Now()
				}
			}

			logStatus(status)
			log.Println("COMPLETED SYNC FOR BUCKET")
		}
	},
}

func logStatus(status SyncStatus) {
	log.Println(fmt.Sprintf(
		`
SYNC STATUS: %s -> %s
SUCCEEDED: %v, FAILED: %v, TOTAL: %v, ELAPSED_TIME: %s
NETWORK_ERROR: %v,
PERMISSIONS_ERROR: %v,
OTHER_ERROR: %v,
CACHED: %v
`,
		status.SourceBucket,
		status.DestBucket,
		status.SuccessCount,
		status.ErrorCount,
		status.TotalCount,
		status.ElapsedTime,
		status.ErrorMap[NETWORK_ERROR],
		status.ErrorMap[PERMISSIONS_ERROR],
		status.ErrorMap[OTHER_ERROR],
		status.CachedCount))
}

func copyObject(s3Client *s3.S3, config *copyConfig, wg *sync.WaitGroup, redisClient *redis.Client, processQueue <-chan *s3.Object, resultsQueue chan<- copyOutput) {
	for object := range processQueue {

		useCache := viper.GetBool("useCache")
		output := copyOutput{}
		skip := false

		cacheKey := fmt.Sprintf("%s-%s", config.SourceBucket, *object.Key)
		lastCachedKey := fmt.Sprintf("%s-LAST_CACHED_KEY", config.SourceBucket)
		if useCache {

			redisErr := redisClient.Set(lastCachedKey, cacheKey, 0).Err()
			if redisErr != nil {
				log.Println("FAILED TO SET LAST KEY")
			}

			val, redisError := redisClient.Get(cacheKey).Result()
			if redisError != nil && redisError != redis.Nil {
				panic(redisError)
			}
			if val == fmt.Sprintf("FAILED-%v", PERMISSIONS_ERROR) {
				output.Success = false
				output.Message = "FAILED PERMISSIONS"
				output.ErrID = PERMISSIONS_ERROR
				output.Cached = true
				resultsQueue <- output
				skip = true
			}

			lastCopied, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", val)
			if err == nil && lastCopied.After(*object.LastModified) || lastCopied.Equal(*object.LastModified) {
				output.Success = true
				output.Message = "COPIED!"
				output.Cached = true
				resultsQueue <- output
				skip = true
			}

		}

		if skip == false {
			encodedKey := url.URL{Path: *object.Key}
			encodedKeyString := encodedKey.String()
			cacheValue := ""

			copySource := fmt.Sprintf("%s/%s", config.SourceBucket, encodedKeyString)
			copyObjectInput := s3.CopyObjectInput{
				Bucket:     &config.DestBucket,
				CopySource: &copySource,
				Key:        object.Key,
			}
			_, err := s3Client.CopyObject(&copyObjectInput)
			if err != nil {
				output.Success = false
				output.Err = err
				output.Message = fmt.Sprintf("ERROR COPYING %s to %s/%s", *copyObjectInput.CopySource, *copyObjectInput.Bucket, *copyObjectInput.Key)

				if strings.Contains(err.Error(), "RequestError") {
					output.ErrID = NETWORK_ERROR
					cacheValue = fmt.Sprintf("FAILED-%v", NETWORK_ERROR)
				} else if strings.Contains(err.Error(), "403") {
					output.ErrID = PERMISSIONS_ERROR
					cacheValue = fmt.Sprintf("FAILED-%v", PERMISSIONS_ERROR)

				} else {
					output.ErrID = OTHER_ERROR
					log.Println(copyObjectInput.Bucket, *object.Key)
					log.Println(err.Error())
				}

			} else {
				output.Success = true
				output.Err = nil
				output.Message = fmt.Sprintf("COPIED %s TO %s/%s", *copyObjectInput.CopySource, *copyObjectInput.Bucket, *copyObjectInput.Key)

				cacheValue = object.LastModified.String()
			}

			if useCache {
				redisErr := redisClient.Set(cacheKey, cacheValue, 0).Err()
				if redisErr != nil {
					log.Println(redisErr)
				}
			}

			resultsQueue <- output
		}
	}

	wg.Done()

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

func createDestinationUserPolicy() bucketPolicyizer.Policy {
	policy := bucketPolicyizer.EmptyPolicy()
	var resources []string

	for sourceBucketName, destinationBucketName := range viper.GetStringMapString("buckets") {
		resources = append(resources, fmt.Sprintf("arn:aws:s3:::%s/*", sourceBucketName))
		resources = append(resources, fmt.Sprintf("arn:aws:s3:::%s", sourceBucketName))
		resources = append(resources, fmt.Sprintf("arn:aws:s3:::%s/*", destinationBucketName))
		resources = append(resources, fmt.Sprintf("arn:aws:s3:::%s", destinationBucketName))
	}

	policyStatment := bucketPolicyizer.Statement{
		Effect:   "Allow",
		Action:   bucketPolicyizer.Action{"s3:*"},
		Resource: resources,
	}
	policy.Statement = append(policy.Statement, policyStatment)

	return policy
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

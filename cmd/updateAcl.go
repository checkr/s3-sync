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
	"fmt"
	"log"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Config struct {
	SourceCanonicalId string
	DestCanonicalId   string
	BucketName        string
}

// syncCmd represents the sync command
var updateACLCmd = &cobra.Command{
	Use:   "updateAcl",
	Short: "Updates ACLs for all objects in a bucket",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		region := viper.GetString("source.aws_region")
		sourceSess := session.Must(session.NewSessionWithOptions(
			session.Options{
				Config: aws.Config{
					Credentials: credentials.NewStaticCredentials(
						viper.GetString("source.aws_access_key_id"),
						viper.GetString("source.aws_secret_access_key"),
						"",
					),
					Region: &region,
				},
			},
		))

		svc := s3.New(sourceSess)

		maxKeys := int64(10000)
		fetchOwners := true
		// Create buckets and policies
		for sourceBucketName := range viper.GetStringMapString("buckets") {
			sourceCanonicalID := viper.GetString("source.canonical_id")
			destCanonicalID := viper.GetString("destination.canonical_id")
			aclConfig := Config{
				SourceCanonicalId: sourceCanonicalID,
				DestCanonicalId:   destCanonicalID,
				BucketName:        sourceBucketName,
			}

			listObjectsInput := s3.ListObjectsV2Input{
				Bucket:     &sourceBucketName,
				MaxKeys:    &maxKeys,
				FetchOwner: &fetchOwners,
			}

			objectsQueue := make(chan *s3.Object, 10000)
			resultsQueue := make(chan string, 10000)

			go listObjects(svc, &listObjectsInput, objectsQueue)

			var wg sync.WaitGroup

			for w := 0; w < viper.GetInt("max_sync_workers"); w++ {
				wg.Add(1)
				go updateAcl(svc, &wg, &aclConfig, objectsQueue, resultsQueue)
			}

			go func() {
				wg.Wait()
				close(resultsQueue)
			}()

			count := 0
			for output := range resultsQueue {
				count++
				log.Println(count, output)
			}
		}
	},
}

func updateAcl(s3Client *s3.S3, wg *sync.WaitGroup, config *Config, processQueue <-chan *s3.Object, results chan<- string) {

	userType := "CanonicalUser"

	fullControl := "FULL_CONTROL"
	fullControlGrantee := s3.Grantee{ID: &config.SourceCanonicalId, Type: &userType}
	fullControlGrant := s3.Grant{Grantee: &fullControlGrantee, Permission: &fullControl}

	readControl := "READ"
	readAccessGrantee := s3.Grantee{ID: &config.DestCanonicalId, Type: &userType}
	readAccessGrant := s3.Grant{Grantee: &readAccessGrantee, Permission: &readControl}

	for object := range processQueue {
		fullControlOriginal := s3.Grantee{ID: object.Owner.ID, Type: &userType}
		fullControlOriginalGrant := s3.Grant{Grantee: &fullControlOriginal, Permission: &fullControl}

		grants := []*s3.Grant{}
		grants = append(grants, &fullControlGrant, &readAccessGrant, &fullControlOriginalGrant)

		// SET OBJECT ACLS
		objectACL := s3.PutObjectAclInput{
			Bucket: &config.BucketName,
			Key:    object.Key,
			AccessControlPolicy: &s3.AccessControlPolicy{
				Grants: grants,
				Owner: &s3.Owner{
					DisplayName: object.Owner.DisplayName,
					ID:          object.Owner.ID,
				},
			},
		}

		output := ""
		_, err := s3Client.PutObjectAcl(&objectACL)
		if err != nil {
			output = fmt.Sprintf("ERROR %s - %s", *object.Key, err)
		} else {
			output = fmt.Sprintf("SUCCESSFULLY UPDATED ACL: %s", *object.Key)
		}
		results <- output
	}
	wg.Done()
}

func init() {
	RootCmd.AddCommand(updateACLCmd)
}

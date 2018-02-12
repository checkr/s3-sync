package cmd

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/service/s3"
)

func listObjects(s3Client *s3.S3, listObjectsInput *s3.ListObjectsV2Input, processQueue chan<- *s3.Object) {

	end := false
	objectsPage := &s3.ListObjectsV2Output{}
	err := fmt.Errorf("")

	for end == false {

		if objectsPage.NextContinuationToken != nil {
			listObjectsInput.SetContinuationToken(*objectsPage.NextContinuationToken)
		}

		objectsPage, err = s3Client.ListObjectsV2(listObjectsInput)
		if err != nil {
			log.Fatal(err)
		}

		for _, object := range objectsPage.Contents {
			processQueue <- object
		}

		if objectsPage.NextContinuationToken == nil {
			end = true
			close(processQueue)
		}

	}
}

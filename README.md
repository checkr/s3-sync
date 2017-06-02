# Migrating S3 Buckets Across AWS Accounts

There are a lot of steeps needed to migrate buckets across accounts and this tool automates them all!

1. Before running copy `config.yaml` to `config.prod.yaml`, fill in the blanks for source and destination account and add buckets you would like to sync.
```
source:
  account_number: ...
  aws_access_key_id: ...
  aws_secret_access_key: ...
  aws_region: ...

destination:
  account_number: ...
  aws_user: username
  aws_access_key_id: ...
  aws_secret_access_key: ...
  aws_region: ...
  enable_bucket_versioning: true
  sync_sse: AES256

buckets:
  saso-test-1: us-east-1-checkr-saso-test-1
  saso-test-2: us-east-1-checkr-saso-test-2
```

2. Run the sync with `go run main.go sync --config config.prod.yaml`

![s3-sync](https://github.com/checkr/s3-sync/blob/master/static/s3-sync.gif?raw=true)

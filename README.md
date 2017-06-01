# S3 bucket sync

```bash
➜  s3-sync git:(master) go run main.go sync --config config.prod.yaml
Using config file: config.prod.yaml
2017/05/30 15:20:05 Creating user(saso) policy
2017/05/30 15:20:06 Creating bucket(saso-test-1) policy
2017/05/30 15:20:07 Creating bucket(us-east-1-checkr-saso-test-1)
2017/05/30 15:20:08 Enabling bucket(us-east-1-checkr-saso-test-1) versioning
2017/05/30 15:20:09 Running bucket(saso-test-1) => bucket(us-east-1-checkr-saso-test-1) sync
copy: s3://saso-test/projects.csv to s3://us-east-1-checkr-saso-test-1/projects.csv
```

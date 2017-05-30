# S3 bucket migrator

```bash
➜  s3-migrator git:(master) go run main.go sync --config config.prod.yaml
Using config file: config.prod.yaml
2017/05/30 15:20:05 Creating user(saso) policy
2017/05/30 15:20:06 Creating bucket(saso-test) policy
2017/05/30 15:20:07 Creating bucket(us-east-1-checkr-saso-test)
2017/05/30 15:20:08 Enabling bucket(us-east-1-checkr-saso-test) versioning
2017/05/30 15:20:09 Running bucket(saso-test) => bucket(us-east-1-checkr-saso-test) sync
copy: s3://saso-test/projects.csv to s3://us-east-1-checkr-saso-test/projects.csv
```

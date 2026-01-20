# S3 → Lambda (trigger) → normalized output DynamoDB

## Date 1/20/2026
As we tested the parse script for getting normalized cloud trail api logs, time has come to make this process automatically run, S3 triggers Lambda and Lambda upload the parsed logs to Dynamo DB tables that will be used later.

## We will do this whole process using AWS CLI, AWS Docs and AI

## Step 1.1: Create a trust policy file. I named it trust-lambda.json allows lambda assume the role

## Step 1.2: Creating IAM Role 
```
aws iam create-role \
  --role-name anomai-ingest-lambda-role \
  --assume-role-policy-document file://trust-lambda.json
```
## Step 1.3 Attaching basic CloudWatch logging policy (managed)
```
aws iam attach-role-policy \
  --role-name anomai-ingest-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

## Step 1.4 Creating an inline policy for S3 read/write. I named policy-anomai-ingest

## Step 1.5 Attaching this inline policy to our role (anomai-ingest-lambda-role)
```
aws iam put-role-policy \
aws iam put-role-policy \
  --role-name anomai-ingest-lambda-role \
  --policy-name anomai-ingest-s3-ddb \
  --policy-document file://policy-anomai-ingest.json
```

## Step 1.6 let's get role ARN we will need in step 2
```
aws iam get-role \
  --role-name anomai-ingest-lambda-role \
  --query 'Role.Arn' \
  --output text
```

## Step 2.1 Creating normalize.py for lambda function and we will have seperate folder for this ofc, lambda/ingest

## Step 2.2 Creating handler.py for writing to the dynamodb

## Step 2.3 Zipping both normalize and handler together
```
zip -r function.zip handler.py normalize.py
```

## Step 2.4 Creating the Lambda function
Setting variables
```
export FUNCTION_NAME=anomai-ingest-cloudtrail
export ROLE_ARN=arn:aws:iam::643766343043:role/anomai-ingest-lambda-role
export AWS_REGION=us-east-2
```
Creating the function
```
aws lambda create-function \
  --function-name "$FUNCTION_NAME" \
  --runtime python3.11 \
  --role "$ROLE_ARN" \
  --handler handler.lambda_handler \
  --zip-file fileb://function.zip \
  --timeout 60 \
  --memory-size 256 \
  --environment "Variables={EVENTS_TABLE=anomai_events,INPUT_PREFIX=AWSLogs/,MASK_KEYS=true,KEEP_HEAVY_FIELDS=false}"
```

## Step 2.5 Verify
```
aws lambda get-function --function-name "$FUNCTION_NAME" --query 'Configuration.State' --output text
```
If it says Active we are fine

## Step 3.1 Allow S3 to invoke the Lambda

Setting up the variables
```
export AWS_REGION=us-east-2
export BUCKET=anomai-cloudtrail-logs-dev
export FUNCTION_NAME=anomai-ingest-cloudtrail
```

Getting lambda ARN
```
export FUNCTION_ARN=$(aws lambda get-function \
  --function-name "$FUNCTION_NAME" \
  --query 'Configuration.FunctionArn' \
  --output text)
echo "$FUNCTION_ARN"
```

Adding permissions
```
aws lambda add-permission \
  --function-name "$FUNCTION_NAME" \
  --statement-id s3-invoke-anomai-ingest \
  --action lambda:InvokeFunction \
  --principal s3.amazonaws.com \
  --source-arn "arn:aws:s3:::$BUCKET" \
  --source-account 643766343043
```

## Step 3.2 Setting S3 bucket notification config
Creating the config file which will trigger lamda when logs will be uploaded to s3 bucket. I named it s3-notification

Then we will apply that to the bucket
```
aws s3api put-bucket-notification-configuration \
  --bucket "$BUCKET" \
  --notification-configuration file://s3-notification.json
```

Verify it did apply
```
aws s3api get-bucket-notification-configuration --bucket "$BUCKET"
```

## Step 4 is Test Stage nothing specifically needs to be done here any type of API actions already recording and uploading to the bucket we just need to do some API actions like describe instances, list buckets and etc. Wait 5-10 mins then final check
```
aws dynamodb scan --table-name anomai_events --max-items 5
```

## Test Results:
```
Lambda function works pretty good, one issue it's also logging it's own function every time creating loop that should be fixed
```

## Step 1. Handler.py updated

## Step 2. Rezipping and updating the lambda

```
zip -r function.zip handler.py normalize.py
```

```
aws lambda update-function-code \
  --function-name anomai-ingest-cloudtrail \
  --zip-file fileb://function.zip
```

## Step 3. Testing once again making sure it doesn't log itself
```
aws dynamodb scan \
  --table-name anomai_events \
  --filter-expression "actor = :a OR contains(event_json, :r)" \
  --expression-attribute-values '{":a":{"S":"anomai-ingest-cloudtrail"},":r":{"S":"anomai-ingest-lambda-role"}}' \
  --max-items 10
```

## Success!
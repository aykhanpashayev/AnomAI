## Today's objective is creating test-actor role which will make noise inside of our environment create some anomalies logs

## Some documentation I used:
https://docs.aws.amazon.com/cli/latest/reference/iam/create-role.html#examples
https://docs.aws.amazon.com/cli/latest/reference/iam/attach-role-policy.html#examples
https://nelson.cloud/aws-iam-allowing-a-role-to-assume-another-role/

## Create trust policy
```
I named it trust-policy.json basically, it allows to assume the role
```

## Then we will create the role
```
aws iam create-role \
    --role-name anomai-test-actor \
    --assume-role-policy-document file://trust-policy.json
```

## Create an inline policy allowing test-actor to make some noise
```
I named it anomai-test-actor.json
```

## Attach this inline policy to our role (anomai-test-actor)
```
aws iam put-role-policy \
  --role-name anomai-test-actor \
  --policy-name anomai-test-actor \
  --policy-document file://anomai-test-actor.json
```

## Time has come to assume the role

https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html#examples

```
aws sts assume-role \
    --role-arn arn:aws:iam::643766343043:role/anomai-test-actor \
    --role-session-name firstTest
```

## Credentials will return use
```
export AWS_ACCESS_KEY_ID="writeTheReturnedAccesKeyID"
export AWS_SECRET_ACCESS_KEY="writeTheReturnedSecretAccesKeyID"
export AWS_SESSION_TOKEN="writeTheReturnedSessionToken"
```

## Test if u assumed
```
aws sts get-caller-identity
```

## This step is running the script which named generate_activity.sh, located in scripts/activity_generator folder


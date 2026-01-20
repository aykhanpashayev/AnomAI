# How to run the parse script?

```
python3 parse_cloudtrail.py 643766343043_CloudTrail_us-west-1_20260119T1615Z_ZRnrQ676zA0RlyWQ.json.gz 
```

# What it creates?

```
It creates a json file named normalized check it out it's on same folder
```

# What it returns?

```
--- Sample normalized events ---
{
  "userType": "AssumedRole",
  "userArn": "arn:aws:sts::643766343043:assumed-role/AWSReservedSSO_AnomAIAdmin_aa59d952f393cb6a/Aykhan",
  "accountId": "643766343043",
  "principalId": "AROAZLY3W2WBRTBIFDNWJ:Aykhan",
  "accessKeyId": "****************RSCT",
  "sessionIssuerArn": "arn:aws:iam::643766343043:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_AnomAIAdmin_aa59d952f393cb6a",
  "roleName": "AWSReservedSSO_AnomAIAdmin_aa59d952f393cb6a",
  "sessionName": "Aykhan",
  "userName": null,
  "actor": "Aykhan",
  "mfaAuthenticated": false,
  "eventName": "DescribeRegions",
  "eventSource": "ec2.amazonaws.com",
  "eventType": "AwsApiCall",
  "readOnly": true,
  "awsRegion": "us-west-1",
  "eventTime": "2026-01-19T16:10:31Z",
  "eventID": "314baed6-b83b-49c0-9d82-c27d991377b1",
  "requestID": "ac90a323-2d6d-489f-a8bf-3b26a61f28e1",
  "sourceIPAddress": "131.94.186.33",
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
  "vpcEndpointId": null,
  "errorCode": null,
  "errorMessage": null,
  "additionalEventData": null,
  "tlsDetails": {
    "tlsVersion": "TLSv1.3",
    "cipherSuite": "TLS_AES_128_GCM_SHA256",
    "clientProvidedHostHeader": "ec2.us-west-1.amazonaws.com"
  }
}
{
  "userType": "AssumedRole",
  "userArn": "arn:aws:sts::643766343043:assumed-role/AWSReservedSSO_AnomAIAdmin_aa59d952f393cb6a/Aykhan",
  "accountId": "643766343043",
  "principalId": "AROAZLY3W2WBRTBIFDNWJ:Aykhan",
  "accessKeyId": "****************44OK",
  "sessionIssuerArn": "arn:aws:iam::643766343043:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_AnomAIAdmin_aa59d952f393cb6a",
  "roleName": "AWSReservedSSO_AnomAIAdmin_aa59d952f393cb6a",
  "sessionName": "Aykhan",
  "userName": null,
  "actor": "Aykhan",
  "mfaAuthenticated": false,
  "eventName": "ListNotificationHubs",
  "eventSource": "notifications.amazonaws.com",
  "eventType": "AwsApiCall",
  "readOnly": true,
  "awsRegion": "us-west-1",
  "eventTime": "2026-01-19T16:10:32Z",
  "eventID": "f2586334-89ec-4893-b17e-d2c164de47a0",
  "requestID": "b7d7b521-17ea-451d-b80d-16cb24a85d2f",
  "sourceIPAddress": "131.94.186.33",
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
  "vpcEndpointId": null,
  "errorCode": null,
  "errorMessage": null,
  "additionalEventData": null,
  "tlsDetails": null
}
{
  "userType": "AssumedRole",
  "userArn": "arn:aws:sts::643766343043:assumed-role/AWSReservedSSO_AnomAIAdmin_aa59d952f393cb6a/Aykhan",
  "accountId": "643766343043",
  "principalId": "AROAZLY3W2WBRTBIFDNWJ:Aykhan",
  "accessKeyId": "****************QRTB",
  "sessionIssuerArn": "arn:aws:iam::643766343043:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_AnomAIAdmin_aa59d952f393cb6a",
  "roleName": "AWSReservedSSO_AnomAIAdmin_aa59d952f393cb6a",
  "sessionName": "Aykhan",
  "userName": null,
  "actor": "Aykhan",
  "mfaAuthenticated": false,
  "eventName": "LookupEvents",
  "eventSource": "cloudtrail.amazonaws.com",
  "eventType": "AwsApiCall",
  "readOnly": true,
  "awsRegion": "us-west-1",
  "eventTime": "2026-01-19T16:10:31Z",
  "eventID": "bc802edd-ea19-4ba6-864b-27ee2ad4c4a6",
  "requestID": "8162be34-3321-4667-b136-abb331f1570d",
  "sourceIPAddress": "131.94.186.33",
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
  "vpcEndpointId": null,
  "errorCode": null,
  "errorMessage": null,
  "additionalEventData": null,
  "tlsDetails": {
    "tlsVersion": "TLSv1.3",
    "cipherSuite": "TLS_AES_128_GCM_SHA256",
    "clientProvidedHostHeader": "cloudtrail.us-west-1.amazonaws.com"
  }
}

--- Summary ---
Total normalized events: 10
Files with errors: 0

Top eventSource:
  cloudtrail.amazonaws.com: 8
  ec2.amazonaws.com: 1
  notifications.amazonaws.com: 1

Top eventName:
  LookupEvents: 2
  DescribeTrails: 2
  GetTrailStatus: 2
  DescribeRegions: 1
  ListNotificationHubs: 1
  ListTrails: 1
  ListEventDataStores: 1

Top actor:
  Aykhan: 10

Wrote JSONL: normalized.jsonl
Heavy fields: DROPPED (requestParameters/responseElements)
```
This explains which CloudTrail log fields are most important for the project, broken down into 5 categories.

Who - track who performed an action and identify unusual/ unauthorized activity:
 
    userIdentity.type | differentiates root, IAM user, or assumed role
    
    userIdentity.arn | unique identifier for the identity
    
    userIdentity.accountId | useful for cross-account activity detection
    
    userIdentity.principalId | tracks session or key usage over time
    
    userIdentity.sessionContext.sessionIssuer.arn | detects role assumptions or delegated access
    
    userIdentity.accessKeyId | monitors potential key misuse

   
What - what action was taken and its context:
   
    eventName | core action
   
    eventSource | AWS service performing the action
   
    eventType | management vs data event
   
    readOnly | indicates if the action was read-only or a write
   
    requestParameters | shows the details of the requested change
   
    responseElements | confirms if the action succeeded or failed


Where - detect suspicious locations or IP activity:

    sourceIPAddress	| tracks IP address to detect unusual logins
   
    userAgent | detects scripts, CLI tools, or browser activity
   
    awsRegion | flags unexpected region usage
   
    vpcEndpointId | differentiates internal vs external access
   
   
When - behavioral profiling and anomaly detection:

    eventTime | timestamp of the event for sequence and timing analysis

    eventID | unique ID to prevent duplicates

    requestID | tracks individual API requests

Outcome - success, failure, and security context:
    
    errorCode | identifies unauthorized or failed actions
   
    errorMessage | provides details about failures
   
    additionalEventData | captures MFA usage or other security context
   
    tlsDetails | confirms encryption/security of requests

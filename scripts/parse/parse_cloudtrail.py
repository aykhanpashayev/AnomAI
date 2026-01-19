#json parser
import json

#define normalized field name & how to extract from cloudtrail record
IMPORTANT_FIELDS = {

    #identity type
    "userType": lambda record: record.get("userIdentity", {}).get("type"),

    #arn of identity
    "userArn": lambda record: record.get("userIdentity", {}).get("arn"),

    #aws account id
    "accountId": lambda record: record.get("userIdentity", {}).get("accountId"),

    #principal id
    "principalId": lambda record: record.get("userIdentity", {}).get("principalId"),

    #access key id
    "accessKeyId": lambda record: record.get("userIdentity", {}).get("accessKeyId"),

    #arn of the role
    "sessionIssuerArn": lambda record: record
        .get("userIdentity", {})
        .get("sessionContext", {})
        .get("sessionIssuer", {})
        .get("arn"),


    #api action name
    "eventName": lambda record: record.get("eventName"),

    #aws service
    "eventSource": lambda record: record.get("eventSource"),

    #event type
    "eventType": lambda record: record.get("eventType"),

    #if read only
    "readOnly": lambda record: record.get("readOnly"),


    #source ip address
    "sourceIPAddress": lambda record: record.get("sourceIPAddress"),

    #client used
    "userAgent": lambda record: record.get("userAgent"),

    #region
    "awsRegion": lambda record: record.get("awsRegion"),

    #internal/ external access
    "vpcEndpointId": lambda record: record.get("vpcEndpointId"),


    #timestamp
    "eventTime": lambda record: record.get("eventTime"),

    #event id
    "eventID": lambda record: record.get("eventID"),

    #request id
    "requestID": lambda record: record.get("requestID"),


    #error code
    "errorCode": lambda record: record.get("errorCode"),

    #readable error message
    "errorMessage": lambda record: record.get("errorMessage"),

    #additional security context
    "additionalEventData": lambda record: record.get("additionalEventData"),

    #tls details
    "tlsDetails": lambda record: record.get("tlsDetails"),
}

#read cloudtrail log file & extract important normalized fields
def parse_cloudtrail_log(file_path):
    
    #open & load json file
    with open(file_path, "r") as file:
        data = json.load(file)

    #store all normalized events
    parsed_events = []

    #loop through each record
    for record in data.get("Records", []):
        parsed_record = {}

        #extract each important field
        for field_name, extractor in IMPORTANT_FIELDS.items():
            parsed_record[field_name] = extractor(record)

        #add parsed record to results
        parsed_events.append(parsed_record)

    return parsed_events

#runs only if script is executed directly
if __name__ == "__main__":

    #parse sample log file
    events = parse_cloudtrail_log("cloudtrail_sample.json")

    #print first 3 parsed events for testing
    for event in events[:3]:
        print(json.dumps(event, indent=2))

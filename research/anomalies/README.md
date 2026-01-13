## Research Notes – Jan 13 (Cheng Zhang)

IAM-Related CloudTrail Events Understood Today

1. ConsoleLogin
I learned how ConsoleLogin events reflect user sign-in behavior.  
Key insights:
- Normal logins usually come from consistent geographic regions and during predictable hours.
- Anomalies often involve new countries, unusual login times, or missing MFA.
- Multiple failed attempts before a successful login can indicate brute-force activity.

2. AssumeRole
I reviewed how AssumeRole represents identity switching in AWS.  
Key insights:
- Normal usage involves services like EC2 or Lambda assuming roles for routine tasks.
- Suspicious patterns include unexpected users assuming roles or AssumeRole followed by privilege changes.

3. CreateAccessKey
I analyzed how access key creation appears in CloudTrail.  
Key insights:
- Access key creation is rare and usually tied to automation.
- Unexpected key creation, especially followed by high API activity, is a strong anomaly signal.

Understanding Gained Today
- IAM user behavior is highly pattern-based, making deviations easier to detect.
- Many anomalies come from timing (when), geography (where), and sequence (what happened before/after).
- CloudTrail logs provide enough context to distinguish normal vs suspicious actions without needing deep AWS configuration knowledge.
## ---------------------------------------Done for now-------------------------------------------------------------------------------

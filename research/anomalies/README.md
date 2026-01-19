## Weekly Research Notes – IAM Anomaly Behavior Analysis (Week 1) (Cheng Zhang)

This week’s research focused on understanding IAM-related CloudTrail behaviors and establishing a foundation for anomaly detection through behavior analysis and feature engineering. The work covered event semantics, normal behavior baselines, suspicious behavior patterns, and systematic methods for defining anomaly features.

IAM Event Semantics and Behavioral Interpretation
Key IAM-related CloudTrail events were analyzed, including ConsoleLogin, AssumeRole, CreateAccessKey, and permission‑related actions. These events were mapped to real-world identity behaviors such as authentication, role switching, credential creation, and privilege modification.
The analysis highlighted that IAM user behavior is generally stable and predictable, making deviations highly informative for anomaly detection.

Normal Behavior Baselines
Normal behavior patterns were defined across several dimensions:
• 	Geographic Baseline: Users typically authenticate from consistent regions; new countries indicate potential credential compromise.
• 	Time Baseline: Activity usually occurs during regular working hours; late-night or weekend activity is uncommon.
• 	Service Usage Baseline: Access to sensitive services (IAM, KMS, Organizations) is rare and meaningful when observed.
• 	Frequency Baseline: API call volume tends to be stable; sudden spikes may indicate automation or misuse.
• 	Failure Baseline: Repeated AccessDenied or failed logins often reflect probing or brute-force attempts.
• 	Sequence Baseline: Attackers frequently follow recognizable action sequences, such as reconnaissance followed by privilege escalation.
These baselines serve as the reference point for identifying anomalous deviations.

Suspicious Behavior Patterns
Several high‑risk behavioral patterns were identified:
- Reconnaissance Activity: Excessive listing of users, roles, or policies.
- Privilege Escalation Attempts: Role assumption followed by permission changes.
- Access Key Misuse: New access keys immediately used for high‑volume API calls.
- Lateral Movement: Access to multiple new services within a short time window.
- Automation Indicators: Abnormally high API call frequency or sudden behavioral spikes.
These patterns align with common stages of the attacker kill chain and provide strong signals for anomaly detection.

Feature Engineering Framework
A structured approach was established for converting behavior patterns into anomaly features.
Each feature includes:
- Feature Name
- Definition
- Security Rationale
- Trigger Logic
- Explainability
This framework ensures consistency, clarity, and usability across all anomaly features.

Example Features Defined This Week
Several anomaly features were formalized using the framework:
- NewGeoLogin: Detects logins from previously unseen geographic locations.
- UnusualLoginTime: Detects logins outside the user’s typical activity window.
- FirstTimeSensitiveServiceAccess: Detects first-time access to high‑risk services.
- ExcessiveAccessDenied: Detects repeated AccessDenied events within a short time window.
- FailedRoleAssume: Detects multiple failed AssumeRole attempts.
- ReconThenRoleAssume: Detects reconnaissance activity followed by role assumption.
- APICallSpike: Detects sudden spikes in API call volume.
- NewKeyThenHighActivity: Detects new access key creation followed by high‑volume API usage.
- CrossServiceAccess: Detects first-time access to multiple new services in a short period.

Overall Progress
The week established a strong foundation for IAM anomaly detection by:
- Interpreting IAM event semantics
- Defining normal behavior baselines
- Identifying attacker-like deviations
- Developing a scalable feature engineering methodology
- Producing a growing library of anomaly features
This foundation enables continued expansion of the anomaly feature set and supports the development of a robust detection model.

## ---------------------------------------Done for now-------------------------------------------------------------------------------

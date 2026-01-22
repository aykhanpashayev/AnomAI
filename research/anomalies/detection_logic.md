# Detection Logic for IAM Anomaly Features

This document defines detection logic for IAM-related anomaly features based on normalized CloudTrail events produced by `scripts/parse/parse_cloudtrail.py`. Each feature includes required fields, trigger logic, and an explainability template.

---

## 1. NewGeoLogin

**Category:** Geo & Time  
**Behavior:** Login from a previously unseen geographic location for a given actor.

**Required Fields:**
- `actor`
- `sourceIPAddress`
- `awsRegion`
- (Optional) historical login locations per actor

**Trigger Logic (Conceptual):**
- For each `ConsoleLogin` (or other authentication event):
  - Resolve `sourceIPAddress` to country/region (or use `awsRegion` if applicable).
  - Compare current location to actor’s historical location set.
  - If current location not in historical set → trigger `NewGeoLogin`.

**Explainability Template:**
> "User {actor} logged in from {location}, which has never appeared in their historical login activity."

---

## 2. UnusualLoginTime

**Category:** Geo & Time  
**Behavior:** Login outside the actor’s typical active time window.

**Required Fields:**
- `actor`
- `eventName` (e.g., `ConsoleLogin`)
- `eventTime`
- (Optional) historical active time window per actor

**Trigger Logic (Conceptual):**
- For each login event:
  - Convert `eventTime` to local time or consistent time zone.
  - Determine actor’s typical active window (e.g., 09:00–18:00) from historical data.
  - If current login time is outside this window → trigger `UnusualLoginTime`.

**Explainability Template:**
> "User {actor} logged in at {eventTime}, which is outside their typical login window of {baseline_window}."

---

## 3. FirstTimeSensitiveServiceAccess

**Category:** Service Access  
**Behavior:** First-time access to a sensitive AWS service.

**Required Fields:**
- `actor`
- `eventSource`
- `eventName`
- (Optional) historical service usage per actor
- Predefined sensitive service list (e.g., IAM, KMS, Organizations, CloudTrail)

**Trigger Logic (Conceptual):**
- For each event:
  - If `eventSource` is in the sensitive service list:
    - Check if actor has previously interacted with this service.
    - If no prior interaction → trigger `FirstTimeSensitiveServiceAccess`.

**Explainability Template:**
> "User {actor} accessed sensitive service {eventSource} for the first time, with no prior activity in the past {days} days."

---

## 4. ExcessiveAccessDenied

**Category:** Failure Patterns  
**Behavior:** High volume of AccessDenied errors in a short time window.

**Required Fields:**
- `actor`
- `eventName`
- `errorCode`
- `eventTime`

**Trigger Logic (Conceptual):**
- For each actor:
  - Within a sliding time window (e.g., 10 minutes):
    - Count events where `errorCode` = `AccessDenied`.
  - If `count >= 5` → trigger `ExcessiveAccessDenied`.

**Explainability Template:**
> "User {actor} received {count} AccessDenied errors within {window}, indicating possible permission probing."

---

## 5. FailedRoleAssume

**Category:** Failure Patterns  
**Behavior:** Multiple failed attempts to assume a role.

**Required Fields:**
- `actor`
- `eventName` (e.g., `AssumeRole`)
- `errorCode`
- `eventTime`

**Trigger Logic (Conceptual):**
- For each actor:
  - Within a sliding time window (e.g., 15 minutes):
    - Count events where `eventName = AssumeRole` and `errorCode` is not null (or indicates failure).
  - If `count >= 3` → trigger `FailedRoleAssume`.

**Explainability Template:**
> "User {actor} attempted to assume a role {count} times within {window}, but all attempts failed, suggesting role guessing or reconnaissance."

---

## 6. ExcessiveListingActivity

**Category:** Reconnaissance / Failure Patterns  
**Behavior:** High volume of List/Describe/Lookup operations in a short time window.

**Required Fields:**
- `actor`
- `eventName`
- `eventSource`
- `eventTime`

**Trigger Logic (Conceptual):**
- Define reconnaissance-style actions as those where `eventName` starts with `List`, `Describe`, or `Lookup`.
- For each actor:
  - Within a sliding time window (e.g., 30 seconds or 1 minute):
    - Count reconnaissance-style events.
  - If `count >= N` (e.g., 5–10) → trigger `ExcessiveListingActivity`.

**Explainability Template:**
> "User {actor} performed {count} listing or describe operations within {window}, indicating possible reconnaissance activity."

---

## 7. ReconThenRoleAssume

**Category:** Action Sequences / Kill Chain  
**Behavior:** Reconnaissance activity followed by role assumption.

**Required Fields:**
- `actor`
- `eventName`
- `eventTime`

**Trigger Logic (Conceptual):**
- For each actor:
  - Detect a cluster of reconnaissance-style events (`List*`, `Describe*`, `Lookup*`) within a short window.
  - Check if an `AssumeRole` event occurs within a follow-up window (e.g., 5–10 minutes) after recon.
  - If recon cluster + subsequent `AssumeRole` → trigger `ReconThenRoleAssume`.

**Explainability Template:**
> "User {actor} performed reconnaissance operations (e.g., {recon_examples}) followed by AssumeRole within {window}, matching a common privilege escalation pattern."

---

## 8. APICallSpike

**Category:** Frequency & Volume  
**Behavior:** Sudden spike in API call volume compared to baseline.

**Required Fields:**
- `actor`
- `eventTime`
- (Optional) baseline API call rate per actor

**Trigger Logic (Conceptual):**
- For each actor:
  - Compute baseline API call rate over a historical period (e.g., last 7 days).
  - In a short window (e.g., 1 minute), count current events.
  - If `current_rate >= 3 × baseline_rate` (or exceeds a fixed threshold) → trigger `APICallSpike`.

**Explainability Template:**
> "User {actor} generated {current_count} API calls within {window}, significantly exceeding their typical rate of {baseline_rate}."

---

## 9. NewKeyThenHighActivity

**Category:** Credential Usage / Frequency  
**Behavior:** New access key creation followed by high-volume API activity.

**Required Fields:**
- `actor`
- `eventName`
- `eventTime`
- (Optional) key identifier if available

**Trigger Logic (Conceptual):**
- Detect `CreateAccessKey` event for an actor.
- In a follow-up window (e.g., 10–30 minutes) after key creation:
  - Count API calls associated with that actor (and key if tracked).
  - If `count >= threshold` (e.g., 100 calls) → trigger `NewKeyThenHighActivity`.

**Explainability Template:**
> "User {actor} created a new access key and generated {api_count} API calls within {window}, suggesting potential automated misuse."

---

## 10. CrossServiceAccess

**Category:** Service Access / Lateral Movement  
**Behavior:** First-time access to multiple new services in a short time window.

**Required Fields:**
- `actor`
- `eventSource`
- `eventTime`
- (Optional) historical service usage per actor

**Trigger Logic (Conceptual):**
- For each actor:
  - Within a sliding window (e.g., 30 minutes):
    - Track distinct `eventSource` values that are new for this actor.
  - If `new_services_count >= 3` → trigger `CrossServiceAccess`.

**Explainability Template:**
> "User {actor} accessed {new_services_count} new services ({service_list}) within {window}, indicating possible exploration or lateral movement."

---

## 11. UnusualServiceAccess

**Category:** Service Access  
**Behavior:** Access to a service rarely or never used by the actor.

**Required Fields:**
- `actor`
- `eventSource`
- (Optional) historical service usage per actor

**Trigger Logic (Conceptual):**
- For each event:
  - Check if `eventSource` is absent or extremely rare in the actor’s historical service usage.
  - If frequency below a defined threshold → trigger `UnusualServiceAccess`.

**Explainability Template:**
> "User {actor} accessed service {eventSource}, which is rarely or never seen in their historical activity."

---

## 12. CloudTrailReconActivity (Specialization of ExcessiveListingActivity)

**Category:** Reconnaissance / Sensitive Service  
**Behavior:** High volume of CloudTrail-related read-only operations.

**Required Fields:**
- `actor`
- `eventSource` (e.g., `cloudtrail.amazonaws.com`)
- `eventName`
- `eventTime`

**Trigger Logic (Conceptual):**
- For each actor:
  - Filter events where `eventSource = cloudtrail.amazonaws.com` and `eventName` in:
    - `DescribeTrails`, `GetTrailStatus`, `ListTrails`, `ListEventDataStores`, `LookupEvents`, etc.
  - Within a short window (e.g., 30–60 seconds), count such events.
  - If `count >= N` (e.g., 5) → trigger `CloudTrailReconActivity`.

**Explainability Template:**
> "User {actor} performed {count} CloudTrail-related read-only operations ({event_names}) within {window}, indicating possible log or trail reconnaissance."

---

## Validation with Sample normalized.jsonl

- ExcessiveListingActivity → Triggered
- APICallSpike → Triggered
- CloudTrailReconActivity → Triggered
- Others → Not triggered due to missing event types

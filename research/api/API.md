# Risk Scoring API — Technical Specification(Draft)

## Overview

The Risk Scoring API analyzes AWS CloudTrail events, detects abnormal IAM behaviors, and produces a combined risk score with human‑readable explanations.  
It is designed for security dashboards, non‑technical users, and backend systems that require interpretable anomaly detection results.

The API does **not** translate logs directly.  
Instead, it performs anomaly detection through:

- Rule‑based scoring  
- Embedding similarity  
- Model‑based scoring  
- Feature‑level signal extraction  
- Human‑readable explainability  

The output is intentionally flat and UI‑friendly.

---

## Endpoint

```
POST /api/v1/risk-score
```

This endpoint accepts a CloudTrail event (raw or normalized) and returns a structured risk analysis.

---

## Request Format

The API accepts either raw CloudTrail logs or normalized events.

### Example Request

```json
{
  "event": {
    "eventName": "ConsoleLogin",
    "sourceIPAddress": "203.0.113.5",
    "userAgent": "Mozilla/5.0",
    "additionalEventData": {
      "MFAUsed": "No"
    }
  }
}
```

---

## Response Format

The API returns:

- Event metadata  
- Rule‑based score  
- Model‑based score  
- Final combined risk score  
- Triggered anomaly features  
- Human‑readable explanations  
- Optional embedding information  

### Example Response

```json
{
  "event_id": "evt-20260130-00123",
  "timestamp": "2026-01-30T20:55:00Z",
  "input_event": {
    "eventName": "ConsoleLogin",
    "sourceIPAddress": "203.0.113.5",
    "additionalEventData": { "MFAUsed": "No" }
  },
  "normalized_event": {
    "action": "ConsoleLogin",
    "ip": "203.0.113.5",
    "mfa_used": false
  },
  "rule_score": 0.72,
  "model_score": 0.84,
  "final_risk_score": 0.79,
  "triggered_features": [
    {
      "feature": "unusual_geo",
      "value": "203.0.113.5",
      "signal": 0.9
    },
    {
      "feature": "mfa_not_used",
      "value": false,
      "signal": 0.7
    }
  ],
  "embedding_vector": [0.12, 0.04, 0.88, 0.33],
  "embedding_deviation": 0.41,
  "explanation": [
    "Login originated from a country the user has never logged in from before.",
    "MFA was not used during the login attempt."
  ]
}
```

---

## JSON Schema

The full JSON Schema is located in:

```
api/schema.json
```

It defines:

- Field names  
- Data types  
- Required fields  
- Validation rules  
- Optional fields  

This schema ensures consistency across backend, UI, and testing.

---

## Field Definitions

### Metadata

| Field | Type | Description |
|-------|------|-------------|
| `event_id` | string | Unique identifier for the event |
| `timestamp` | string (ISO datetime) | When the event occurred |
| `input_event` | object | Raw CloudTrail event |
| `normalized_event` | object | Standardized event used for feature extraction |

---

### Scoring Fields

| Field | Type | Description |
|-------|------|-------------|
| `rule_score` | number (0–1) | Score from rule‑based anomaly detection |
| `model_score` | number (0–1) | Score from embedding similarity or model |
| `final_risk_score` | number (0–1) | Combined risk score |

---

### Feature‑Level Signals

`triggered_features` is an array of objects:

| Field | Type | Description |
|-------|------|-------------|
| `feature` | string | Name of the anomaly feature |
| `value` | any | Value extracted from the event |
| `signal` | number (0–1) | Contribution of this feature to the risk score |

---

### Explainability

| Field | Type | Description |
|-------|------|-------------|
| `explanation` | array of strings | Human‑readable reasons why the event is risky |

This is the primary field used by the UI.

---

### Optional Embedding Fields

| Field | Type | Description |
|-------|------|-------------|
| `embedding_vector` | array of numbers | Embedding representation of the event |
| `embedding_deviation` | number | Distance from baseline embedding |

These are used for debugging and advanced analysis.

---

## UI Integration

The UI consumes:

- `final_risk_score`  
- `rule_score`  
- `model_score`  
- `triggered_features`  
- `explanation`  
- `event_id`, `timestamp`  
- Optional: `embedding_deviation`, `input_event`, `normalized_event`

The API is designed so the UI can display risk information without understanding CloudTrail logs.

---

## Versioning

Current version: **v1.0.0**  
Future updates may include:

- Additional anomaly features  
- Expanded explainability templates  
- More detailed scoring breakdowns  

---

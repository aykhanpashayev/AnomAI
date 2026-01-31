# Risk Scoring API Documentation

This folder contains the full specification, schema, and examples for the Risk Scoring API used in the AnomAI project.  
The API analyzes AWS CloudTrail events, detects abnormal IAM behaviors, and produces a combined risk score with human‑readable explanations.

---

## Purpose

The API serves two main functions:

1. **Risk Scoring**  
   Computes rule‑based and model‑based anomaly scores, then combines them into a final risk score.

2. **Explainability**  
   Converts complex CloudTrail events into simple, human‑readable explanations suitable for non‑technical users and UI dashboards.

---

## API Overview

- **Input:** Raw or normalized AWS CloudTrail event  
- **Output:**  
  - Rule‑based score  
  - Model‑based score  
  - Final risk score  
  - Triggered anomaly features  
  - Human‑readable explanations  
  - Optional embedding information  

The API output is intentionally flat and UI‑friendly.

---

## Files in This Folder

| File | Description |
|------|-------------|
| `schema.json` | Official JSON Schema defining the API response format |
| `API.md` | Full API documentation including endpoint, request/response structure |
| `example_output.json` | Example of a complete API response for UI integration |
| `README.md` | Overview of the API folder (this file) |

---

## JSON Schema

The full JSON Schema is located in:
API/schema.json


It defines all fields, types, required properties, and validation rules.

---

## Example Output

A complete example response is provided in:
API/example_output.json


This file is used by the UI team to design the dashboard and by backend developers to ensure consistent output formatting.

---

## How the UI Uses This API

The UI consumes the following fields:

- `final_risk_score`  
- `rule_score`  
- `model_score`  
- `triggered_features`  
- `explanation`  
- `event_id`, `timestamp`  
- Optional: `embedding_deviation`, `input_event`, `normalized_event`

The API is designed so the UI can render risk information without needing to understand CloudTrail logs.

---

## Status

Version: **v1.0.0**  
Next steps:  
- Add more anomaly features  
- Expand explainability templates  
- Integrate with UI wireframes in Week 4

---

If you need help understanding the schema or integrating the API with the UI, refer to `API.md` or the example output file.

AI Model Research – Week 3
This document summarizes the initial research on AI model options that can support our anomaly detection and risk scoring pipeline. The goal is to identify models that work well with the rule‑based features, scoring logic, and API structure defined in Week 2.

1. Purpose of the Model
The model is not meant to replace our rule‑based anomaly features.
Instead, it should:
- Support risk scoring
- Help rank actors based on behavior
- Detect patterns that rules may miss
- Complement the existing detection logic
- Work with normalized CloudTrail events
The model should enhance the system, not override the logic we already built.

2. Model Requirements
Based on our pipeline, the model should:
- Handle sparse IAM activity data
- Work with per‑actor behavior
- Support anomaly scoring (0–1)
- Be explainable enough for UI/API
- Integrate with our existing feature scores
- Not require huge training datasets

3. Candidate Model Approaches
A. Embedding‑Based Similarity (Recommended Direction)
- Convert actor behavior into vectors
- Compare current behavior to historical behavior
- Score = distance between embeddings
- Works well with mixed signals (API calls, timing, frequency)
Pros:
- Flexible
- Works with small datasets
- Easy to integrate with rule‑based scores
Cons:
- Requires embedding design
- Needs tuning

B. Isolation Forest
- Classic anomaly detection
- Learns what “normal” looks like
- Flags outliers
Pros:
- Simple
- Fast
- Works with numeric features
Cons:
- Harder to explain
- Not great with categorical IAM data


C. One‑Class SVM
- Learns a boundary around normal behavior
Pros:
- Good for anomaly detection
Cons:
- Sensitive to parameters
- Not ideal for high‑dimensional IAM logs

D. Autoencoder
- Neural network that reconstructs normal behavior
- High reconstruction error = anomaly
Pros:
- Powerful
- Can learn complex patterns
Cons:
- Requires more data
- Harder to explain
- Overkill for our current dataset

4. Comparison Summary
## 4. Comparison Summary

| Model               | Works with Small Data | Explainable | Good for IAM | Integration Difficulty |
|---------------------|------------------------|-------------|--------------|-------------------------|
| Embedding Similarity | ✔                      | ✔           | ✔✔✔          | Medium                  |
| Isolation Forest     | ✔                      | △           | ✔            | Low                     |
| One-Class SVM        | △                      | △           | △            | Medium                  |
| Autoencoder          | △                      | ✘           | ✔            | High                    |

5. Recommended Direction
Embedding‑based scoring + rule‑based features
This hybrid approach fits our system best because:
- We already have strong rule‑based features
- Embeddings can capture behavior patterns rules miss
- Easy to combine embedding score with feature scores
- Works with limited data
- Explainability is manageable

6. Integration Plan
Phase 1 (This Week)
- Define embedding inputs (API frequency, event types, timing)
- Test simple similarity scoring
- Compare with rule‑based scores
Phase 2
- Build combined risk score
- Validate with sample normalized events
Phase 3
- Prepare model output for AI API
- Add explainability templates

7. Next Steps
- Finalize embedding design
- Run small‑scale tests
- Document scoring formula
- Prepare examples for the team



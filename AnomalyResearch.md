# **Anomaly Detection Research Notes (Week 1 → Week 11)**  

This document provides a complete, end‑to‑end record of the research, design, and development process behind the IAM anomaly detection system.  
It consolidates all work from Week 1 through Week 11 into a single, coherent technical narrative suitable for engineering review, academic evaluation, and long‑term project maintenance.

---

# **📌 Week 1 — IAM Behavior Foundations**

### **IAM Event Semantics**
Analyzed CloudTrail IAM events and mapped them to real‑world identity behaviors:
- Authentication (`ConsoleLogin`)  
- Role switching (`AssumeRole`)  
- Credential creation (`CreateAccessKey`)  
- Privilege modification (policy/role updates)

IAM behavior is stable and predictable, making deviations highly informative for anomaly detection.

### **Normal Behavior Baselines**
Defined baselines across:
- Geography  
- Time of day / weekday  
- Sensitive service usage  
- API frequency  
- Failure patterns  
- Behavioral sequences  

These baselines form the foundation for anomaly feature engineering.

---

# **📌 Week 2 — Normalization Pipeline & Event Categorization**

### **Normalization Pipeline**
Designed a unified structure for CloudTrail → normalized events:
- Consistent actor/resource fields  
- Unified timestamps  
- Standardized action semantics  
- Cleaned and structured event categories  

### **Event Categorization**
Created a 4‑class taxonomy:
- Recon  
- Write  
- Privilege  
- Timing  

This enables consistent feature extraction and scoring.

---

# **📌 Week 3 — Rule‑Based Anomaly Features**

### **Feature Set Completed**
Implemented all rule‑based anomaly features:
- Recon anomalies  
- Write anomalies  
- Privilege anomalies  
- Timing anomalies  
- Burst anomalies  

### **Scoring & Explainability**
Each feature includes:
- A numeric score  
- Trigger conditions  
- Human‑readable explanation  

### **Rule Score**
All features combine into a single `rule_score`.

---

# **📌 Week 4 — Embedding Design & Model Research**

### **Embedding (Behavior Vector)**
Defined embedding dimensions:
- API type distribution  
- Recon/Write/Privilege ratios  
- Time‑based behavior  
- Activity intensity  
- Burst score  

### **Model Research**
Evaluated:
- Embedding similarity  
- Isolation Forest  
- One‑Class SVM  
- Autoencoder  

### **Final Model Choice**
Selected **Hybrid = Embedding Similarity + Rule‑Based Scoring** for:
- Interpretability  
- Stability  
- MVP simplicity  
- Strong alignment with CloudTrail behavior patterns  

---

# **📌 Week 5 — Final Risk Score & End‑to‑End Pipeline**

### **Final Risk Score Formula**
```
final_risk_score = 0.6 * rule_score + 0.4 * model_score
```

### **End‑to‑End Pipeline Completed**
1. CloudTrail event  
2. Normalization  
3. Feature extraction  
4. Embedding  
5. Model score  
6. Rule score  
7. Final risk score  
8. API response  

This was the first fully functional version of the system.

---

# **📌 Week 6 — API Specification & Incident Schema**

### **API Specification Finalized**
Defined:
- Input schema  
- Output schema  
- Triggered features  
- Explanation structure  
- Error format  
- End‑to‑end example  

### **Incident Schema Finalized**
UI‑ready fields:
- Actor  
- Final risk score  
- Severity  
- Triggered features  
- Explanation  
- Optional raw events  

This became the contract between backend and UI.

---

# **📌 Week 7 — Documentation & Validation**

### **MVP Documentation Completed**
Documented:
- Incident schema  
- Scoring logic  
- Explanation logic  
- Field definitions  
- Example incidents  

### **End‑to‑End Validation**
Confirmed:
- Detection output aligns with schema  
- Explanation logic is stable  
- Scoring is consistent  

Backend is fully ready for UI integration.

---

# **📌 Week 8 — Schema Polishing & UI Requirements Alignment**

### **Incident Schema Refinement**
Improved:
- Field naming consistency  
- Explanation formatting  
- Triggered feature enumeration  
- Severity mapping  

### **Example Incidents Added**
Provided multiple realistic JSON examples for UI and documentation teams.

### **API → UI Mapping Finalized**
Defined:
- Dashboard fields  
- Chatbot fields  
- Optional vs required fields  

---

# **📌 Week 9 — Robustness & Error Handling**

### **Pipeline Stress Testing**
Validated:
- Rare IAM actions  
- Missing fields  
- High‑burst sequences  
- Edge cases  

### **Error Handling Rules**
Defined behavior for:
- Invalid schema  
- Missing actor  
- Unsupported event types  
- Empty event lists  

### **Stability Improvements**
Ensured:
- Explanations always return meaningful text  
- Triggered features are deterministic  
- Final risk score is always bounded  

---

# **📌 Week 10 — Documentation Freeze & System Consolidation**

### **MVP Documentation Freeze**
Completed:
- Scoring logic  
- Explanation logic  
- Incident schema  
- API contract  
- Field mapping tables  
- Example outputs  

### **Research Notes Consolidation**
Merged all research into a unified technical narrative.

### **UI Integration Prep**
Provided:
- Example incidents  
- Field descriptions  
- Severity mapping  
- Triggered feature definitions  

---

# **📌 Week 11 — UI Integration Support & Final Adjustments**

### **Backend Fully Complete**
All backend components are stable:
- Schema  
- Scoring  
- Explanation  
- API  
- Documentation  

### **UI Integration Support**
Provided:
- Clarifications  
- Example incidents  
- Field mappings  
- Explanation formatting guidance  

### **Final Refinements**
Adjusted:
- Explanation phrasing  
- Triggered feature naming  
- Severity thresholds  

Backend is 100% ready; only UI implementation remains.

---

# **📌 Overall System Summary (Week 1 → Week 11)**

By Week 11, the system includes:

### **✔ Complete normalization pipeline**  
### **✔ Full anomaly feature set**  
### **✔ Hybrid scoring model**  
### **✔ Embedding‑based behavior modeling**  
### **✔ Final risk scoring formula**  
### **✔ Fully defined API & incident schema**  
### **✔ End‑to‑end functional pipeline**  
### **✔ Complete MVP documentation**  
### **✔ Backend fully ready for UI integration**

This README serves as the authoritative research record for the anomaly detection system.

---

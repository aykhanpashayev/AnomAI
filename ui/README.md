# AnomAI Dashboard

Streamlit dashboard for visualizing AWS IAM anomaly incidents detected by
the AnomAI pipeline. Includes a security-focused AI assistant powered by
Google Gemini.

---

## What it does

The dashboard connects to the Flask API (`scripts/pipeline/anomai_incidents_api.py`)
and presents live incident data in two views:

**Dashboard** — filters, summary metrics, charts, and a detailed incident panel.

**AI Chatbot** — a Gemini-powered assistant grounded with the live incident
data. Explains incidents in plain English, gives step-by-step remediation
guidance, and refuses to answer anything outside the loaded incident data.

---

## Setup

### 1. Install dependencies

```bash
cd ui/
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp ../.env.example .env
```

Edit `.env` and set:

```
GOOGLE_API_KEY=your-gemini-api-key-here
ANOMAI_API_URL=http://localhost:8000     # default, change if API runs elsewhere
```

### 3. Make sure the Flask API is running

```bash
# In a separate terminal
cd scripts/pipeline/
python anomai_incidents_api.py
```

### 4. Run the dashboard

```bash
streamlit run app.py
```

Opens at `http://localhost:8501`

---

## Dashboard view

### Filters (left panel)

Filters are built dynamically from the live incident data — only actors,
severities, and incident types that actually exist in the current dataset
appear as options. All filters default to selected (show everything).

| Filter | Options |
|---|---|
| Severity | High / Medium / Low |
| Actor | Every actor present in the loaded incidents |
| Incident Type | Every type present in the loaded incidents |

Click **Reset Filters** to restore all defaults.

### Metric cards

| Metric | Description |
|---|---|
| Total Incidents | Count of incidents matching current filters |
| Last Two Weeks | Incidents with `timestamp_start` within the last 14 days |
| High Severity | Count of high-severity incidents in the filtered set |
| Top Actor | Actor with the highest total event count across all incidents |

### Charts

| Chart | Description |
|---|---|
| Incident Severity | Pie chart — distribution of High / Medium / Low |
| Incident Types | Bar chart — count per detector type |
| Incidents by Month | Line chart — incident volume over time, sorted chronologically |

### Recent Incidents table

Sortable table showing all filtered incidents. Severity is colour-coded:
red (High), orange (Medium), green (Low).

### Incident Details panel

Select any incident from the dropdown to see:
- Incident type and severity badge
- Actor(s) involved with event counts
- Risk score (0–100)
- Summary of what happened
- Recommendation — what to do about it
- Advanced details — event count, timestamps, top AWS API calls, regions

---

## Chatbot view

The filter panel is hidden on this view — the chatbot always has access to
the full unfiltered incident list so it can answer questions about any incident.

### How it works

On session start, all incidents are fetched from the API and converted into
a plain-English context block. This is injected into the Gemini system prompt
so the model can only answer based on what's actually in your environment.

### Quick questions

Six pre-written questions appear before the first interaction:

- Which incident should I worry about most?
- What is an IAM spike and is mine serious?
- Which actors show up the most?
- Explain the highest risk incident simply
- What exact steps should I take right now?
- Summarize all incidents for me

The quick questions panel disappears after the first message and does not
reappear until **Clear Chat** is clicked.

### What the chatbot will and won't do

**Will do:**
- Explain any incident in plain English
- Give numbered action steps for remediation
- Summarize all incidents or compare severities
- Explain what an incident type means in the context of your data

**Will not do:**
- Answer general cybersecurity questions unrelated to the loaded incidents
- Make up incident details not present in the data
- Discuss other cloud providers or unrelated tools

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `ANOMAI_API_URL` | `http://localhost:8000` | Base URL of the Flask API |
| `GOOGLE_API_KEY` | — | Gemini API key (required for the chatbot) |

Both can be set in `.env` or in `.streamlit/secrets.toml` for Streamlit Cloud deployment.

---

## Data refresh

Incident data is cached for **60 seconds** (`@st.cache_data(ttl=60)`).
The dashboard refreshes automatically on the next page interaction after
the cache expires. To force an immediate refresh, reload the browser tab.

---

## Dependencies

```
streamlit
plotly
pandas
requests
google-genai
python-dotenv
```

See `requirements.txt` for pinned versions.
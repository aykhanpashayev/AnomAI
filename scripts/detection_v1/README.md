# Detection Pipeline v1 (Archived)

This is the original two-script detection pipeline, kept for reference.
It has been superseded by the unified pipeline in `scripts/pipeline/`.

---

## Why it was replaced

The original pipeline used local JSON files as intermediate state:

```
run_detection.py  →  out/incidents.json
                              │
convert_incidents_to_api.py  →  out/incidents_api.json
                                          │
serve_incidents_api_flask.py  ←  reads file from disk
```

This worked but had two problems — it required manual runs in sequence,
and the Flask API depended on a local file rather than a live data source.

The unified pipeline in `scripts/pipeline/` removes both intermediate
files and writes directly to DynamoDB, which the API then reads in real time.

---

## Files

| File | Description |
|---|---|
| `run_detection.py` | Scans `anomai_events` and writes raw incidents to `out/incidents.json` |
| `convert_incidents_to_api.py` | Reads `out/incidents.json`, converts to API schema, writes `out/incidents_api.json` |
| `serve_incidents_api_flask.py` | Flask API that reads from `out/incidents_api.json` |

---

## Running (for reference only)

```bash
# Step 1 — detect
python3 run_detection.py

# Step 2 — convert
python3 convert_incidents_to_api.py

# Step 3 — serve
python3 serve_incidents_api_flask.py
```

---

## Current pipeline

Use `scripts/pipeline/` instead:

```bash
cd scripts/pipeline/

# Detect + convert + write to DynamoDB in one command
python anomai_pipeline.py

# Serve the API
python anomai_incidents_api.py
```

See `scripts/pipeline/README.md` for full documentation.
# Install dependency (boto3 usually already present)
pip install boto3

# Basic run (uses defaults: us-east-2, anomai_events → anomai_incidents_api, 30-day lookback)
python anomai_pipeline.py

# Explicit region + tables
python anomai_pipeline.py --region us-east-2 \
  --source-table anomai_events \
  --dest-table anomai_incidents_api

# Custom lookback + state file
python anomai_pipeline.py --lookback-days 14 --state-path /tmp/anomai_state.json

# Dry run (full pipeline, no DynamoDB writes)
python anomai_pipeline.py --dry-run

# Verbose debug output
python anomai_pipeline.py --debug

# Typical cron/Lambda invocation
python anomai_pipeline.py --region us-east-2 --lookback-days 30
import os
import re
from datetime import datetime, timedelta, timezone

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

# -----------------------------------
# Configuration
# -----------------------------------
API_BASE_URL = (
    os.environ.get("ANOMAI_API_URL")
    or st.secrets.get("ANOMAI_API_URL", "http://localhost:8000")
)

GEMINI_API_KEY = (
    os.environ.get("GOOGLE_API_KEY")
    or st.secrets.get("GOOGLE_API_KEY", "")
)

st.set_page_config(
    page_title="AnomAI Security Dashboard",
    layout="wide"
)

# -----------------------------------
# CSS
# -----------------------------------
st.markdown("""
    <style>
    [data-testid="stVerticalBlockBorderWrapper"] {
        border: 1px solid rgba(128, 128, 128, 0.25) !important;
        border-radius: 8px !important;
        padding: 15px !important;
        box-shadow: none !important;
    }

    [data-testid="stExpander"] {
        background-color: transparent !important;
        border: none !important;
    }

    h1 {
        margin-top: 0px !important;
        line-height: 1.2 !important;
        font-size: 42px !important;
        text-align: center;
    }
    </style>
""", unsafe_allow_html=True)

# -----------------------------------
# API Loading
# -----------------------------------
@st.cache_data(ttl=60)
def load_incidents():
    try:
        resp = requests.get(f"{API_BASE_URL}/incidents", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        incidents = data.get("incidents", [])

        if not isinstance(incidents, list):
            raise ValueError("API field 'incidents' is not a list")

        return {
            "generated_at": data.get("generated_at"),
            "incident_count": data.get("count", len(incidents)),
            "new_incident_count": sum(1 for i in incidents if i.get("is_new")),
            "incidents": incidents,
        }

    except requests.exceptions.ConnectionError:
        st.error(f"⚠️ Could not connect to API at **{API_BASE_URL}**. Is Flask running?")
    except requests.exceptions.Timeout:
        st.error(f"⚠️ API request timed out at **{API_BASE_URL}**.")
    except requests.exceptions.HTTPError as e:
        st.error(f"⚠️ API returned an HTTP error: {e}")
    except Exception as e:
        st.error(f"⚠️ Failed to load incidents: {e}")

    return {
        "generated_at": None,
        "incident_count": 0,
        "new_incident_count": 0,
        "incidents": [],
    }

# -----------------------------------
# Helpers
# -----------------------------------
def parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None

def format_dt_short(value):
    dt = parse_dt(value)
    if not dt:
        return "Unknown"
    return dt.astimezone(timezone.utc).strftime("%b %d %Y")

def get_first_seen(inc):
    return inc.get("timestamp_start") or inc.get("first_seen") or ""

def get_last_seen(inc):
    return inc.get("timestamp_end") or inc.get("last_seen") or ""

def get_age(inc):
    age_s = inc.get("age_seconds")
    if age_s is None:
        return "Unknown"

    try:
        age_s = int(age_s)
    except Exception:
        return "Unknown"

    if age_s < 60:
        return f"{age_s}s ago"
    if age_s < 3600:
        return f"{age_s // 60}m ago"
    if age_s < 86400:
        return f"{age_s // 3600}h ago"

    days = age_s // 86400
    return "yesterday" if days == 1 else f"{days}d ago"

def get_incident_type_raw(inc):
    return str(inc.get("incident_type", "")).strip()

def normalize_incident_type(api_type):
    api_type_map = {
        "AccessDeniedSpike": "access_denied_spike",
        "SensitiveIAMSpike": "suspicious_iam_activity",
        "APIBurst": "api_burst",
        "NewRegion": "new_region_activity",
        "SigninFailureSpike": "signin_failure_spike",
        "InvalidAMISpike": "invalid_ami_spike",
    }
    return api_type_map.get(api_type, str(api_type).strip().lower())

def format_incident_type(type_value):
    type_map = {
        "access_denied_spike": "Access Denied Spike",
        "suspicious_iam_activity": "Suspicious IAM Activity",
        "api_burst": "API Burst",
        "new_region_activity": "New Region Activity",
        "signin_failure_spike": "Sign-in Failure Spike",
        "invalid_ami_spike": "Invalid AMI Spike",
    }

    normalized = normalize_incident_type(type_value)
    return type_map.get(normalized, str(type_value).replace("_", " ").title())

def get_recommendation(inc):
    return (
        (inc.get("explanation") or {}).get("recommendation")
        or inc.get("recommendation")
        or "No recommendation available."
    )

def get_summary(inc):
    return (
        (inc.get("explanation") or {}).get("summary")
        or inc.get("summary")
        or "No summary available."
    )

def get_risk_score(inc):
    score = inc.get("final_risk_score")
    if score is None:
        score = inc.get("rule_score")
    if score is None:
        return 0
    try:
        return int(score)
    except Exception:
        return 0

def get_display_severity(inc):
    return str(inc.get("severity", "low")).capitalize()

def slugify(value):
    return re.sub(r"[^a-zA-Z0-9_]+", "_", str(value).strip().lower()).strip("_")

def get_actor_counts(inc):
    evidence = inc.get("evidence") or {}
    actor_counts = inc.get("by_actor") or evidence.get("by_actor") or {}

    cleaned = {}
    if isinstance(actor_counts, dict):
        for actor, count in actor_counts.items():
            actor_name = str(actor).strip()
            if not actor_name:
                continue
            try:
                cleaned[actor_name] = int(count)
            except Exception:
                cleaned[actor_name] = 0

    if cleaned:
        return cleaned

    fallback_actor = str(inc.get("actor", "")).strip()
    if fallback_actor:
        return {fallback_actor: int(evidence.get("count", 1) or 1)}

    peak_actor = str(evidence.get("peak_actor", "")).strip()
    if peak_actor:
        return {peak_actor: int(evidence.get("peak_count", 1) or 1)}

    return {}

def get_actor_names(inc):
    actor_counts = get_actor_counts(inc)
    if actor_counts:
        return list(actor_counts.keys())

    fallback_actor = str(inc.get("actor", "")).strip()
    return [fallback_actor] if fallback_actor else ["Unknown"]

def get_actor_display(inc):
    names = [name for name in get_actor_names(inc) if name and name != "Unknown"]
    if names:
        return ", ".join(names)
    return "Unknown"

def get_actor_counts_display(inc):
    actor_counts = get_actor_counts(inc)
    if actor_counts:
        return ", ".join(f"{actor} ({count})" for actor, count in actor_counts.items())
    return get_actor_display(inc)

def get_top_actor_totals(incidents):
    totals = {}
    for inc in incidents:
        for actor, count in get_actor_counts(inc).items():
            totals[actor] = totals.get(actor, 0) + count
    return totals

def build_filter_options(incidents):
    severity_order = {"High": 0, "Medium": 1, "Low": 2}

    severity_options = sorted(
        {get_display_severity(inc) for inc in incidents if get_display_severity(inc)},
        key=lambda s: severity_order.get(s, 999)
    )

    actor_options = sorted(
        {actor for inc in incidents for actor in get_actor_names(inc) if actor and actor != "Unknown"},
        key=lambda s: s.lower()
    )

    incident_type_options = sorted(
        {format_incident_type(get_incident_type_raw(inc)) for inc in incidents if get_incident_type_raw(inc)},
        key=lambda s: s.lower()
    )

    return severity_options, actor_options, incident_type_options

def ensure_filter_state(prefix, options):
    for option in options:
        key = f"{prefix}_{slugify(option)}"
        if key not in st.session_state:
            st.session_state[key] = True

def reset_filter_state():
    for key in st.session_state.get("filter_keys", []):
        st.session_state[key] = True

def incident_sort_key(inc):
    dt = parse_dt(get_first_seen(inc))
    return dt if dt else datetime.min.replace(tzinfo=timezone.utc)

# -----------------------------------
# Gemini helpers
# -----------------------------------
SYSTEM_PROMPT = """You are AnomAI Assistant — a specialist in AWS IAM anomaly detection.

You help users understand ONLY the incidents currently loaded into this dashboard.

Rules:
- Only discuss the incidents provided in the system context.
- Do not invent any facts, actors, times, or scores.
- If asked about unrelated cybersecurity topics, politely say you can only help with the incidents detected by AnomAI.
- Explain things simply, in plain English.
- Use numbered action steps when giving advice.
- Tie your answer to specific incidents whenever possible.
"""

def build_incident_context(incidents):
    if not incidents:
        return "No incidents are currently available."

    high_count = sum(1 for i in incidents if str(i.get("severity", "")).lower() == "high")
    medium_count = sum(1 for i in incidents if str(i.get("severity", "")).lower() == "medium")
    low_count = sum(1 for i in incidents if str(i.get("severity", "")).lower() == "low")

    actor_totals = get_top_actor_totals(incidents)
    top_actor = max(actor_totals, key=actor_totals.get) if actor_totals else "unknown"

    lines = [
        "=== ENVIRONMENT SUMMARY ===",
        f"Total incidents: {len(incidents)}",
        f"High severity: {high_count}",
        f"Medium severity: {medium_count}",
        f"Low severity: {low_count}",
        f"Top actor by activity: {top_actor}",
        "",
        "=== INCIDENT DETAILS ===",
    ]

    for idx, inc in enumerate(incidents, start=1):
        incident_type = format_incident_type(get_incident_type_raw(inc))
        severity = get_display_severity(inc).upper()
        risk_score = get_risk_score(inc)
        actors = get_actor_display(inc)
        first_seen = get_first_seen(inc)
        last_seen = get_last_seen(inc)
        age = get_age(inc)
        summary = get_summary(inc)
        recommendation = get_recommendation(inc)
        evidence = inc.get("evidence") or {}
        top_events = evidence.get("top_event_names") or []
        count = evidence.get("count", 0)

        lines.extend([
            f"--- Incident {idx} ---",
            f"ID: {inc.get('incident_id', 'Unknown')}",
            f"Type: {incident_type}",
            f"Severity: {severity}",
            f"Risk score: {risk_score}/100",
            f"Actors involved: {actors}",
            f"Start: {first_seen}",
            f"End: {last_seen}",
            f"Age: {age}",
            f"Summary: {summary}",
            f"Recommendation: {recommendation}",
            f"Event count: {count}",
            f"Top events: {', '.join(top_events[:5]) if top_events else 'None'}",
            "",
        ])

    return "\n".join(lines)

def get_gemini_client():
    if "gemini_client" not in st.session_state:
        if not GEMINI_API_KEY:
            return None
        st.session_state.gemini_client = genai.Client(api_key=GEMINI_API_KEY)
    return st.session_state.gemini_client

def get_or_create_chat(incident_context):
    client = get_gemini_client()
    if client is None:
        return None

    if "gemini_chat" not in st.session_state:
        st.session_state.gemini_chat = client.chats.create(
            model="gemini-3-flash-preview",
            config=types.GenerateContentConfig(
                system_instruction=f"{SYSTEM_PROMPT}\n\nCURRENT INCIDENT DATA:\n{incident_context}",
                max_output_tokens=1024,
                temperature=0.4,
            ),
        )
    return st.session_state.gemini_chat

# -----------------------------------
# Load data
# -----------------------------------
incidents_data = load_incidents()
raw_incidents = incidents_data.get("incidents", [])
generated_at = incidents_data.get("generated_at")

severity_options, actor_options, incident_type_options = build_filter_options(raw_incidents)

ensure_filter_state("severity", severity_options)
ensure_filter_state("actor", actor_options)
ensure_filter_state("type", incident_type_options)

st.session_state["filter_keys"] = (
    [f"severity_{slugify(severity)}" for severity in severity_options]
    + [f"actor_{slugify(actor)}" for actor in actor_options]
    + [f"type_{slugify(incident_type)}" for incident_type in incident_type_options]
)

# -----------------------------------
# Navigation
# -----------------------------------
col_nav, col_title, col_spacer = st.columns([1.7, 5.7, 1.5])

with col_nav:
    with st.container(border=True):
        page_selection = st.radio(
            "Navigation",
            options=["🔴 Dashboard", "🤖 Chatbot"],
            horizontal=True,
            label_visibility="collapsed"
        )

with col_title:
    st.markdown("<h1 style='text-align: center;'>AnomAI Security Overview</h1>", unsafe_allow_html=True)

st.divider()

if page_selection == "🔴 Dashboard":
    col_filter, col_display = st.columns([1.2, 5])
else:
    col_display = st.container()

# -----------------------------------
# Dynamic Filters from API
# -----------------------------------
selected_severity = list(severity_options)
selected_actors = list(actor_options)
selected_types = list(incident_type_options)

if page_selection == "🔴 Dashboard":
    with col_filter:
        with st.container(border=True):
            st.markdown("### Filters")

            with st.expander("Severity", expanded=True):
                if severity_options:
                    for severity in severity_options:
                        st.checkbox(severity, key=f"severity_{slugify(severity)}")

                    selected_severity = [
                        severity for severity in severity_options
                        if st.session_state.get(f"severity_{slugify(severity)}", False)
                    ]
                else:
                    st.caption("No severity data available.")

            st.divider()

            with st.expander("Actor", expanded=True):
                if actor_options:
                    for actor in actor_options:
                        st.checkbox(actor, key=f"actor_{slugify(actor)}")

                    selected_actors = [
                        actor for actor in actor_options
                        if st.session_state.get(f"actor_{slugify(actor)}", False)
                    ]
                else:
                    st.caption("No actor data available.")

            st.divider()

            with st.expander("Incident Type", expanded=True):
                if incident_type_options:
                    for incident_type in incident_type_options:
                        st.checkbox(incident_type, key=f"type_{slugify(incident_type)}")

                    selected_types = [
                        incident_type for incident_type in incident_type_options
                        if st.session_state.get(f"type_{slugify(incident_type)}", False)
                    ]
                else:
                    st.caption("No incident type data available.")

            st.button(
                "Reset Filters",
                use_container_width=True,
                on_click=reset_filter_state
            )

# -----------------------------------
# Apply Filters
# -----------------------------------
def incident_matches_filters(inc):
    severity_value = get_display_severity(inc)
    type_value = format_incident_type(get_incident_type_raw(inc))
    actors_in_incident = set(get_actor_names(inc))

    severity_match = severity_value in selected_severity if severity_options else True
    type_match = type_value in selected_types if incident_type_options else True
    actor_match = bool(actors_in_incident.intersection(selected_actors)) if actor_options else True

    return severity_match and type_match and actor_match

if page_selection == "🔴 Dashboard":
    filtered_incidents = [inc for inc in raw_incidents if incident_matches_filters(inc)]
else:
    filtered_incidents = raw_incidents

filtered_incidents = sorted(filtered_incidents, key=incident_sort_key, reverse=True)

# -----------------------------------
# Metrics
# -----------------------------------
total_incidents_count = len(filtered_incidents)

two_weeks_ago = datetime.now(timezone.utc) - timedelta(days=14)
last_two_weeks_count = 0

for inc in filtered_incidents:
    dt = parse_dt(get_first_seen(inc))
    if dt and dt >= two_weeks_ago:
        last_two_weeks_count += 1

high_severity_count = sum(
    1 for inc in filtered_incidents
    if str(inc.get("severity", "")).lower() == "high"
)

actor_totals = get_top_actor_totals(filtered_incidents)
top_actor_name = max(actor_totals, key=actor_totals.get) if actor_totals else "--"

# -----------------------------------
# Transform for UI
# -----------------------------------
table_rows = []
incident_details = []

for inc in filtered_incidents:
    severity_val = get_display_severity(inc)
    actor_label = get_actor_display(inc)
    incident_type_label = format_incident_type(get_incident_type_raw(inc))
    risk_score = get_risk_score(inc)
    first_seen = get_first_seen(inc)
    date_str = format_dt_short(first_seen)

    table_rows.append({
        "Severity": severity_val,
        "Incident Type": incident_type_label,
        "Actor(s)": actor_label,
        "Risk Score": risk_score,
        "Date": date_str,
    })

    evidence = inc.get("evidence") or {}
    top_events = evidence.get("top_event_names") or []
    regions = evidence.get("by_region", {})

    adv_details = [
        f"Incident ID: {inc.get('incident_id', 'Unknown')}",
        f"Count: {evidence.get('count', 0)} events",
        f"First seen: {first_seen or 'Unknown'}",
        f"Last seen: {get_last_seen(inc) or 'Unknown'}",
        f"Age: {get_age(inc)}",
        f"Actors involved: {get_actor_counts_display(inc)}",
    ]

    if top_events:
        adv_details.append(f"Top Events: {', '.join(top_events[:5])}")
    if regions:
        adv_details.append(f"Regions: {', '.join(regions.keys())}")

    incident_details.append({
        "Dropdown Label": f"{incident_type_label} | {actor_label} | {date_str}",
        "Incident Name": incident_type_label,
        "Severity": severity_val,
        "Actors": actor_label,
        "Risk Score": risk_score,
        "Summary": get_summary(inc),
        "Recommendation": get_recommendation(inc),
        "Advanced Details": adv_details,
    })

if table_rows:
    incident_table_data = pd.DataFrame(table_rows)
else:
    incident_table_data = pd.DataFrame(columns=["Severity", "Incident Type", "Actor(s)", "Risk Score", "Date"])

# -----------------------------------
# Main display
# -----------------------------------
with col_display:
    with st.container(border=True):

        if page_selection == "🔴 Dashboard":
            st.subheader("Dashboard View")

            if generated_at:
                st.caption(f"API generated at: {generated_at}")

            metric_1, metric_2, metric_3, metric_4 = st.columns(4)

            with metric_1:
                with st.container(border=True):
                    st.markdown(
                        f"""
                        <div style='text-align: center;'>
                            <div style='font-size: 20px; font-weight: 600;'>Total Incidents</div>
                            <div style='font-size: 42px; font-weight: 700;'>{total_incidents_count}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

            with metric_2:
                with st.container(border=True):
                    st.markdown(
                        f"""
                        <div style='text-align: center;'>
                            <div style='font-size: 20px; font-weight: 600;'>Last Two Weeks Incidents</div>
                            <div style='font-size: 42px; font-weight: 700;'>{last_two_weeks_count}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

            with metric_3:
                with st.container(border=True):
                    st.markdown(
                        f"""
                        <div style='text-align: center;'>
                            <div style='font-size: 20px; font-weight: 600;'>High Severity</div>
                            <div style='font-size: 42px; font-weight: 700;'>{high_severity_count}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

            with metric_4:
                with st.container(border=True):
                    st.markdown(
                        f"""
                        <div style='text-align: center;'>
                            <div style='font-size: 20px; font-weight: 600;'>Top Actor</div>
                            <div style='font-size: 30px; font-weight: 700; margin-top: 10px;'>{top_actor_name}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

            st.write("")

            chart_col1, chart_col2, chart_col3 = st.columns(3)

            with chart_col1:
                with st.container(border=True):
                    st.markdown("### Incident Severity")
                    if not incident_table_data.empty:
                        severity_data = incident_table_data["Severity"].value_counts().reset_index()
                        severity_data.columns = ["Severity", "Count"]
                    else:
                        severity_data = pd.DataFrame({"Severity": ["No Data"], "Count": [1]})

                    fig = px.pie(
                        severity_data,
                        names="Severity",
                        values="Count",
                        color="Severity",
                        color_discrete_map={
                            "High": "#e74c3c",
                            "Medium": "#f1c40f",
                            "Low": "#95a5a6",
                            "No Data": "#bdc3c7",
                        }
                    )
                    fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=250)
                    st.plotly_chart(fig, use_container_width=True, theme="streamlit", key="severity_pie_chart")

            with chart_col2:
                with st.container(border=True):
                    st.markdown("### Incident Types")
                    if not incident_table_data.empty:
                        incident_type_data = incident_table_data["Incident Type"].value_counts().reset_index()
                        incident_type_data.columns = ["Incident Type", "Count"]
                    else:
                        incident_type_data = pd.DataFrame({"Incident Type": ["No Data"], "Count": [0]})

                    fig_bar = px.bar(incident_type_data, x="Incident Type", y="Count", color="Incident Type")
                    fig_bar.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=250, showlegend=False)
                    st.plotly_chart(fig_bar, use_container_width=True, theme="streamlit", key="incident_type_bar_chart")

            with chart_col3:
                with st.container(border=True):
                    st.markdown("### Incidents by Month")

                    month_values = []
                    for inc in filtered_incidents:
                        dt = parse_dt(get_first_seen(inc))
                        if dt:
                            month_values.append(dt.strftime("%b %Y"))

                    if month_values:
                        incident_time_data = pd.Series(month_values).value_counts().reset_index()
                        incident_time_data.columns = ["Month", "Count"]
                        incident_time_data["Month_dt"] = pd.to_datetime(incident_time_data["Month"], format="%b %Y", errors="coerce")
                        incident_time_data = incident_time_data.sort_values("Month_dt").drop(columns=["Month_dt"])
                    else:
                        incident_time_data = pd.DataFrame({"Month": ["No Data"], "Count": [0]})

                    fig_line = px.line(incident_time_data, x="Month", y="Count", markers=True)
                    fig_line.update_layout(
                        xaxis=dict(type="category"),
                        margin=dict(l=0, r=0, t=10, b=0),
                        height=250,
                        xaxis_title=None,
                        yaxis_title=None
                    )
                    st.plotly_chart(fig_line, use_container_width=True, theme="streamlit", key="incidents_over_time_line_chart")

            st.write("")

            bottom_left, bottom_right = st.columns([2.2, 1.3])

            with bottom_left:
                with st.container(border=True):
                    st.markdown("### Recent Incidents")
                    if incident_table_data.empty:
                        st.info("No incidents match the current filters.")
                    else:
                        styled_table = incident_table_data.style.map(
                            lambda x: (
                                "color:#e74c3c;font-weight:bold" if x == "High"
                                else "color:#f39c12;font-weight:bold" if x == "Medium"
                                else "color:#27ae60;font-weight:bold" if x == "Low"
                                else ""
                            ),
                            subset=["Severity"]
                        )
                        st.dataframe(styled_table, use_container_width=True, hide_index=True)

            with bottom_right:
                with st.container(border=True):
                    st.markdown("### Incident Details")

                    if incident_details:
                        selected_label = st.selectbox(
                            "Select Incident",
                            [i["Dropdown Label"] for i in incident_details],
                            label_visibility="collapsed"
                        )
                        incident_detail_data = next(
                            i for i in incident_details if i["Dropdown Label"] == selected_label
                        )

                        if incident_detail_data["Severity"] == "High":
                            severity_color = "#e74c3c"
                        elif incident_detail_data["Severity"] == "Medium":
                            severity_color = "#f39c12"
                        else:
                            severity_color = "#27ae60"

                        st.markdown(
                            f"<p style='font-size:24px; font-weight:600; margin-bottom:6px;'>{incident_detail_data['Incident Name']}</p>",
                            unsafe_allow_html=True
                        )
                        st.markdown(
                            f"""
                            <p style='font-size:18px; margin-bottom:2px;'>
                                <strong>Severity:</strong>
                                <span style='background-color:{severity_color}; color:white; padding:2px 10px; border-radius:6px; font-weight:600;'>
                                    {incident_detail_data["Severity"]}
                                </span>
                            </p>
                            """,
                            unsafe_allow_html=True
                        )
                        st.markdown(
                            f"<p style='font-size:18px; margin-bottom:2px;'><strong>Actor(s):</strong> <em>{incident_detail_data['Actors']}</em></p>",
                            unsafe_allow_html=True
                        )
                        st.markdown(
                            f"<p style='font-size:18px; margin-bottom:6px;'><strong>Risk Score:</strong> {incident_detail_data['Risk Score']}</p>",
                            unsafe_allow_html=True
                        )
                        st.divider()
                        st.markdown("<h3 style='margin-bottom:6px;'>Summary</h3>", unsafe_allow_html=True)
                        st.markdown(
                            f"<p style='font-size:18px; line-height:1.5; margin-top:0; margin-bottom:8px;'>{incident_detail_data['Summary']}</p>",
                            unsafe_allow_html=True
                        )
                        st.divider()
                        st.markdown("<h3 style='margin-bottom:6px;'>Recommendation</h3>", unsafe_allow_html=True)
                        st.markdown(
                            f"<p style='font-size:18px; line-height:1.5; margin-top:0; margin-bottom:8px;'>{incident_detail_data['Recommendation']}</p>",
                            unsafe_allow_html=True
                        )
                        st.divider()
                        st.markdown("<h3 style='margin-bottom:6px;'>Advanced Details</h3>", unsafe_allow_html=True)
                        for item in incident_detail_data["Advanced Details"]:
                            st.markdown(
                                f"<p style='font-size:18px; margin-top:0; margin-bottom:4px;'>• {item}</p>",
                                unsafe_allow_html=True
                            )
                    else:
                        st.info("No incidents match the current filters.")

        elif page_selection == "🤖 Chatbot":
            chat_header_col, chat_clear_col = st.columns([5, 1])

            with chat_header_col:
                st.subheader("Security Assistant")
                st.markdown(
                    "<p style='font-size:16px; margin-top:-10px; margin-bottom:10px;'>"
                    "Ask anything about your incidents in plain English — no technical knowledge needed.</p>",
                    unsafe_allow_html=True
                )

            with chat_clear_col:
                st.write("")
                if st.button("Clear Chat", use_container_width=True):
                    st.session_state.pop("messages", None)
                    st.session_state.pop("gemini_chat", None)
                    st.session_state.show_suggestions = True
                    st.rerun()

            st.divider()

            if not GEMINI_API_KEY:
                st.warning(
                    "⚠️ No Gemini API key found. Add `GOOGLE_API_KEY` to your environment or Streamlit secrets.",
                    icon="🔑"
                )
                st.stop()

            if not raw_incidents:
                st.info("No incident data available from the API.")
                st.stop()

            incident_context = build_incident_context(raw_incidents)
            chat = get_or_create_chat(incident_context)

            if "messages" not in st.session_state:
                st.session_state.messages = []

            if "show_suggestions" not in st.session_state:
                st.session_state.show_suggestions = True

            if st.session_state.messages:
                st.session_state.show_suggestions = False

            if st.session_state.show_suggestions:
                with st.container(border=True):
                    st.markdown(
                        "<p style='font-size:16px; font-weight:600; margin-bottom:10px;'>Quick Questions</p>",
                        unsafe_allow_html=True
                    )

                    suggestions = [
                        "Which incident should I worry about most?",
                        "What is an IAM spike and is mine serious?",
                        "Which actors show up the most?",
                        "Explain the highest risk incident simply",
                        "What exact steps should I take right now?",
                        "Summarize all incidents for me",
                    ]

                    row1 = st.columns(3)
                    row2 = st.columns(3)

                    for col, suggestion in zip(list(row1) + list(row2), suggestions):
                        with col:
                            if st.button(suggestion, use_container_width=True, key=f"sug_{suggestion}"):
                                st.session_state.show_suggestions = False
                                st.session_state.messages.append({"role": "user", "content": suggestion})
                                with st.spinner("Thinking..."):
                                    try:
                                        resp = chat.send_message(message=suggestion)
                                        st.session_state.messages.append({"role": "assistant", "content": resp.text})
                                    except Exception as e:
                                        st.session_state.messages.append({"role": "assistant", "content": f"Sorry, I hit an error: {e}"})
                                st.rerun()

            st.write("")

            if st.session_state.messages:
                with st.container(border=True):
                    for msg in st.session_state.messages:
                        if msg["role"] == "user":
                            st.markdown(
                                f"<p style='font-size:13px; font-weight:600; color:#888; text-align:right; margin-bottom:2px;'>You</p>"
                                f"<p style='font-size:16px; line-height:1.55; text-align:right; margin-bottom:12px;'>{msg['content']}</p>",
                                unsafe_allow_html=True
                            )
                        else:
                            st.markdown(
                                f"<p style='font-size:13px; font-weight:600; color:#e74c3c; margin-bottom:2px;'>AnomAI Assistant</p>"
                                f"<p style='font-size:16px; line-height:1.6; margin-bottom:12px;'>{msg['content']}</p>",
                                unsafe_allow_html=True
                            )
                        st.divider()
            else:
                with st.container(border=True):
                    st.markdown(
                        "<div style='text-align:center; padding:40px 0;'>"
                        "<p style='font-size:32px; margin-bottom:8px;'>💬</p>"
                        "<p style='font-size:18px;'>Click a question above or type below to get started.</p>"
                        "</div>",
                        unsafe_allow_html=True
                    )

            user_input = st.chat_input("Ask about your security incidents...")
            if user_input:
                st.session_state.show_suggestions = False
                st.session_state.messages.append({"role": "user", "content": user_input})

                with st.spinner("Thinking..."):
                    try:
                        resp = chat.send_message(message=user_input)
                        st.session_state.messages.append({"role": "assistant", "content": resp.text})
                    except Exception as e:
                        st.session_state.messages.append({"role": "assistant", "content": f"Sorry, something went wrong: {e}"})

                st.rerun()
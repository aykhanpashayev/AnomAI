import streamlit as st
import plotly.express as px
import pandas as pd
import json
import os
import requests
from datetime import datetime, timedelta

# -----------------------------------
# API Configuration
# -----------------------------------
# Set ANOMAI_API_URL env var to override, e.g. for production.
# Defaults to localhost where Flask runs during development or if it's online we will provide the public api link
API_BASE_URL = (
    os.environ.get("ANOMAI_API_URL")
    or st.secrets.get("ANOMAI_API_URL", "http://localhost:8000")
)


# -----------------------------------
# Load incidents from Flask API
# -----------------------------------
def load_incidents():
    """
    Fetch all incidents from the Flask API (/incidents endpoint).
    Returns the same structure the old JSON file had so the rest of
    the UI code works without any changes:
      { "incident_count": N, "new_incident_count": N, "incidents": [...] }
    Falls back to a safe empty default on any network or parse error.
    """
    try:
        resp = requests.get(f"{API_BASE_URL}/incidents", timeout=10)
        resp.raise_for_status()
        data = resp.json()

        incidents = data.get("incidents", [])

        return {
            "incident_count": data.get("count", len(incidents)),
            "new_incident_count": sum(1 for i in incidents if i.get("is_new")),
            "incidents": incidents,
        }

    except requests.exceptions.ConnectionError:
        st.error(f"⚠️ Could not connect to the AnomAI API at **{API_BASE_URL}**. Is the Flask server running?")
    except requests.exceptions.Timeout:
        st.error(f"⚠️ API request timed out ({API_BASE_URL}). The server may be overloaded.")
    except requests.exceptions.HTTPError as e:
        st.error(f"⚠️ API returned an error: {e}")
    except (ValueError, KeyError) as e:
        st.error(f"⚠️ Unexpected API response format: {e}")

    return {"incident_count": 0, "new_incident_count": 0, "incidents": []}


# -----------------------------------
# Field mapping helpers
# -----------------------------------
# The Flask API uses the converted schema (incident_type, explanation.summary, etc.)
# The old UI used the raw detection schema (type, title, recommendation, etc.)
# These helpers bridge the two so all existing UI code works unchanged.

def get_incident_type(inc):
    """Return the raw type string for format_incident_type()."""
    # API schema uses incident_type (e.g. "AccessDeniedSpike")
    # Map back to internal keys so format_incident_type() still works.
    api_type_map = {
        "AccessDeniedSpike":  "access_denied_spike",
        "SensitiveIAMSpike":  "suspicious_iam_activity",
        "APIBurst":           "api_burst",
        "NewRegion":          "new_region_activity",
        "SigninFailureSpike": "signin_failure_spike",
        "InvalidAMISpike":    "invalid_ami_spike",
    }
    api_type = inc.get("incident_type", "")
    return api_type_map.get(api_type, api_type.lower())


def get_recommendation(inc):
    """Return recommendation text from either schema format."""
    return (
        (inc.get("explanation") or {}).get("recommendation")
        or inc.get("recommendation")
        or "No recommendation available."
    )


def get_title(inc):
    """Return incident title/summary from either schema format."""
    return (
        (inc.get("explanation") or {}).get("summary")
        or inc.get("title")
        or get_incident_type(inc)
    )


def get_first_seen(inc):
    """Return first-seen timestamp from either schema format."""
    return inc.get("timestamp_start") or inc.get("first_seen") or ""


def get_age(inc):
    """Return human-readable age string, computed from age_seconds if available."""
    age_s = inc.get("age_seconds")
    if age_s is not None:
        age_s = int(age_s)
        if age_s < 3600:
            return f"{age_s // 60}m ago"
        if age_s < 86400:
            return f"{age_s // 3600}h ago"
        days = age_s // 86400
        return "yesterday" if days == 1 else f"{days}d ago"
    return inc.get("age", "Unknown")


# Convert internal incident type codes into clean, human-readable labels.
def format_incident_type(type_value):
    type_map = {
        "access_denied_spike":  "Access Denied Spike",
        "suspicious_iam_activity": "Suspicious IAM Activity",
        "api_burst":            "API Burst",
        "new_region_activity":  "New Region Activity",
        "signin_failure_spike": "Sign-in Failure Spike",
        "invalid_ami_spike":    "Invalid AMI Spike",
    }
    return type_map.get(type_value, str(type_value).replace("_", " ").title())


# -----------------------------------
# Load data
# -----------------------------------
incidents_data = load_incidents()
raw_incidents = incidents_data.get("incidents", [])

# -----------------------------------
# Page config
# -----------------------------------
st.set_page_config(
    page_title="AnomAI Security Dashboard",
    layout="wide"
)

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

col_filter, col_display = st.columns([1.2, 5])

# -----------------------------------
# Filter state defaults
# -----------------------------------
default_filter_state = {
    "severity_high":     True,
    "severity_medium":   True,
    "severity_low":      True,

    "actor_all":         False,
    "actor_firstTest":   True,
    "actor_test":        True,
    "actor_aykhan":      True,
    "actor_charlie":     True,
    "actor_alex":        True,
    "actor_resource":    True,
    "actor_nicolas":     True,
    "actor_multiple":    True,

    "type_access_denied":    True,
    "type_suspicious_iam":   True,
    "type_api_burst":        True,
}

for key, value in default_filter_state.items():
    if key not in st.session_state:
        st.session_state[key] = value

with col_filter:
    with st.container(border=True):
        st.markdown("### Filters")

        with st.expander("Severity", expanded=True):
            severity_high   = st.checkbox("High",   key="severity_high")
            severity_medium = st.checkbox("Medium", key="severity_medium")
            severity_low    = st.checkbox("Low",    key="severity_low")

            selected_severity = []
            if severity_high:   selected_severity.append("High")
            if severity_medium: selected_severity.append("Medium")
            if severity_low:    selected_severity.append("Low")

        st.divider()

        with st.expander("Actor", expanded=True):
            actor_all       = st.checkbox("All Actors",          key="actor_all")
            actor_firstTest = st.checkbox("firstTest",           key="actor_firstTest")
            actor_test      = st.checkbox("test",                key="actor_test")
            actor_aykhan    = st.checkbox("Aykhan",              key="actor_aykhan")
            actor_charlie   = st.checkbox("Charlie",             key="actor_charlie")
            actor_alex      = st.checkbox("Alex",                key="actor_alex")
            actor_resource  = st.checkbox("resource-explorer-2", key="actor_resource")
            actor_nicolas   = st.checkbox("Nicolas",             key="actor_nicolas")
            actor_multiple  = st.checkbox("Multiple",            key="actor_multiple")

            selected_actors = []
            if actor_all:
                selected_actors = ["All Actors"]
            else:
                if actor_firstTest: selected_actors.append("firstTest")
                if actor_test:      selected_actors.append("test")
                if actor_aykhan:    selected_actors.append("Aykhan")
                if actor_charlie:   selected_actors.append("Charlie")
                if actor_alex:      selected_actors.append("Alex")
                if actor_resource:  selected_actors.append("resource-explorer-2")
                if actor_nicolas:   selected_actors.append("Nicolas")
                if actor_multiple:  selected_actors.append("Multiple")

        st.divider()

        with st.expander("Incident Type", expanded=True):
            type_access_denied  = st.checkbox("Access Denied Spike",    key="type_access_denied")
            type_suspicious_iam = st.checkbox("Suspicious IAM Activity", key="type_suspicious_iam")
            type_api_burst      = st.checkbox("API Burst",              key="type_api_burst")

            selected_types = []
            if type_access_denied:  selected_types.append("Access Denied Spike")
            if type_suspicious_iam: selected_types.append("Suspicious IAM Activity")
            if type_api_burst:      selected_types.append("API Burst")

        if st.button("Reset Filters", use_container_width=True):
            for key, value in default_filter_state.items():
                st.session_state[key] = value
            st.rerun()

        # -----------------------------------
        # Filtering logic
        # -----------------------------------
        filtered_incidents = []

        for inc in raw_incidents:
            severity_val = str(inc.get("severity", "low")).capitalize()

            # Resolve actor — API schema has top-level "actor" field
            actors_dict = inc.get("by_actor") or inc.get("evidence", {}).get("by_actor", {})
            if not actors_dict:
                peak = (inc.get("evidence") or {}).get("peak_actor")
                actor_name = peak if peak else inc.get("actor", "Unknown")
            elif len(actors_dict) == 1:
                actor_name = list(actors_dict.keys())[0]
            else:
                actor_name = "Multiple"

            incident_type_val = format_incident_type(get_incident_type(inc))

            if selected_severity and severity_val not in selected_severity:
                continue
            if selected_actors and selected_actors != ["All Actors"] and actor_name not in selected_actors:
                continue
            if selected_types and incident_type_val not in selected_types:
                continue

            filtered_incidents.append(inc)

# -----------------------------------
# Metric calculations
# -----------------------------------
total_incidents_count = len(filtered_incidents)
two_weeks_ago = datetime.utcnow() - timedelta(days=14)
last_two_weeks_count = 0

for i in filtered_incidents:
    first_seen = get_first_seen(i)
    if not first_seen:
        continue
    try:
        incident_time = datetime.strptime(first_seen[:19], "%Y-%m-%dT%H:%M:%S")
        if incident_time >= two_weeks_ago:
            last_two_weeks_count += 1
    except ValueError:
        continue

high_severity_count = len([i for i in filtered_incidents if i.get("severity", "").lower() == "high"])

top_actors_dict = {}
for i in filtered_incidents:
    actors = i.get("by_actor") or i.get("evidence", {}).get("by_actor", {})
    if not actors:
        peak = (i.get("evidence") or {}).get("peak_actor")
        if peak:
            actors = {peak: (i.get("evidence") or {}).get("peak_count", 1)}
    for actor, count in (actors or {}).items():
        top_actors_dict[actor] = top_actors_dict.get(actor, 0) + int(count)

top_actor_name = max(top_actors_dict, key=top_actors_dict.get) if top_actors_dict else "--"

# -----------------------------------
# Build table rows + detail panels
# -----------------------------------
incident_details = []
table_rows = []

for idx, inc in enumerate(filtered_incidents, start=1):
    severity_val = str(inc.get("severity", "low")).capitalize()

    actors_dict = inc.get("by_actor") or inc.get("evidence", {}).get("by_actor", {})
    if not actors_dict:
        peak = (inc.get("evidence") or {}).get("peak_actor")
        actor_name = peak if peak else inc.get("actor", "Unknown")
    elif len(actors_dict) == 1:
        actor_name = list(actors_dict.keys())[0]
    else:
        actor_name = "Multiple"

    inc_type = format_incident_type(get_incident_type(inc))

    # Use actual final_risk_score from API if available, else fall back to severity bucket
    risk_score = inc.get("final_risk_score") or inc.get("rule_score") or \
                 {"High": 90, "Medium": 60, "Low": 30}.get(severity_val, 0)

    first_seen = get_first_seen(inc)
    if "T" in first_seen:
        try:
            dt = datetime.strptime(first_seen[:19], "%Y-%m-%dT%H:%M:%S")
            date_str  = dt.strftime("%b %d %Y")
        except ValueError:
            date_str = "Unknown"
    else:
        date_str = "Unknown"

    table_rows.append({
        "Severity":      severity_val,
        "Incident Type": inc_type,
        "Actor":         actor_name,
        "Risk Score":    risk_score,
        "Date":          date_str,
    })

    adv_details = [
        f"Count: {(inc.get('evidence') or {}).get('count', inc.get('count', 0))} events",
        f"First seen: {first_seen or 'Unknown'}",
        f"Age: {get_age(inc)}",
    ]

    ev_events = (inc.get("evidence") or {}).get("by_eventName") or \
                {n: "" for n in ((inc.get("evidence") or {}).get("top_event_names") or [])}
    if ev_events:
        top_events_str = ", ".join(list(ev_events.keys())[:3])
        adv_details.append(f"Top Events: {top_events_str}")

    regions = (inc.get("evidence") or {}).get("by_region", {})
    if regions:
        adv_details.append(f"Regions: {', '.join(regions.keys())}")

    incident_details.append({
        "Dropdown Label":  f"{inc_type} | {actor_name} | {date_str}",
        "Incident Name":   inc_type,
        "Severity":        severity_val,
        "Actor":           actor_name,
        "Risk Score":      risk_score,
        "Summary":         get_recommendation(inc),
        "Advanced Details": adv_details,
    })

# Build DataFrame
if table_rows:
    incident_table_data = pd.DataFrame(table_rows)
    try:
        incident_table_data["Date_dt"] = pd.to_datetime(
            [get_first_seen(inc) for inc in filtered_incidents], errors="coerce"
        )
        incident_table_data = incident_table_data.sort_values("Date_dt", ascending=False)
        incident_table_data = incident_table_data.drop(columns=["Date_dt"])
    except Exception:
        pass
else:
    incident_table_data = pd.DataFrame(
        columns=["Severity", "Incident Type", "Actor", "Risk Score", "Date"]
    )

# -----------------------------------
# Main display
# -----------------------------------
with col_display:
    with st.container(border=True):

        if page_selection == "🔴 Dashboard":
            st.subheader("Dashboard View")

            metric_1, metric_2, metric_3, metric_4 = st.columns(4)

            with metric_1:
                with st.container(border=True):
                    st.markdown(f"""
                        <div style='text-align:center;'>
                            <div style='font-size:20px;font-weight:600;'>Total Incidents</div>
                            <div style='font-size:42px;font-weight:700;'>{total_incidents_count}</div>
                        </div>""", unsafe_allow_html=True)

            with metric_2:
                with st.container(border=True):
                    st.markdown(f"""
                        <div style='text-align:center;'>
                            <div style='font-size:20px;font-weight:600;'>Last Two Weeks</div>
                            <div style='font-size:42px;font-weight:700;'>{last_two_weeks_count}</div>
                        </div>""", unsafe_allow_html=True)

            with metric_3:
                with st.container(border=True):
                    st.markdown(f"""
                        <div style='text-align:center;'>
                            <div style='font-size:20px;font-weight:600;'>High Severity</div>
                            <div style='font-size:42px;font-weight:700;'>{high_severity_count}</div>
                        </div>""", unsafe_allow_html=True)

            with metric_4:
                with st.container(border=True):
                    st.markdown(f"""
                        <div style='text-align:center;'>
                            <div style='font-size:20px;font-weight:600;'>Top Actor</div>
                            <div style='font-size:30px;font-weight:700;margin-top:10px;'>{top_actor_name}</div>
                        </div>""", unsafe_allow_html=True)

            st.write("")

            chart_col1, chart_col2, chart_col3 = st.columns(3)

            with chart_col1:
                with st.container(border=True):
                    st.markdown("### Incident Severity")
                    severity_data = incident_table_data["Severity"].value_counts().reset_index()
                    severity_data.columns = ["Severity", "Count"]
                    fig = px.pie(
                        severity_data, names="Severity", values="Count", color="Severity",
                        color_discrete_map={"High": "#e74c3c", "Medium": "#f1c40f", "Low": "#95a5a6"}
                    )
                    fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=250)
                    st.plotly_chart(fig, use_container_width=True, theme="streamlit", key="severity_pie_chart")

            with chart_col2:
                with st.container(border=True):
                    st.markdown("### Incident Types")
                    incident_type_data = incident_table_data["Incident Type"].value_counts().reset_index()
                    incident_type_data.columns = ["Incident Type", "Count"]
                    fig_bar = px.bar(incident_type_data, x="Incident Type", y="Count", color="Incident Type")
                    fig_bar.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=250, showlegend=False)
                    st.plotly_chart(fig_bar, use_container_width=True, theme="streamlit", key="incident_type_bar_chart")

            with chart_col3:
                with st.container(border=True):
                    st.markdown("### Incidents by Month")
                    month_values = []
                    for inc in filtered_incidents:
                        fs = get_first_seen(inc)
                        if "T" in fs:
                            try:
                                dt = datetime.strptime(fs[:19], "%Y-%m-%dT%H:%M:%S")
                                month_values.append(dt.strftime("%b %Y"))
                            except ValueError:
                                continue
                    incident_time_data = pd.Series(month_values).value_counts().reset_index()
                    incident_time_data.columns = ["Month", "Count"]
                    try:
                        incident_time_data["Month_dt"] = pd.to_datetime(incident_time_data["Month"], format="%b %Y")
                        incident_time_data = incident_time_data.sort_values("Month_dt").drop(columns=["Month_dt"])
                    except Exception:
                        pass
                    if incident_time_data.empty:
                        incident_time_data = pd.DataFrame({"Month": ["Unknown"], "Count": [0]})
                    fig_line = px.line(incident_time_data, x="Month", y="Count", markers=True)
                    fig_line.update_layout(
                        xaxis=dict(type="category"),
                        margin=dict(l=0, r=0, t=10, b=0),
                        height=250, xaxis_title=None, yaxis_title=None
                    )
                    st.plotly_chart(fig_line, use_container_width=True, theme="streamlit", key="incidents_over_time_line_chart")

            st.write("")

            bottom_left, bottom_right = st.columns([2.2, 1.3])

            with bottom_left:
                with st.container(border=True):
                    st.markdown("### Recent Incidents")
                    styled_table = incident_table_data.style.map(
                        lambda x: (
                            "color:#e74c3c;font-weight:bold" if x == "High" else
                            "color:#f39c12;font-weight:bold" if x == "Medium" else
                            "color:#27ae60;font-weight:bold" if x == "Low" else ""
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
                    else:
                        st.info("No incidents match the current filters.")
                        incident_detail_data = None

                    if incident_detail_data is not None:
                        severity_color = (
                            "#e74c3c" if incident_detail_data["Severity"] == "High" else
                            "#f39c12" if incident_detail_data["Severity"] == "Medium" else
                            "#27ae60"
                        )
                        st.markdown(
                            f"<p style='font-size:24px;font-weight:600;margin-bottom:6px;'>{incident_detail_data['Incident Name']}</p>",
                            unsafe_allow_html=True
                        )
                        st.markdown(
                            f"<p style='font-size:18px;margin-bottom:2px;'><strong>Severity:</strong> "
                            f"<span style='background-color:{severity_color};color:white;padding:2px 10px;"
                            f"border-radius:6px;font-weight:600;'>{incident_detail_data['Severity']}</span></p>",
                            unsafe_allow_html=True
                        )
                        st.markdown(
                            f"<p style='font-size:18px;margin-bottom:2px;'><strong>Actor:</strong> <em>{incident_detail_data['Actor']}</em></p>",
                            unsafe_allow_html=True
                        )
                        st.markdown(
                            f"<p style='font-size:18px;margin-bottom:6px;'><strong>Risk Score:</strong> {incident_detail_data['Risk Score']}</p>",
                            unsafe_allow_html=True
                        )
                        st.divider()
                        st.markdown("<h3 style='margin-bottom:6px;'>Summary</h3>", unsafe_allow_html=True)
                        st.markdown(
                            f"<p style='font-size:18px;line-height:1.5;margin-top:0;margin-bottom:8px;'>{incident_detail_data['Summary']}</p>",
                            unsafe_allow_html=True
                        )
                        st.divider()
                        st.markdown("<h3 style='margin-bottom:6px;'>Advanced Details</h3>", unsafe_allow_html=True)
                        for item in incident_detail_data["Advanced Details"]:
                            st.markdown(
                                f"<p style='font-size:18px;margin-top:0;margin-bottom:4px;'>• {item}</p>",
                                unsafe_allow_html=True
                            )

        elif page_selection == "🤖 Chatbot":
            st.subheader("Chatbot View")
            st.write("AI assistant is ready for your questions.")
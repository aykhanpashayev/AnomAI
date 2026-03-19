import streamlit as st
import plotly.express as px
import pandas as pd
import json
import os

# Load incident data from the JSON output file.
# The function tries several possible relative paths so that the UI can still run
# even if the script is launched from different working directories.
# If the file cannot be found or parsed, it returns a safe empty default structure.
def load_incidents():
    paths_to_try = [
        os.path.join(os.path.dirname(__file__), "..", "..", "out", "incidents.json"),
        os.path.join("out", "incidents.json"),
        os.path.join("..", "..", "out", "incidents.json")
    ]
    for p in paths_to_try:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError):
                pass
    return {"incident_count": 0, "new_incident_count": 0, "incidents": []}

# Convert internal incident type codes into clean, human-readable labels.
# This ensures the dashboard shows consistent naming in filters, charts, tables,
# and the incident details panel.
def format_incident_type(type_value):
    type_map = {
        "access_denied_spike": "Access Denied Spike",
        "suspicious_iam_activity": "Suspicious IAM Activity",
        "api_burst": "API Burst"
    }
    return type_map.get(type_value, str(type_value).replace("_", " ").title())

# Load the incident dataset once at startup.
# raw_incidents is the unfiltered source list used for all downstream processing.
incidents_data = load_incidents()
raw_incidents = incidents_data.get("incidents", [])

# Configure the Streamlit page layout.
# "wide" is used so the dashboard has enough horizontal space for metrics,
# charts, and the incident detail panel.
st.set_page_config(
    page_title="AnomAI Security Dashboard",
    layout="wide"
)

# Custom CSS styling for a cleaner dashboard appearance.
# This section adjusts the background, title formatting, and the style
# of bordered containers and expanders.
st.markdown("""
    <style>
    .stApp {
        background-color: white;
    }

    h1 {
        margin-top: 0px !important; 
        line-height: 1.2 !important; 
        font-size: 42px !important;    
        text-align: center;
    }

    [data-testid="stVerticalBlockBorderWrapper"] {
        background-color: #f8f9fa !important; 
        border: 1px solid #e6e9ef !important; 
        border-radius: 8px !important;
        padding: 15px !important;
    }

    [data-testid="stExpander"] {
        background-color: transparent !important;
        border: none !important;
    }
    </style>
    """, unsafe_allow_html=True)

# Create the top navigation row:
# - col_nav: page switcher (Dashboard / Chatbot)
# - col_title: application title
# - col_spacer: visual spacing on the right
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

# Split the main page into:
# - left column: filters
# - right column: dashboard / chatbot content
col_filter, col_display = st.columns([1.2, 5])

# Default checkbox state for all filters.
# These values are stored in Streamlit session_state so that:
# 1. the UI remembers the current filter state,
# 2. the Reset Filters button can restore the original defaults.
default_filter_state = {
    "severity_high": True,
    "severity_medium": True,
    "severity_low": True,

    "actor_all": False,
    "actor_firstTest": True,
    "actor_test": True,
    "actor_aykhan": True,
    "actor_charlie": True,
    "actor_alex": True,
    "actor_resource": True,
    "actor_nicolas": True,
    "actor_multiple": True,

    "type_access_denied": True,
    "type_suspicious_iam": True,
    "type_api_burst": True,
}

# Initialize session state only once.
# This prevents Streamlit from resetting filter choices on every rerun.
for key, value in default_filter_state.items():
    if key not in st.session_state:
        st.session_state[key] = value

with col_filter:
    with st.container(border=True):
        st.markdown("### Filters")

        # -----------------------------
        # Severity Filter
        # -----------------------------
        # Build the selected severity list based on the current checkbox states.
        with st.expander("Severity", expanded=True):
            severity_high = st.checkbox("High", key="severity_high")
            severity_medium = st.checkbox("Medium", key="severity_medium")
            severity_low = st.checkbox("Low", key="severity_low")

            selected_severity = []
            if severity_high:
                selected_severity.append("High")
            if severity_medium:
                selected_severity.append("Medium")
            if severity_low:
                selected_severity.append("Low")

        st.divider()

        # -----------------------------
        # Actor Filter
        # -----------------------------
        # "All Actors" acts like a bypass flag.
        # If selected, actor-specific filtering is skipped.
        with st.expander("Actor", expanded=True):
            actor_all = st.checkbox("All Actors", key="actor_all")
            actor_firstTest = st.checkbox("firstTest", key="actor_firstTest")
            actor_test = st.checkbox("test", key="actor_test")
            actor_aykhan = st.checkbox("Aykhan", key="actor_aykhan")
            actor_charlie = st.checkbox("Charlie", key="actor_charlie")
            actor_alex = st.checkbox("Alex", key="actor_alex")
            actor_resource = st.checkbox("resource-explorer-2", key="actor_resource")
            actor_nicolas = st.checkbox("Nicolas", key="actor_nicolas")
            actor_multiple = st.checkbox("Multiple", key="actor_multiple")

            selected_actors = []

            if actor_all:
                selected_actors = ["All Actors"]
            else:
                if actor_firstTest:
                    selected_actors.append("firstTest")
                if actor_test:
                    selected_actors.append("test")
                if actor_aykhan:
                    selected_actors.append("Aykhan")
                if actor_charlie:
                    selected_actors.append("Charlie")
                if actor_alex:
                    selected_actors.append("Alex")
                if actor_resource:
                    selected_actors.append("resource-explorer-2")
                if actor_nicolas:
                    selected_actors.append("Nicolas")
                if actor_multiple:
                    selected_actors.append("Multiple")

        st.divider()

        # -----------------------------
        # Incident Type Filter
        # -----------------------------
        # These display labels match the formatted labels used elsewhere in the UI.
        with st.expander("Incident Type", expanded=True):
            type_access_denied = st.checkbox("Access Denied Spike", key="type_access_denied")
            type_suspicious_iam = st.checkbox("Suspicious IAM Activity", key="type_suspicious_iam")
            type_api_burst = st.checkbox("API Burst", key="type_api_burst")

            selected_types = []
            if type_access_denied:
                selected_types.append("Access Denied Spike")
            if type_suspicious_iam:
                selected_types.append("Suspicious IAM Activity")
            if type_api_burst:
                selected_types.append("API Burst")

        # Reset all filters back to their default state.
        # st.rerun() is used so the UI refreshes immediately after reset.
        if st.button("Reset Filters", use_container_width=True):
            for key, value in default_filter_state.items():
                st.session_state[key] = value
            st.rerun()

        # Debug helpers kept for development/testing.
        # Uncomment if you need to inspect the active filter selections.
        # st.write("Selected Severity:", selected_severity)
        # st.write("Selected Actors:", selected_actors)
        # st.write("Selected Types:", selected_types)

        # -----------------------------
        # Core Filtering Logic
        # -----------------------------
        # Build a filtered list of incidents that match the currently selected
        # severity, actor, and incident type filters.
        filtered_incidents = []

        for inc in raw_incidents:
            severity_val = str(inc.get("severity", "Low")).capitalize()

            # Extract a user-friendly actor label.
            # If multiple actors are present, use "Multiple".
            # If no by_actor data exists but peak_actor exists, use peak_actor instead.
            actors_dict = inc.get("evidence", {}).get("by_actor", {})
            if not actors_dict and "peak_actor" in inc.get("evidence", {}):
                actor_name = inc["evidence"]["peak_actor"]
            elif actors_dict:
                actor_name = list(actors_dict.keys())[0] if len(actors_dict) == 1 else "Multiple"
            else:
                actor_name = "Unknown"

            incident_type_val = format_incident_type(inc.get("type", "Unknown"))

            # Skip incidents that do not match the selected severity values.
            if selected_severity and severity_val not in selected_severity:
                continue

            # Skip incidents that do not match the selected actor values,
            # unless "All Actors" is enabled.
            if selected_actors and selected_actors != ["All Actors"] and actor_name not in selected_actors:
                continue

            # Skip incidents that do not match the selected incident types.
            if selected_types and incident_type_val not in selected_types:
                continue

            filtered_incidents.append(inc)

# -----------------------------
# Metric Calculations
# -----------------------------
# All summary metrics are calculated from filtered_incidents so that the top
# row always stays synchronized with the active filter state.
total_incidents_count = len(filtered_incidents)
new_incidents_count = len([i for i in filtered_incidents if i.get("is_new", False)])
high_severity_count = len([i for i in filtered_incidents if i.get("severity", "").lower() == "high"])

# Calculate the top actor by summing event counts across the filtered incidents.
# This supports both by_actor and peak_actor-based incident formats.
top_actors_dict = {}
for i in filtered_incidents:
    actors = i.get("evidence", {}).get("by_actor", {})
    if not actors and "peak_actor" in i.get("evidence", {}):
        actors = {i["evidence"]["peak_actor"]: i["evidence"].get("peak_count", 1)}
    for actor, count in actors.items():
        top_actors_dict[actor] = top_actors_dict.get(actor, 0) + count

top_actor_name = max(top_actors_dict, key=top_actors_dict.get) if top_actors_dict else "--"

# -----------------------------
# Transform Incidents for UI Rendering
# -----------------------------
# table_rows is used for the Recent Incidents table and charts.
# incident_details is used for the right-side Incident Details panel.
incident_details = []
table_rows = []

for idx, inc in enumerate(filtered_incidents, start=1):
    severity_val = str(inc.get("severity", "Low")).capitalize()

    actors_dict = inc.get("evidence", {}).get("by_actor", {})
    if not actors_dict and "peak_actor" in inc.get("evidence", {}):
        actor_name = inc["evidence"]["peak_actor"]
    elif actors_dict:
        actor_name = list(actors_dict.keys())[0] if len(actors_dict) == 1 else "Multiple"
    else:
        actor_name = "Unknown"

    inc_title = inc.get("title", f"Incident {idx}")
    inc_type = format_incident_type(inc.get("type", "Unknown"))

    # Static risk score mapping based on severity.
    # This can be replaced later with a more advanced scoring model if needed.
    risk_score = {"High": 90, "Medium": 60, "Low": 30}.get(severity_val, 0)

    created_time = inc.get("first_seen", "")
    time_str = created_time.split("T")[1][:5] if "T" in created_time else "Unknown"

    table_rows.append({
        "Severity": severity_val,
        "Incident Type": inc_type,
        "Actor": actor_name,
        "Risk Score": risk_score,
        "Time": time_str
    })

    # Build a detailed explanation list for the Incident Details panel.
    adv_details = [
        f"Count: {inc.get('count', 0)} events",
        f"First seen: {inc.get('first_seen', 'Unknown')}",
        f"Age: {inc.get('age', 'Unknown')}"
    ]

    ev_events = inc.get("evidence", {}).get("by_eventName", {})
    if ev_events:
        top_events_str = ", ".join([f"{k} ({v})" for k, v in ev_events.items()][:3])
        adv_details.append(f"Top Events: {top_events_str}")

    regions = inc.get("evidence", {}).get("by_region", {})
    if regions:
        adv_details.append(f"Regions: {', '.join(regions.keys())}")

    incident_details.append({
        "Dropdown Label": f"{inc_title} ({time_str})",
        "Incident Name": inc_type,
        "Severity": severity_val,
        "Actor": actor_name,
        "Risk Score": risk_score,
        "Summary": inc.get("recommendation", "No recommendation available.") or "No summary provided.",
        "Advanced Details": adv_details
    })

# Create the table DataFrame used by charts and the Recent Incidents table.
# If no incidents match the filters, create an empty DataFrame with the expected columns.
if table_rows:
    incident_table_data = pd.DataFrame(table_rows)
else:
    incident_table_data = pd.DataFrame(columns=["Severity", "Incident Type", "Actor", "Risk Score", "Time"])

with col_display:

    with st.container(border=True):

        # -----------------------------
        # Dashboard Page
        # -----------------------------
        if page_selection == "🔴 Dashboard":
            st.subheader("Dashboard View")

            total_incidents = total_incidents_count
            new_incidents = new_incidents_count
            high_severity = high_severity_count
            top_actor = top_actor_name

            # Top metric cards
            metric_1, metric_2, metric_3, metric_4 = st.columns(4)

            with metric_1:
                with st.container(border=True):
                    st.markdown(
                        f"""
                        <div style='text-align: center;'>
                            <div style='font-size: 20px; font-weight: 600;'>Total Incidents</div>
                            <div style='font-size: 42px; font-weight: 700;'>{total_incidents}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

            with metric_2:
                with st.container(border=True):
                    st.markdown(
                        f"""
                        <div style='text-align: center;'>
                            <div style='font-size: 20px; font-weight: 600;'>New Incidents</div>
                            <div style='font-size: 42px; font-weight: 700;'>{new_incidents}</div>
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
                            <div style='font-size: 42px; font-weight: 700;'>{high_severity}</div>
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
                            <div style='font-size: 30px; font-weight: 700; margin-top: 10px;'>{top_actor}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

            st.write("")

            chart_col1, chart_col2, chart_col3 = st.columns(3)

            with chart_col1:
                with st.container(border=True):
                    st.markdown("### Incident Severity")
                    severity_data = incident_table_data["Severity"].value_counts().reset_index()
                    severity_data.columns = ["Severity", "Count"]

                    fig = px.pie(
                        severity_data,
                        names="Severity",
                        values="Count",
                        color="Severity",
                        color_discrete_map={
                            "High": "#e74c3c",
                            "Medium": "#f1c40f",
                            "Low": "#95a5a6"
                        }
                    )

                    fig.update_layout(
                        margin=dict(l=0, r=0, t=10, b=0),
                        height=250
                    )

                    st.plotly_chart(fig, use_container_width=True)

            with chart_col2:
                with st.container(border=True):
                    st.markdown("### Incident Types")
                    incident_type_data = incident_table_data["Incident Type"].value_counts().reset_index()
                    incident_type_data.columns = ["Incident Type", "Count"]

                    fig_bar = px.bar(
                        incident_type_data,
                        x="Incident Type",
                        y="Count",
                        color="Incident Type"
                    )

                    fig_bar.update_layout(
                        margin=dict(l=0, r=0, t=10, b=0),
                        height=250,
                        showlegend=False
                    )

                    st.plotly_chart(fig_bar, use_container_width=True)

            with chart_col3:
                with st.container(border=True):
                    st.markdown("### Incidents Over Time")

                    incident_time_data = incident_table_data["Time"].value_counts().sort_index().reset_index()
                    incident_time_data.columns = ["Time", "Count"]

                    # Provide a fallback row so the line chart can still render
                    # cleanly when there is no matching filtered data.
                    if incident_time_data.empty:
                        incident_time_data = pd.DataFrame({"Time": ["00:00"], "Count": [0]})

                    fig_line = px.line(
                        incident_time_data,
                        x="Time",
                        y="Count",
                        markers=True
                    )

                    fig_line.update_layout(
                        margin=dict(l=0, r=0, t=10, b=0),
                        height=250,
                        xaxis_title=None,
                        yaxis_title=None
                    )

                    st.plotly_chart(fig_line, use_container_width=True)

            st.write("")

            # Bottom row: incident table + detail panel
            bottom_left, bottom_right = st.columns([2.2, 1.3])

            with bottom_left:
                with st.container(border=True):
                    st.markdown("### Recent Incidents")

                    styled_table = incident_table_data.style.map(
                        lambda x: (
                            "color:#e74c3c;font-weight:bold"
                            if x == "High"
                            else "color:#f39c12;font-weight:bold"
                            if x == "Medium"
                            else "color:#27ae60;font-weight:bold"
                            if x == "Low"
                            else ""
                        ),
                        subset=["Severity"]
                    )

                    st.dataframe(
                        styled_table,
                        use_container_width=True,
                        hide_index=True
                    )

            with bottom_right:
                with st.container(border=True):
                    st.markdown("### Incident Details")

                    # Let the user select one filtered incident to inspect in detail.
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

                    # Only render the detail panel when a valid incident exists.
                    if incident_detail_data is not None:
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
                            f"<p style='font-size:18px; margin-bottom:2px;'><strong>Actor:</strong> <em>{incident_detail_data['Actor']}</em></p>",
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

                        st.markdown("<h3 style='margin-bottom:6px;'>Advanced Details</h3>", unsafe_allow_html=True)

                        for item in incident_detail_data["Advanced Details"]:
                            st.markdown(
                                f"<p style='font-size:18px; margin-top:0; margin-bottom:4px;'>• {item}</p>",
                                unsafe_allow_html=True
                            )

        # Placeholder page reserved for future chatbot integration.
        elif page_selection == "🤖 Chatbot":
            st.subheader("Chatbot View")
            st.write("AI assistant is ready for your questions.")

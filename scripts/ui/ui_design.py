import streamlit as st
import plotly.express as px
import pandas as pd
import json
import os

def load_incidents():
    paths_to_try = [
        os.path.join(os.path.dirname(__file__), "..", "..", "out", "incidents.json"),
        os.path.join("out", "incidents.json"),
        os.path.join("..", "..", "out", "incidents.json")
    ]
    for p in paths_to_try:
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    return json.load(f)
            except:
                pass
    return {"incident_count": 0, "new_incident_count": 0, "incidents": []}

incidents_data = load_incidents()
raw_incidents = incidents_data.get("incidents", [])

total_incidents_count = incidents_data.get("incident_count", len(raw_incidents))
new_incidents_count = incidents_data.get("new_incident_count", len([i for i in raw_incidents if i.get("is_new", False)]))
high_severity_count = len([i for i in raw_incidents if i.get("severity", "").lower() == "high"])

top_actors_dict = {}
for i in raw_incidents:
    actors = i.get("evidence", {}).get("by_actor", {})
    if not actors and "peak_actor" in i.get("evidence", {}):
        actors = {i["evidence"]["peak_actor"]: i["evidence"].get("peak_count", 1)}
    for actor, count in actors.items():
        top_actors_dict[actor] = top_actors_dict.get(actor, 0) + count

top_actor_name = max(top_actors_dict, key=top_actors_dict.get) if top_actors_dict else "--"

incident_details = []
table_rows = []

for idx, inc in enumerate(raw_incidents, start=1):
    severity_val = str(inc.get("severity", "Low")).capitalize()
    
    actors_dict = inc.get("evidence", {}).get("by_actor", {})
    if not actors_dict and "peak_actor" in inc.get("evidence", {}):
        actor_name = inc["evidence"]["peak_actor"]
    elif actors_dict:
        actor_name = list(actors_dict.keys())[0] if len(actors_dict) == 1 else "Multiple"
    else:
        actor_name = "Unknown"
        
    inc_title = inc.get("title", f"Incident {idx}")
    inc_type = inc.get("type", "Unknown").replace('_', ' ').title()
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

if not incident_details:
    incident_details.append({
        "Dropdown Label": "No Incidents", "Incident Name": "None",
        "Severity": "Low", "Actor": "-", "Risk Score": 0, "Summary": "No incidents found.", "Advanced Details": []
    })
    table_rows.append({"Severity": "Low", "Incident Type": "None", "Actor": "-", "Risk Score": 0, "Time": "-"})

incident_table_data = pd.DataFrame(table_rows)

st.set_page_config(
    page_title="AnomAI Security Dashboard",
    layout="wide"
)

st.markdown("""
    <style>
    .stApp {
        background-color: white;
    }
    
    div[data-testid="stSegmentedControl"] {
        width: 100% !important; 
        margin-top: 0px !important; 
    }
    
    div[data-testid="stSegmentedControl"] button {
        min-height: 100px !important; 
        display: flex !important;
        align-items: center !important; 
        justify-content: center !important;    
        font-size: 24px !important;
        font-weight: bold !important;
        border-radius: 4px !important;
        margin: 0px !important;
        flex-grow: 1 !important;
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

col_nav, col_title, col_spacer = st.columns([3.5, 5, 2])

with col_nav:
    st.markdown("<div style='height:40px;'></div>", unsafe_allow_html=True)

    page_selection = st.segmented_control(
        label="Navigation",
        options=["🔴 Dashboard", "🤖 Chatbot"],
        default="🔴 Dashboard",
        label_visibility="collapsed"
    )

with col_title:
    st.markdown("<h1 style='text-align: center;'>AnomAI Security Overview</h1>", unsafe_allow_html=True)

st.divider()

col_filter, col_display = st.columns([1.2, 5])

with col_filter:
    with st.container(border=True):
        st.markdown("### Filters")

        with st.expander("Severity", expanded=True):
            st.checkbox("High")
            st.checkbox("Medium")
            st.checkbox("Low")

        st.divider()

        with st.expander("Actor", expanded=True):
            st.checkbox("All Actors")
            st.checkbox("admin_user")
            st.checkbox("jdoe")
            st.checkbox("test_user")
            st.checkbox("service_account")
            st.checkbox("guest_user")

        st.divider()

        with st.expander("Incident Type", expanded=True):
            st.checkbox("Access Denied")
            st.checkbox("API Burst")
            st.checkbox("New Region")
            st.checkbox("IAM Change")

        st.button("Reset Filters", use_container_width=True)

with col_display:
    if page_selection and "Dashboard" in page_selection:
        st.subheader("Dashboard View")

        total_incidents = total_incidents_count
        new_incidents = new_incidents_count
        high_severity = high_severity_count
        top_actor = top_actor_name

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

    elif page_selection and "Chatbot" in page_selection:
        st.subheader("Chatbot View")
        st.write("AI assistant is ready for your questions.")

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


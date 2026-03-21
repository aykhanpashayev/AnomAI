import streamlit as st
import plotly.express as px
import pandas as pd
import json
import os
import urllib.request

# Load JSON data dynamically
def load_incidents():
    # Attempt to fetch from API first
    try:
        req = urllib.request.Request("http://localhost:8000/incidents")
        with urllib.request.urlopen(req, timeout=2) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                
                raw_incs = data.get("incidents", [])
                normalized_incs = []
                for inc in raw_incs:
                    # If it uses the original schema, keep it
                    if "type" in inc and ("evidence" in inc and "by_actor" in inc.get("evidence", {})):
                        normalized_incs.append(inc)
                    # If it's the API schema (incident_type, actor), map it back to UI expectations
                    elif "incident_type" in inc:
                        # Use preserved by_actor if available, else reconstruct from actor field
                        preserved_by_actor = inc.get("by_actor") or inc.get("evidence", {}).get("by_actor")
                        if not preserved_by_actor and inc.get("actor"):
                            preserved_by_actor = {inc["actor"]: inc.get("evidence", {}).get("count", 1)}
                        mapped = {
                            "severity": inc.get("severity", "Low"),
                            "type": inc.get("incident_type", "Unknown"),
                            "title": inc.get("explanation", {}).get("summary", f"Incident {inc.get('incident_id', '')}"),
                            "recommendation": inc.get("explanation", {}).get("recommendation", ""),
                            "is_new": inc.get("is_new", False),
                            "first_seen": inc.get("timestamp_start", ""),
                            "age": f"{inc.get('age_seconds', 0)} seconds ago",
                            "count": inc.get("evidence", {}).get("count", 0),
                            "evidence": {
                                "by_actor": preserved_by_actor or {},
                                "by_eventName": {name: 1 for name in inc.get("evidence", {}).get("top_event_names", [])}
                            }
                        }
                        normalized_incs.append(mapped)
                    else:
                        normalized_incs.append(inc)

                return {
                    "incident_count": data.get("count", len(normalized_incs)),
                    "new_incident_count": len([i for i in normalized_incs if i.get("is_new")]),
                    "incidents": normalized_incs
                }
    except Exception as e:
        print(f"[AnomAI] API connection failed: {type(e).__name__}: {e}")
        pass

    # Attempt multiple path strategies in case script is run from different directories
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

# Pre-calculate main metrics
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
    
    # Determine Actor
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
    
    # Extract time snippet for charting/table
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
    # Fallback to prevent UI crash if no incidents
    incident_details.append({
        "Dropdown Label": "No Incidents", "Incident Name": "None",
        "Severity": "Low", "Actor": "-", "Risk Score": 0, "Summary": "No incidents found.", "Advanced Details": []
    })
    table_rows.append({"Severity": "Low", "Incident Type": "None", "Actor": "-", "Risk Score": 0, "Time": "-"})

incident_table_data = pd.DataFrame(table_rows)

# Step 1: Page Configuration
# Set the page to wide mode to match the AnomAI UI Design Plan[cite: 7, 22].
st.set_page_config(
    page_title="AnomAI Security Dashboard",
    layout="wide"
)

# Step 2: Clean CSS for the UI Layout
# This CSS ensures the background is white and the custom Filter box is grey[cite: 23].
st.markdown("""
    <style>
    /* 1. Ensure the main background remains white */
    .stApp {
        background-color: white;
    }
    
    /* 2. Target the segmented control to fill space and align vertically */
    div[data-testid="stSegmentedControl"] {
        width: 100% !important; 
        /* Reduced margin to align with H1 padding/margin */
        margin-top: 0px !important; 
    }
    
    div[data-testid="stSegmentedControl"] button {
        /* Height and centering */
        min-height: 100px !important; 
        display: flex !important;
        align-items: center !important; 
        justify-content: center !important;    
    
        /* Text appearance - Added back for visibility */
        font-size: 24px !important;
        font-weight: bold !important;
    
        /* Shape and spacing - FIXED: Now properly inside the bracket */
        border-radius: 4px !important;
        margin: 0px !important;
        flex-grow: 1 !important;
    }
    
    /* 3. Vertically center the title with the buttons */
    h1 {
        /* Adjusted to match the button's vertical position */
        margin-top: 0px !important; 
        line-height: 1.2 !important; 
        font-size: 42px !important;    
        text-align: center;
    }
    
    /* 4. Filter Box styling: Solid grey box [cite: 130] */
    [data-testid="stVerticalBlockBorderWrapper"] {
        background-color: #f8f9fa !important; 
        border: 1px solid #e6e9ef !important; 
        border-radius: 8px !important;
        padding: 15px !important;
    }
    
    /* 5. Expander styling inside Filter box [cite: 132] */
    [data-testid="stExpander"] {
        background-color: transparent !important;
        border: none !important;
    }
    </style>
    """, unsafe_allow_html=True)

# Step 3: Top Navigation Row [cite: 25]
# Use columns to place Dashboard/Chatbot buttons and Title on the same line[cite: 36].
# Ratio [1.5, 4, 1.5] ensures buttons are to the far left.
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

# Step 4: Main Content Layout [cite: 24]
# col_filter is for the grey box, col_display is for the main data.
# The ratio [1.2, 5] keeps the Filter box narrow, not exceeding the Chatbot button width.
col_filter, col_display = st.columns([1.2, 5])

# --- LEFT SIDE: THE GREY FILTER BOX ---
with col_filter:
    # Use a container with a border.
    # Our CSS above will turn this container's background grey.
    with st.container(border=True):
        st.markdown("### Filters")  # Section title [cite: 130]

        # 1. Severity Category [cite: 133, 137]
        with st.expander("Severity", expanded=True):
            st.checkbox("High")
            st.checkbox("Medium")
            st.checkbox("Low")

        st.divider()  # Optional: thin line between categories

        # 2. Actor Category [cite: 138, 144]
        with st.expander("Actor", expanded=True):
            st.checkbox("All Actors")
            st.checkbox("admin_user")
            st.checkbox("jdoe")
            st.checkbox("test_user")
            st.checkbox("service_account")
            st.checkbox("guest_user")

        st.divider()

        # 3. Incident Type Category [cite: 145, 151]
        with st.expander("Incident Type", expanded=True):
            st.checkbox("Access Denied")
            st.checkbox("API Burst")
            st.checkbox("New Region")
            st.checkbox("IAM Change")


        # 4. Reset Button - Placed at the very bottom inside the grey box [cite: 152]
        st.button("Reset Filters", use_container_width=True)

# --- RIGHT SIDE: CONTENT DISPLAY [cite: 12] ---
with col_display:
    # We use 'in' to check the selection because the string contains icons.
    if page_selection and "Dashboard" in page_selection:
        # Dashboard section title
        st.subheader("Dashboard View")

        # ----------------------------------------------------
        # Summary metric cards
        # These are placeholder values for now.
        # Later, they should be calculated from filtered data.
        # ----------------------------------------------------
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
        st.write("AI assistant is ready for your questions[cite: 155].")

    # ----------------------------------------------------
    # Chart section (3 empty charts)
    # Layout: 3 columns for future visualizations
    # ----------------------------------------------------

    st.write("")  # small spacing

    chart_col1, chart_col2, chart_col3 = st.columns(3)

    # Chart 1: Incident Severity
    with chart_col1:
        with st.container(border=True):
            st.markdown("### Incident Severity")
            # Sample severity data
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

    # Chart 2: Incident Types
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

    # Chart 3: Incidents Over Time
    with chart_col3:
        with st.container(border=True):
            st.markdown("### Incidents Over Time")

            # Dynamic time series data
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

    # ----------------------------------------------------
    # Bottom section
    # Left: Recent Incidents
    # Right: Incident Details
    # ----------------------------------------------------
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

            # Set severity badge color
            if incident_detail_data["Severity"] == "High":
                severity_color = "#e74c3c"
            elif incident_detail_data["Severity"] == "Medium":
                severity_color = "#f39c12"
            else:
                severity_color = "#27ae60"

            # Incident internal name
            st.markdown(
                f"<p style='font-size:24px; font-weight:600; margin-bottom:6px;'>{incident_detail_data['Incident Name']}</p>",
                unsafe_allow_html=True
            )

            # Severity row
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

            # Actor row
            st.markdown(
                f"<p style='font-size:18px; margin-bottom:2px;'><strong>Actor:</strong> <em>{incident_detail_data['Actor']}</em></p>",
                unsafe_allow_html=True
            )

            # Risk score row
            st.markdown(
                f"<p style='font-size:18px; margin-bottom:6px;'><strong>Risk Score:</strong> {incident_detail_data['Risk Score']}</p>",
                unsafe_allow_html=True
            )

            st.divider()

            # Summary section
            st.markdown("<h3 style='margin-bottom:6px;'>Summary</h3>", unsafe_allow_html=True)
            st.markdown(
                f"<p style='font-size:18px; line-height:1.5; margin-top:0; margin-bottom:8px;'>{incident_detail_data['Summary']}</p>",
                unsafe_allow_html=True
            )

            st.divider()

            # Advanced details section
            st.markdown("<h3 style='margin-bottom:6px;'>Advanced Details</h3>", unsafe_allow_html=True)
            for item in incident_detail_data["Advanced Details"]:
                st.markdown(
                    f"<p style='font-size:18px; margin-top:0; margin-bottom:4px;'>• {item}</p>",
                    unsafe_allow_html=True
                )

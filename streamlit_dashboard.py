# streamlit_dashboard.py
import streamlit as st
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import time
import os
from sklearn.ensemble import IsolationForest
from datetime import datetime
from sklearn.preprocessing import StandardScaler
from scipy import stats

# --- Page config (WIDE) ---
st.set_page_config(page_title="AI Self-Healing Firewall", layout="wide")

# --- Ensure logs folder exists ---
LOG_DIR = "logs"
CSV_PATH = os.path.join(LOG_DIR, "firewall_log.csv")
TRAFFIC_PLOT = os.path.join(LOG_DIR, "traffic_plot.png")
STATUS_PLOT = os.path.join(LOG_DIR, "status_plot.png")
os.makedirs(LOG_DIR, exist_ok=True)

# --- CSS: keep layout wide and reserve live-panel height to avoid reflow ---
st.markdown(
    """
    <style>
    [data-testid="stMetricLabel"] {
    color: black !important;
    }
    /* Make the main container wider and prevent narrow-centered portrait feel */
    .reportview-container .main .block-container{
        max-width: 1300px;
        padding-left: 2rem;
        padding-right: 2rem;
    }
    /* Metric values (big numbers like 15, 0, etc.) */
    div[data-testid="stMetricValue"] {
        color: #FF6B6B !important;   /* Coral Red */
        font-weight: 700 !important;
    }

    /* Metric labels (small text under them like Total Events, Anomalies Detected) */
    div[data-testid="stMetricLabel"] {
        color: #FF6B6B !important;   /* Coral Red */
        font-weight: 600 !important;
    }
    /* App background & typography */
    .stApp {
        background: linear-gradient(135deg, #E6E6FA 0%, #F3E5F5 100%);
        color: #001F3F;
        font-family: 'Poppins', sans-serif;
    }

    /* Reserve a fixed-size box for live updates so the page doesn't reflow */
    .live-box {
        min-height: 180px;  /* reserve vertical space */
        max-height: 220px;
        overflow: auto;
        padding: 0.8rem;
        background: rgba(255,255,255,0.4);
        border-radius: 10px;
        box-shadow: 0 0 10px rgba(0,0,0,0.04);
    }

    /* Buttons */
    .stButton>button {
        background: linear-gradient(135deg, #D8BFD8, #C3B1E1);
        color: #001F3F;
        border: none;
        border-radius: 10px;
        padding: 0.5rem 1rem;
        font-weight: 600;
    }
    .stButton>button:hover {
        color: white;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# --- Centered Title and Subtitle ---
st.markdown(
    """
    <div style="text-align: center; margin-top: 0.1rem; margin-bottom: 0.6rem;">
        <h1 style="color: #001F3F; font-size: 2.2em; font-weight: 700; margin-bottom: 0.1rem;">
            AI SELF-HEALING FIREWALL
        </h1>
        <p style="color: #001F3F; font-size: 1.05em; margin-top: 0;">
            Simulate network traffic, detect anomalies, and demonstrate self-healing firewall actions.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# -----------------------
# Utility: Data generator
# -----------------------
def generate_traffic_data(n_samples=1, is_attack=False, attack_type="DDoS"):
    data = {}
    data['timestamp'] = [datetime.now().strftime("%H:%M:%S")] * n_samples
    data['packet_length'] = np.random.randint(64, 1500, n_samples)
    data['flow_duration'] = np.random.randint(1, 1000, n_samples)
    data['packets_per_flow'] = np.random.randint(2, 50, n_samples)
    data['attack_type'] = ["Normal"] * n_samples
    if is_attack:
        if attack_type == "DDoS":
            data['packets_per_flow'] = np.random.randint(100, 500, n_samples)
            data['flow_duration'] = np.random.randint(10, 500, n_samples)
            data['attack_type'] = [attack_type] * n_samples
    return pd.DataFrame(data)

# -----------------------
# --- Updated train_model: scale features and increase sensitivity ---
@st.cache_resource
def train_model():
    # Produce more varied "normal" training data (mix of many small batches)
    X_parts = []
    for _ in range(8):  # make training distribution a bit richer
        X_parts.append(generate_traffic_data(300, is_attack=False).drop(columns=["timestamp", "attack_type"]))
    X_train = pd.concat(X_parts, ignore_index=True)

    # Scale features (important for distance-based detectors)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    # More sensitive IsolationForest for demo: contamination slightly higher
    model = IsolationForest(contamination=0.03, random_state=42)
    model.fit(X_scaled)

    # Return both model and scaler for inference
    return {"model": model, "scaler": scaler}

# -----------------------
# Run simulation and save logs + plots
# -----------------------
def run_simulation(show_live=True, sleep=0.25, placeholders=None):
    """
    Reworked to use scaled features and hybrid detection (ML + rule-based).
    """
    resources = train_model()
    model = resources["model"]
    scaler = resources["scaler"]

    traffic_log = []
    anomaly_count = 0
    healing_count = 0

    total_cycles = 15
    PACKET_THRESHOLD = 80  # threshold for rule-based detection

    if placeholders is None:
        live_box = st.empty()
        progress = st.progress(0)
    else:
        live_box = placeholders.get("live_box")
        progress = placeholders.get("progress")

    if live_box is not None:
        live_box.markdown('<div class="live-box"></div>', unsafe_allow_html=True)
        live_inner = live_box.container()
    else:
        live_inner = None

    for i in range(1, total_cycles + 1):
        # Last few cycles = simulated attack burst
        if i >= 11:
            attack_batch = generate_traffic_data(3, is_attack=True, attack_type="DDoS")
            for idx in range(len(attack_batch)):
                row = attack_batch.iloc[[idx]]
                X_test = row.drop(columns=["timestamp", "attack_type"])
                X_scaled = scaler.transform(X_test)
                ml_pred = model.predict(X_scaled)[0]

                packets = int(row["packets_per_flow"].iloc[0])
                is_ml_anom = (ml_pred == -1)
                is_rule_anom = (packets > PACKET_THRESHOLD)
                is_anomaly = is_ml_anom or is_rule_anom

                status = "ANOMALY" if is_anomaly else "NORMAL"
                if status == "ANOMALY":
                    anomaly_count += 1
                    healing_count += 1
                    action_text = f"Blocked 203.0.113.15 at {datetime.now().strftime('%H:%M:%S')} (packets={packets})"
                else:
                    action_text = ""

                traffic_log.append({
                    "Cycle": i,
                    "Timestamp": row['timestamp'].iloc[0],
                    "Packets": packets,
                    "Flow_Duration": int(row['flow_duration'].iloc[0]),
                    "Status": status,
                    "Attack_Type": row['attack_type'].iloc[0],
                    "Action": action_text
                })

                # Update Streamlit view live
                if live_inner is not None:
                    badge = "<b style='color:#ff2b2b'>ANOMALY</b>" if status == "ANOMALY" else "<b style='color:#0a7a0a'>NORMAL</b>"
                    lines = []
                    for r in traffic_log[-10:]:
                        action_html = f"<span style='color:#001F3F'> - {r['Action']}</span>" if r['Action'] else ""
                        lines.append(f"<div style='padding:4px 6px; font-family:monospace;'>Cycle {r['Cycle']:02d}: {badge} | Packets: {r['Packets']} | Flow: {r['Flow_Duration']} {action_html}</div>")
                    html_block = "\n".join(lines)
                    live_inner.markdown(html_block, unsafe_allow_html=True)

                if progress is not None:
                    progress.progress(int(i / total_cycles * 100))
                time.sleep(sleep * 0.4)

                # Optional: stop early when anomaly occurs (for demo clarity)
                if is_anomaly:
                    df_logs = pd.DataFrame(traffic_log)
                    df_logs.to_csv(CSV_PATH, index=False)
                    _save_plots_from_df(df_logs)
                    return df_logs, anomaly_count, healing_count
        else:
            # Normal traffic cycles
            row = generate_traffic_data(1, is_attack=False)
            X_test = row.drop(columns=["timestamp", "attack_type"])
            X_scaled = scaler.transform(X_test)
            ml_pred = model.predict(X_scaled)[0]
            packets = int(row["packets_per_flow"].iloc[0])
            is_ml_anom = (ml_pred == -1)
            is_rule_anom = (packets > PACKET_THRESHOLD)
            is_anomaly = is_ml_anom or is_rule_anom

            status = "ANOMALY" if is_anomaly else "NORMAL"
            if status == "ANOMALY":
                anomaly_count += 1
                healing_count += 1
                action_text = f"Blocked 203.0.113.15 at {datetime.now().strftime('%H:%M:%S')} (packets={packets})"
            else:
                action_text = ""

            traffic_log.append({
                "Cycle": i,
                "Timestamp": row['timestamp'].iloc[0],
                "Packets": packets,
                "Flow_Duration": int(row['flow_duration'].iloc[0]),
                "Status": status,
                "Attack_Type": row['attack_type'].iloc[0],
                "Action": action_text
            })

            if live_inner is not None:
                lines = []
                for r in traffic_log[-10:]:
                    badge = "<b style='color:#ff2b2b'>ANOMALY</b>" if r["Status"] == "ANOMALY" else "<b style='color:#0a7a0a'>NORMAL</b>"
                    action_html = f"<span style='color:#001F3F'> - {r['Action']}</span>" if r['Action'] else ""
                    lines.append(f"<div style='padding:4px 6px; font-family:monospace;'>Cycle {r['Cycle']:02d}: {badge} | Packets: {r['Packets']} | Flow: {r['Flow_Duration']} {action_html}</div>")
                html_block = "\n".join(lines)
                live_inner.markdown(html_block, unsafe_allow_html=True)

            if progress is not None:
                progress.progress(int(i / total_cycles * 100))
            time.sleep(sleep)

    df_logs = pd.DataFrame(traffic_log)
    df_logs.to_csv(CSV_PATH, index=False)
    _save_plots_from_df(df_logs)
    return df_logs, anomaly_count, healing_count

def _save_plots_from_df(df_logs):
    plt.figure(figsize=(9, 4.2))
    plt.plot(df_logs["Cycle"], df_logs["Packets"], marker='o')
    plt.title("Network Traffic Pattern Over Time")
    plt.xlabel("Cycle")
    plt.ylabel("Packets per Flow")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(TRAFFIC_PLOT)
    plt.close()

    plt.figure(figsize=(6, 3.5))
    counts = df_logs["Status"].value_counts().reindex(["NORMAL", "ANOMALY"], fill_value=0)
    counts.plot(kind="bar", color=['#2ecc71', '#ff6b6b'])
    plt.title("Normal vs Anomalous Events")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(STATUS_PLOT)
    plt.close()

# -----------------------
# Streamlit UI
# -----------------------
# Prepare layout: left column controls + live box, right column shows metrics + charts
left_col, right_col = st.columns([1, 1.2])

with left_col:
    st.markdown("### CONTROLS")
    # Use session_state to keep last-run results
    if "last_df" not in st.session_state:
        st.session_state.last_df = None

    # Placeholders for live updates (fixed area)
    live_placeholder = st.empty()
    progress_placeholder = st.empty()

    # Buttons
    run_button = st.button("Simulate Attack (live)")
    quick_button = st.button("Quick Run (no live)")

    if run_button:
        with st.spinner("Running simulation (live)..."):
            placeholders = {"live_box": live_placeholder, "progress": progress_placeholder}
            df_logs, anomalies, heals = run_simulation(show_live=True, sleep=0.25, placeholders=placeholders)
            st.session_state.last_df = df_logs
            st.success(f"Simulation complete — {anomalies} anomalies detected, {heals} self-healing actions.")

    if quick_button:
        with st.spinner("Running quick simulation..."):
            placeholders = {"live_box": live_placeholder, "progress": progress_placeholder}
            # Quick run: very small sleep so UI doesn't feel blocked
            df_logs, anomalies, heals = run_simulation(show_live=True, sleep=0.03, placeholders=placeholders)
            st.session_state.last_df = df_logs
            st.success(f"Quick run complete — {anomalies} anomalies, {heals} heals.")

with right_col:
    st.markdown("### DASHBOARD")
    # Load from session_state or disk
    if st.session_state.last_df is not None:
        df = st.session_state.last_df
        st.metric("Total Events", len(df))
        st.metric("Anomalies Detected", int((df["Status"] == "ANOMALY").sum()))
        st.metric("Self-Healing Actions (simulated)", int((df["Action"] != "").sum()))

        st.subheader("RECENT LOGS")
        st.dataframe(df.tail(10), use_container_width=True)

        st.subheader("VISUALIZATIONS")
        if os.path.exists(TRAFFIC_PLOT):
            st.image(TRAFFIC_PLOT, use_container_width=True)
        if os.path.exists(STATUS_PLOT):
            st.image(STATUS_PLOT, use_container_width=True)
    elif os.path.exists(CSV_PATH):
        df_disk = pd.read_csv(CSV_PATH)
        st.metric("Total Events", len(df_disk))
        st.metric("Anomalies Detected", int((df_disk["Status"] == "ANOMALY").sum()))
        st.metric("Self-Healing Actions (simulated)", int((df_disk["Action"] != "").sum()))
        st.subheader("Recent Logs (from disk)")
        st.dataframe(df_disk.tail(10), use_container_width=True)
        st.subheader("Visualizations")
        if os.path.exists(TRAFFIC_PLOT):
            st.image(TRAFFIC_PLOT, use_container_width=True)
        if os.path.exists(STATUS_PLOT):
            st.image(STATUS_PLOT, use_container_width=True)
    else:
        st.info("No logs yet. Click *Simulate Attack (live)* or *Quick Run* to create a run.")

st.markdown("---")

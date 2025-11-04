# self_healing_firewall_v2.py
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from datetime import datetime
import time
import os

# --- GLOBAL LOG STORAGE ---
traffic_log = []  # List of dicts to record all traffic events
anomaly_count = 0
healing_count = 0

# --- 1. DATA SIMULATION ---
def generate_traffic_data(n_samples, is_attack=False, attack_type="DDoS"):
    """Generates synthetic network traffic features."""
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


# --- 2. AI MODEL (Anomaly Detection) ---
def train_ai_model():
    print("🤖 Stage 1: Training AI Anomaly Detection Model...")
    X_train = generate_traffic_data(1000, is_attack=False).drop(columns=["timestamp", "attack_type"])
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X_train)
    print("✅ Model Training Complete.\n")
    return model


# --- 3. SELF-HEALING LOGIC ---
def self_heal_action(attack_data):
    global healing_count
    healing_count += 1

    attack_source = "203.0.113.15 (Simulated Malicious IP)"
    print(f"\n🚨 **ANOMALY DETECTED** at {datetime.now().strftime('%H:%M:%S')}!")
    print(f"   Inferred Threat: High Packet Flow (Possible DDoS/Flood).")
    print("\n🩹 **NEUROSHIELD SELF-HEALING INITIATED...**")
    print(f"   → Blocking Source IP: {attack_source}")
    print(f"   → Logging rule update to database (simulated).")
    print("✅ Self-Healing Rule Applied.\n")


# --- 4. MONITORING SIMULATION ---
def monitor_traffic(model):
    global anomaly_count

    print("📊 Stage 2: Real-Time Traffic Monitoring Commenced.")

    for i in range(1, 16):
        is_attack = i >= 11
        data = generate_traffic_data(1, is_attack=is_attack)
        X_test = data.drop(columns=["timestamp", "attack_type"])
        pred = model.predict(X_test)
        status = "ANOMALY" if pred[0] == -1 else "NORMAL"

        # Update counts
        if status == "ANOMALY":
            anomaly_count += 1
            if is_attack:
                self_heal_action(data)

        # Store in global log
        traffic_log.append({
            "Cycle": i,
            "Timestamp": data['timestamp'][0],
            "Packets": int(data['packets_per_flow'][0]),
            "Flow_Duration": int(data['flow_duration'][0]),
            "Status": status,
            "Attack_Type": data['attack_type'][0]
        })

        print(f"Cycle {i:02d}: {status} | Packets: {data['packets_per_flow'][0]} | Flow: {data['flow_duration'][0]}")
        time.sleep(0.5)

    print("\n--- Monitoring Complete ---")
    save_and_plot_results()


# --- 5. LOGGING + VISUALIZATION ---
def save_and_plot_results():
    df = pd.DataFrame(traffic_log)
    os.makedirs("logs", exist_ok=True)
    csv_path = "logs/firewall_log.csv"
    df.to_csv(csv_path, index=False)
    print(f"🗂 Logs saved to: {csv_path}")

    # --- Visualization ---
    plt.figure(figsize=(10, 6))
    plt.plot(df["Cycle"], df["Packets"], label="Packets per Flow", marker='o')
    plt.title("Network Traffic Pattern Over Time")
    plt.xlabel("Cycle")
    plt.ylabel("Packets per Flow")
    plt.legend()
    plt.grid(True)
    plt.savefig("logs/traffic_plot.png")
    plt.close()

    plt.figure(figsize=(6, 4))
    df["Status"].value_counts().plot(kind='bar', color=['green', 'red'])
    plt.title("Normal vs Anomalous Events")
    plt.ylabel("Count")
    plt.savefig("logs/status_plot.png")
    plt.close()

    print("📊 Charts generated in /logs folder.")


# --- MAIN EXECUTION ---
if __name__ == "__main__":
    ai_model = train_ai_model()
    monitor_traffic(ai_model)
    print(f"\nSummary: {anomaly_count} anomalies detected, {healing_count} self-healing actions executed.")

import scapy.all as scapy
import numpy as np
from sklearn.ensemble import IsolationForest

import subprocess

def get_wifi_profiles():
    try:
        # Run the command to get Wi-Fi profiles
        result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], capture_output=True, text=True, check=True)
        
        # Decode the output
        output = result.stdout
        
        # Split the output into lines and process each line
        profiles = []
        for line in output.split('\n'):
            if "All User Profile" in line:
                # Extract profile name
                profile_name = line.split(":")[1].strip()
                profiles.append(profile_name)
        
        return profiles

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        return []

def main():
    profiles = get_wifi_profiles()
    if profiles:
        print("Wi-Fi Profiles:")
        for profile in profiles:
            print(f" - {profile}")
    else:
        print("No Wi-Fi profiles found.")

if _name_ == "_main_":
    main()

def capture_packets(interface, duration):
    try:
        packets = scapy.sniff(iface=interface, timeout=duration)
        print(f"Captured {len(packets)} packets.")
        return packets
    except OSError as e:
        print(f"Error: {e}")
        return []

def extract_features(packets):
    features = []
    for packet in packets:
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            length = len(packet)
            features.append([src_ip, dst_ip, length])
    if not features:
        print("No features extracted from packets.")
    return features

def analyze_behavior(features):
    if not features:
        print("No features to analyze.")
        return []

    data = np.array([f[2] for f in features])  # Use packet length as a simple feature
    if data.size == 0:
        print("No data to analyze.")
        return []

    data = data.reshape(-1, 1)
    
    clf = IsolationForest(contamination=0.01)
    clf.fit(data)
    predictions = clf.predict(data)
    
    anomalies = [features[i] for i in range(len(predictions)) if predictions[i] == -1]
    return anomalies

def main():
    interface = "Ethernet"  # Use the correct interface name
    duration = 60  # Capture duration in seconds
    print(f"Capturing packets for {duration} seconds...")
    
    packets = capture_packets(interface, duration)
    features = extract_features(packets)
    anomalies = analyze_behavior(features)
    
    if anomalies:
        print("Anomalous behavior detected:")
        for anomaly in anomalies:
            print(f"Source: {anomaly[0]}, Destination: {anomaly[1]}, Length: {anomaly[2]}")
    else:
        print("No anomalies detected.")
    
if _name_ == "_main_":
    main()

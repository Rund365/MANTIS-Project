from scapy.all import wrpcap
from datetime import datetime
import csv
import os
from flask import jsonify
import re

def save_packets_to_file(filename, packets):
    """Saves captured packets to a PCAP file."""
    try:
        wrpcap(filename, packets)
        print(f"Packets saved to {filename}")
    except Exception as e:
        print(f"Failed to save packets: {e}")

def timestamped_filename(base_name):
    """Generates a timestamped filename."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base_name}_{timestamp}.pcap"

def export_logs_to_csv(filename, packets):
    """Exports packet summaries to a CSV file."""
    try:
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Index", "Summary"])
            for idx, packet in enumerate(packets):
                writer.writerow([idx + 1, packet.summary()])
        print(f"Logs exported to {filename}")
    except Exception as e:
        print(f"Failed to export logs: {e}")

def extract_session_from_filename(filename):
    """
    Given a file name like "('127.0.0.1', 49372, '127.0.0.1', 50660)1",
    use a regex to extract and return the session portion as a string:
    "127.0.0.1:49372 > 127.0.0.1:50660"
    """
    # Regex to capture ip1, port1, ip2, port2 inside the parentheses.
    pattern = re.compile(r"\('([^']+)',\s*(\d+),\s*'([^']+)',\s*(\d+)\)")
    match = pattern.search(filename)
    if match:
        ip1, port1, ip2, port2 = match.groups()
        return f"{ip1}:{port1} > {ip2}:{port2}"
    return None

def normalize_session_string(session_string):
    """
    Normalize the frontend session string.
    
    Removes any protocol prefix ("TCP " or "UDP ") and extra spaces.
    Expected output format: "ip1:port1 > ip2:port2"
    """
    # Remove protocol prefix if present.
    for prefix in ("TCP ", "UDP "):
        if session_string.startswith(prefix):
            session_string = session_string[len(prefix):]
            break
    return session_string.strip()

def files_extractor(requested_id, dir_path):
    """
    Iterates over all files in the given directory and returns those whose
    extracted session (from the file name) matches the normalized requested_id.
    """
    # Normalize the session string from the frontend.
    requested_id = normalize_session_string(requested_id)
    
    matching_files = {}

    # Iterate over all files in the directory.
    for filename in os.listdir(dir_path):
        file_path = os.path.join(dir_path, filename)
        if os.path.isfile(file_path):
            extracted_session = extract_session_from_filename(filename)
            if extracted_session is None:
                continue
            # Compare the extracted session with the normalized requested session.
            if extracted_session == requested_id:
                matching_files[filename] = {
                    "filename": filename,
                    "path": file_path
                }

    if not matching_files:
        return jsonify({"error": "No files found for this session"}), 404

    return jsonify({"files": matching_files})
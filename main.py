from flask import Flask, request, jsonify, Response
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from scapy.layers.l2 import PacketList
from Sniffer import start_sniffing, stop_sniffing
from Filters import build_filters
from threading import Thread
import queue
import logging
import os
import json
import time
from Utils import save_packets_to_file, files_extractor
from Loopbackdict import CustomPacketList

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:8000"}})

captured_packets = CustomPacketList()
sniff_thread = None
sniffing_active = False
loopback_flag=False

@app.route('/start_sniffing', methods=['POST'])
def start_sniffing_endpoint():
    global sniff_thread, sniffing_active, loopback_flag

    if sniffing_active:
        return jsonify({"message": "Sniffing is already in progress."}), 400

    data = request.json
    ip_src = data.get('ip_src')
    ip_dst = data.get('ip_dst')
    port = data.get('port')
    protocol = data.get('protocol')
    logic = data.get('logic', 'AND')
    packet_count = int(data.get('packet_count') or 0)
    interface_to_be_used=data.get('interface')
    filters = build_filters(ip_src, ip_dst, port, protocol, logic)

    if interface_to_be_used=='lo0':
        loopback_flag=True
    def sniffing_logic():
        try:
            start_sniffing(filters, packet_count, captured_packets,interface_to_be_used,loopback_flag)
        except Exception as e:
            logging.error(f"Error during sniffing: {e}")
    #sniff thread
    sniff_thread = Thread(target=sniffing_logic)
    sniff_thread.daemon = True
    sniff_thread.start()
    sniffing_active = True
    #stream_thread.start()
    return jsonify({"message": "Sniffing started.", "filters": filters})

@app.route('/stop_sniffing', methods=['POST'])
def stop_sniffing_endpoint():
    global sniffing_active, loopback_flag
    loopback_flag=False
    sniffing_active = False
    stop_sniffing()
    return jsonify({"message": "Sniffing stopped."})

@app.route('/save_session', methods=['POST'])
def save_session_endpoint():
    global captured_packets
    data = request.get_json()
    file_name = data.get('file_name')

    if file_name:
        # Save the session data to the file with the provided name
        try:
            print(captured_packets)
            save_packets_to_file(file_name,captured_packets)
            return jsonify({'status': 'success', 'message': 'Session saved!'}), 200
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    else:
        return jsonify({'status': 'error', 'message': 'File name is required!'}), 400
    
@app.route('/get_sessions', methods=['GET'])
def get_sessions():
    global captured_packets
    #copies the packetlist to ensure valid packetlist
    #copyed_captured_packets=captured_packets.copy()
    captured_sessions=captured_packets.sessions()
    session_list = [{"session_id": key} for key in captured_sessions.keys()]

    return jsonify(session_list)

@app.route('/get_session_files', methods=['GET'])
def get_session_files():
    try:
        REASSEMBLED_FILES_DIR = os.path.join(os.getcwd(), 'reassembled_files')
    except:
        return jsonify({})
    # Retrieve the session_id from the query parameters.
    session_id = request.args.get('session_id')
    if not session_id:
        return jsonify({"error": "No session_id provided"}), 400

    return files_extractor(session_id,REASSEMBLED_FILES_DIR)

@app.route('/get_session_packets', methods=['GET'])
def get_session_packets():
    global captured_packets
    session_id = request.args.get('session_id')
    session_packets=[]
    all_sessions=captured_packets.sessions()
    wanted_sessions=all_sessions[session_id]
    for pkt in wanted_sessions:
        session_packets.append({
        "summary": pkt.summary(),
        "details": pkt.show(dump=True)
    })

    return jsonify({"packets": session_packets})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5004)

from flask import Flask, request, jsonify
from flask_cors import CORS
from scapy.layers.l2 import PacketList
from Sniffer import start_sniffing, stop_sniffing
from Filters import build_filters
from threading import Thread
import logging
import os
from Utils import save_packets_to_file, files_extractor
from Loopbackdict import CustomPacketList
from Sniffer import apply_tc_limit, remove_tc_limit

# might not be needed:
# def is_admin():
#     """Check if the script is running with admin privileges."""
#     try:
#         return ctypes.windll.shell32.IsUserAnAdmin()
#     except:
#         return False

# def restart_as_admin():
#     """Restart the script with admin privileges if it's not already running as admin."""
#     if not is_admin():
#         print("Restarting with Administrator privileges...")
#         try:
#             # Relaunch the script with admin rights
#             script_path = sys.argv[0]  # Get the current script path
#             command = f'powershell -Command "Start-Process python \'{script_path}\' -Verb RunAs"'
#             subprocess.run(command, shell=True, check=True)
#             sys.exit()  # Close the current instance
#         except Exception as e:
#             print(f"⚠️ Failed to restart as Admin: {e}")
#             sys.exit(1)

# # Check and restart as Admin if needed
# restart_as_admin()

# print("Running as Administrator. Continuing execution...")


app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:8000"}})

captured_packets = CustomPacketList()
sniff_thread = None
sniffing_active = False
loopback_flag=False


@app.route('/set_qos', methods=['POST'])
def set_qos():
    """Sets QoS bandwidth limit for a specific port."""
    data = request.get_json()
    interface = data.get('interface-qos', data.get('interface', None))
    port = int(data.get('qos_port', 0))
    bandwidth_kbps = int(data.get('bandwidth', 0))
    print("zobor interface is: ", interface )

    if port <= 0 or bandwidth_kbps <= 0 or not interface:
        return jsonify({"error": "Invalid port, bandwidth, or interface value"}), 400

    success = apply_tc_limit(interface, port, bandwidth_kbps)

    if success:
        return jsonify({"message": f"QoS applied: {bandwidth_kbps} Kbps on port {port} via {interface}"}), 200
    else:
        return jsonify({"error": "Failed to apply QoS"}), 500


@app.route('/remove_qos', methods=['POST'])
def remove_qos():
    """Removes QoS bandwidth limit for a specific port."""
    data = request.get_json()
    interface = data.get('interface-qos', data.get('interface', None))
    port = int(data.get('qos_port', 0))

    if port <= 0 or not interface:
        return jsonify({"error": "Invalid port or interface value"}), 400

    success = remove_tc_limit(interface, port)

    if success:
        return jsonify({"message": f"QoS removed for port {port} via {interface}"}), 200
    else:
        return jsonify({"error": "Failed to remove QoS"}), 500


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
    if ip_src == "127.0.0.1" or ip_dst == "127.0.0.1":
        interface_to_be_used = "lo"
    if not interface_to_be_used:
        interface_to_be_used= None
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
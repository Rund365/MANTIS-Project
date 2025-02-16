from collections import defaultdict, OrderedDict
from scapy.all import IP, TCP, Packet, Raw, IPv6
from pathlib import Path

def get_session_id(packet: Packet):
    if packet.haslayer(IP):  # Check if it's an IPv4 packet
        src = (packet[IP].src, packet[TCP].sport)
        dst = (packet[IP].dst, packet[TCP].dport)
    elif packet.haslayer(IPv6):  # Check if it's an IPv6 packet
        src = (packet[IPv6].src, packet[TCP].sport)
        dst = (packet[IPv6].dst, packet[TCP].dport)
    else:
        raise ValueError("Packet is neither IPv4 nor IPv6")

    # Sort the tuples so that the lower one comes first
    if src <= dst:
        return src + dst
    else:
        return dst + src
        
def file_type(payload):
    if payload.startswith(b"%PDF-"):
        return '.pdf'
    if payload.startswith(b"\xff\xd8"):
        return '.jpeg'
    if payload.startswith(b"\x89PNG"):
        return '.png'
    return '.txt'
    
class SessionFileReassembler:
    def __init__(self):
        # sessions is a dict mapping session IDs to a list of file dictionaries.
        self.sessions = defaultdict(list)
        # active_file is a dict mapping a session ID to the currently active (incomplete) file OrderedDict.
        self.active_file = {}
        # Make a directory to save reassembled files.
        project_location = Path(__file__).parent.resolve()
        self.new_dir = project_location / 'reassembled_files'
        self.new_dir.mkdir(exist_ok=True)

    def process_packet(self, packet: Packet):
        """
        Process a packet for a given session.
        If the payload starts with a file magic number, start a new file.
        Otherwise, if an active file exists, add the payload keyed by its sequence number.
        If the payload contains b"EOF", mark the file as complete and write it to disk.
        """
        session_id = get_session_id(packet)
        #print("DEBUG: Processing packet for session", session_id)
        payload = packet[Raw].load
        seq = packet[TCP].seq
        if not payload:
            return

        # Check if this packet signals the start of a new file (e.g. PDF magic number)
        if self.active_file.get(session_id) is None:
            #print("DEBUG: Starting a new file")
            # Create a new OrderedDict for this file
            file_dict = OrderedDict()
            file_dict[seq] = payload
            # Append the new file to the session's list of files.
            self.sessions[session_id].append(file_dict)
            # Mark this file as active for further fragments.
            self.active_file[session_id] = file_dict
        else:
            # There is an active file for this session.
            #print("DEBUG: Adding payload to active file")
            active = self.active_file.get(session_id)
            if active is not None:
                active[seq] = payload
                # If this payload contains the termination marker, mark the file as complete.
                if b"EOF" in payload:
                    # Use the active file dictionary for extension determination.
                    extension = file_type(next(iter(active.values())))
                    filename = str(session_id) + str(len(self.sessions[session_id])) + extension
                    # Build the full file path using self.new_dir.
                    file_name_and_path = str(self.new_dir / filename)
                    #print("DEBUG: Writing file to", file_name_and_path)
                    with open(file_name_and_path, 'wb') as f:
                        # Iterate over the values (payloads) in the active file.
                        for data in active.values():
                            f.write(data)
                    # Mark the file as complete.
                    self.active_file[session_id] = None

    def get_session_files(self, session_id):
        """
        Retrieve the list of files (OrderedDict objects) reassembled for a specific session.
        """
        return self.sessions.get(session_id, [])

from scapy.all import IP, IPv6, TCP, UDP
from scapy.plist import PacketList
from collections import defaultdict

class CustomPacketList(PacketList):
    def get_session_id(self, pkt):
        """
        Create a symmetric session key for the packet.
        The key is constructed so that it is independent of the packet direction,
        with the lower IP (or if equal, the lower port) coming first.
        """
        # Check for IP or IPv6 layer
        if IP in pkt or IPv6 in pkt:
            # Determine whether the packet uses TCP or UDP
            if TCP in pkt:
                proto = "TCP"
                # Use the IP layer that exists (IPv4 or IPv6)
                ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
                src_tuple = (ip_layer.src, pkt[TCP].sport)
                dst_tuple = (ip_layer.dst, pkt[TCP].dport)
            elif UDP in pkt:
                proto = "UDP"
                ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
                src_tuple = (ip_layer.src, pkt[UDP].sport)
                dst_tuple = (ip_layer.dst, pkt[UDP].dport)
            else:
                # If neither TCP nor UDP is present, use IP addresses only.
                proto = "IP"
                ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
                src_tuple = (ip_layer.src, 0)
                dst_tuple = (ip_layer.dst, 0)
            
            # Sort the two tuples so that the lower one comes first.
            if src_tuple <= dst_tuple:
                return f"{proto} {src_tuple[0]}:{src_tuple[1]} > {dst_tuple[0]}:{dst_tuple[1]}"
            else:
                return f"{proto} {dst_tuple[0]}:{dst_tuple[1]} > {src_tuple[0]}:{src_tuple[1]}"
        else:
            # If no IP/IPv6 layer, fall back to using Scapy's default sessions.
            tmp_list = PacketList([pkt])
            tmp_sessions = tmp_list.sessions()
            return next(iter(tmp_sessions.keys()))

    def sessions(self):
        """
        Group packets into sessions using a custom symmetric key.
        If a packet has an IP (or IPv6) layer, we use its IP and port
        information to build a symmetric key that is identical for both directions.
        Otherwise, we fall back to the default session key.
        """
        sessions = defaultdict(PacketList)
        for pkt in self:
            try:
                session_key = self.get_session_id(pkt)
            except Exception:
                # Fallback if there's an error (for instance, missing expected layers)
                tmp_list = PacketList([pkt])
                tmp_sessions = tmp_list.sessions()
                session_key = next(iter(tmp_sessions.keys()))
            sessions[session_key].append(pkt)
        return sessions
